//! HTTP/3 `/auth` only. After 233, TCP/UDP leave h3.

use super::h3_uni::{AuthUniFilter, QueuedTcpBidi, ServerAuthH3};
use crate::error::Error;
use crate::protocol::{
    auth_request_from_headers, auth_request_to_headers, auth_response_from_headers,
    auth_response_to_headers, AuthRequest, AuthResponse, STATUS_AUTH_OK, URL_HOST, URL_PATH,
};
use crate::server::{Authenticator, MasqHandler, MasqResponse};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Client: POST `https://hysteria/auth` with Hysteria-Auth / CC-RX / Padding.
///
/// Returns `(status, AuthResponse)`. Caller maps `status != 233` → `Error::Auth`.
/// Keeps the h3 client driver alive so Drop does not tear down QUIC.
pub struct ClientH3Hold {
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    _drive: tokio::task::JoinHandle<()>,
}

pub async fn client_auth(
    conn: quinn::Connection,
    auth: &str,
    max_rx: u64,
) -> Result<(u16, AuthResponse, ClientH3Hold), Error> {
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| Error::Connect(format!("h3 client: {e}")))?;

    let drive = tokio::spawn(async move {
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut driver).poll_close(cx)).await;
    });

    match post_hysteria_auth(&mut send_request, auth, max_rx).await {
        Ok((status, auth_resp)) => Ok((
            status,
            auth_resp,
            ClientH3Hold {
                _send_request: send_request,
                _drive: drive,
            },
        )),
        Err(e) => {
            drive.abort();
            Err(e)
        }
    }
}

/// POST `https://hysteria/auth` on an existing h3 client. Used by `client_auth`
/// and by the same-QUIC second-auth integration test.
pub(crate) async fn post_hysteria_auth(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    auth: &str,
    max_rx: u64,
) -> Result<(u16, AuthResponse), Error> {
    let req_body = AuthRequest {
        auth: auth.to_string(),
        rx: max_rx,
    };
    let headers = auth_request_to_headers(&req_body);

    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{URL_HOST}{URL_PATH}"));
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = builder
        .body(())
        .map_err(|e| Error::Connect(format!("build auth request: {e}")))?;

    let mut stream = send_request
        .send_request(req)
        .await
        .map_err(|e| Error::Connect(format!("send auth: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::Connect(format!("finish auth: {e}")))?;

    let resp = stream
        .recv_response()
        .await
        .map_err(|e| Error::Connect(format!("recv auth: {e}")))?;
    let status = resp.status().as_u16();

    let mut hdrs = Vec::new();
    for (k, v) in resp.headers().iter() {
        if let Ok(val) = v.to_str() {
            hdrs.push((k.as_str().to_string(), val.to_string()));
        }
    }
    while stream
        .recv_data()
        .await
        .map_err(|e| Error::Connect(format!("auth body: {e}")))?
        .is_some()
    {}

    Ok((status, auth_response_from_headers(&hdrs)))
}

/// Server: handle a single h3 request for auth (or masq).
///
/// Returns `Some((auth_id, AuthResponse))` on success (233 written).
/// Returns `None` if masq/404 was sent (connection stays unauthenticated).
pub async fn server_handle_auth_request<S>(
    req: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    remote: SocketAddr,
    authenticator: &dyn Authenticator,
    ignore_client_bw: bool,
    server_max_tx: u64,
    server_max_rx: u64,
    disable_udp: bool,
    masq: Option<&dyn MasqHandler>,
) -> Result<Option<(String, AuthResponse, crate::congestion::CcChoice)>, Error>
where
    S: h3::quic::BidiStream<Bytes>,
    <S as h3::quic::RecvStream>::Buf: bytes::Buf,
{
    let method = req.method().as_str();
    let path = req.uri().path();
    let host = request_host(&req);
    let is_auth = is_hysteria_auth_request(method, &host, path);

    if is_auth {
        let mut hdrs = Vec::new();
        for (k, v) in req.headers().iter() {
            if let Ok(val) = v.to_str() {
                hdrs.push((k.as_str().to_string(), val.to_string()));
            }
        }
        let auth_req = auth_request_from_headers(&hdrs);
        let (ok, id) = authenticator
            .authenticate(remote, &auth_req.auth, auth_req.rx)
            .await;
        if ok {
            tracing::info!(remote = %remote, id = %id, "auth ok");
            let cc = crate::congestion::server_send_cc(
                ignore_client_bw,
                server_max_tx,
                auth_req.rx,
            );
            let resp = AuthResponse {
                udp_enabled: !disable_udp,
                rx: if ignore_client_bw { 0 } else { server_max_rx },
                rx_auto: ignore_client_bw,
            };
            send_auth_ok(&mut stream, &resp).await?;
            return Ok(Some((id, resp, cc)));
        }
        // Auth HTTP request with a failed password: still masquerade, but log first.
        tracing::info!(remote = %remote, id = %id, "auth failed");
    }

    // Masq / 404
    let masq_resp = if let Some(m) = masq {
        m.handle(method, &host, path).await
    } else {
        MasqResponse {
            status: 404,
            headers: vec![],
            body: Bytes::new(),
        }
    };
    send_masq(&mut stream, masq_resp).await?;
    Ok(None)
}

async fn send_auth_ok<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    resp: &AuthResponse,
) -> Result<(), Error>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let status = StatusCode::from_u16(STATUS_AUTH_OK)
        .map_err(|e| Error::Protocol(format!("status 233: {e}")))?;
    let mut builder = Response::builder().status(status);
    for (k, v) in auth_response_to_headers(resp) {
        builder = builder.header(k, v);
    }
    let response = builder
        .body(())
        .map_err(|e| Error::Quic(format!("auth response: {e}")))?;
    stream
        .send_response(response)
        .await
        .map_err(|e| Error::Quic(format!("send 233: {e}")))?;
    stream
        .finish()
        .await
        .map_err(|e| Error::Quic(format!("finish 233: {e}")))?;
    Ok(())
}

async fn send_masq<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    masq: MasqResponse,
) -> Result<(), Error>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let status = StatusCode::from_u16(masq.status).unwrap_or(StatusCode::NOT_FOUND);
    let mut builder = Response::builder().status(status);
    for (k, v) in &masq.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let response = builder
        .body(())
        .map_err(|e| Error::Quic(format!("masq response: {e}")))?;
    stream
        .send_response(response)
        .await
        .map_err(|e| Error::Quic(format!("send masq: {e}")))?;
    if !masq.body.is_empty() {
        stream
            .send_data(masq.body)
            .await
            .map_err(|e| Error::Quic(format!("masq body: {e}")))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| Error::Quic(format!("finish masq: {e}")))?;
    Ok(())
}

/// Drive h3 on `conn` until one auth succeeds or the first request is masq'd.
///
/// Accepts **once**. After a successful 233 the caller keeps this
/// `h3::server::Connection` and continues `accept()` / `tcp_rx` in the same
/// task (the wrapper is the only `accept_bi` owner). `tcp_rx` is the live
/// 0x401 queue — not a one-shot drain.
pub async fn server_authenticate(
    conn: quinn::Connection,
    authenticator: Arc<dyn Authenticator>,
    ignore_client_bw: bool,
    server_max_tx: u64,
    server_max_rx: u64,
    disable_udp: bool,
    masq: Option<Arc<dyn MasqHandler>>,
) -> Result<
    (
        Option<(String, AuthResponse, crate::congestion::CcChoice)>,
        ServerAuthH3,
        tokio::sync::mpsc::UnboundedReceiver<QueuedTcpBidi>,
    ),
    Error,
> {
    let remote = conn.remote_address();
    let (tcp_tx, tcp_rx) = tokio::sync::mpsc::unbounded_channel();
    let authed = Arc::new(AtomicBool::new(false));
    let mut h3_conn = h3::server::Connection::new(AuthUniFilter::with_tcp_tx_authed(
        h3_quinn::Connection::new(conn),
        tcp_tx,
        Arc::clone(&authed),
    ))
    .await
    .map_err(|e| Error::Connect(format!("h3 server: {e}")))?;

    let resolver = match h3_conn.accept().await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return Ok((None, h3_conn, tcp_rx));
        }
        Err(e) => return Err(Error::Connect(format!("h3 accept: {e}"))),
    };

    let (req, stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| Error::Connect(format!("h3 resolve: {e}")))?;

    let result = server_handle_auth_request(
        req,
        stream,
        remote,
        authenticator.as_ref(),
        ignore_client_bw,
        server_max_tx,
        server_max_rx,
        disable_udp,
        masq.as_deref(),
    )
    .await?;

    if result.is_some() {
        authed.store(true, Ordering::Release);
    }

    Ok((result, h3_conn, tcp_rx))
}

/// After first 233: another POST `/auth` writes 233 again (reuse `auth_resp`);
/// any other HTTP is masquerade.
pub async fn server_handle_authed_http<S>(
    req: Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    auth_resp: &AuthResponse,
    masq: Option<&dyn MasqHandler>,
) -> Result<(), Error>
where
    S: h3::quic::BidiStream<Bytes>,
    <S as h3::quic::RecvStream>::Buf: bytes::Buf,
{
    let method = req.method().as_str();
    let path = req.uri().path();
    let host = request_host(&req);
    if is_hysteria_auth_request(method, &host, path) {
        match send_auth_ok(&mut stream, auth_resp).await {
            Ok(()) => return Ok(()),
            Err(e) if later_http_peer_closed(&e) => {
                tracing::info!(err = %e, "h3 later request send 233");
                return Ok(());
            }
            Err(e) => return Err(e),
        }
    }
    let masq_resp = if let Some(m) = masq {
        m.handle(method, &host, path).await
    } else {
        MasqResponse {
            status: 404,
            headers: vec![],
            body: Bytes::new(),
        }
    };
    match send_masq(&mut stream, masq_resp).await {
        Ok(()) => Ok(()),
        Err(e) if later_http_peer_closed(&e) => {
            tracing::info!(err = %e, "h3 later request send 233");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Peer closed QUIC with HTTP/3 / QUIC NO_ERROR (`ApplicationClose: 0x0` or
/// `H3_NO_ERROR`). Later HTTP must not escalate this to a protocol error.
fn later_http_peer_closed(e: &Error) -> bool {
    match e {
        Error::Quic(s) | Error::Connect(s) => {
            s.contains("ApplicationClose: 0x0") || s.contains("H3_NO_ERROR")
        }
        _ => false,
    }
}

/// `h3.accept` saw the peer close with no error. After 233 this is not auth
/// failure; in-flight TCP copy tasks must not be torn down.
pub(crate) fn h3_accept_is_peer_normal_close(e: &h3::error::ConnectionError) -> bool {
    if e.is_h3_no_error() {
        return true;
    }
    let s = e.to_string();
    s.contains("ApplicationClose: 0x0") || s.contains("ApplicationClose: H3_NO_ERROR")
}

fn request_host(req: &Request<()>) -> String {
    req.uri()
        .host()
        .map(|h| h.to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default()
}

fn is_hysteria_auth_request(method: &str, host: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST")
        && host.eq_ignore_ascii_case(URL_HOST)
        && path == URL_PATH
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hysteria_auth_path_is_auth() {
        assert!(is_hysteria_auth_request("POST", "hysteria", "/auth"));
        assert!(is_hysteria_auth_request("post", "HYSTERIA", "/auth"));
        // Ordinary masquerade HTTP must not be treated as auth fail.
        assert!(!is_hysteria_auth_request("GET", "hysteria", "/auth"));
        assert!(!is_hysteria_auth_request("POST", "example.com", "/"));
        assert!(!is_hysteria_auth_request("POST", "hysteria", "/"));
        assert!(!is_hysteria_auth_request("POST", "", "/auth"));
    }

    #[test]
    fn later_send_233_on_peer_0x0_is_not_protocol_error() {
        assert!(later_http_peer_closed(&Error::Quic(
            "send 233: ApplicationClose: 0x0".into()
        )));
        assert!(later_http_peer_closed(&Error::Quic(
            "Connection error: Remote error: ApplicationClose: H3_NO_ERROR".into()
        )));
        assert!(!later_http_peer_closed(&Error::Quic(
            "H3_FRAME_UNEXPECTED".into()
        )));
        assert!(!later_http_peer_closed(&Error::Protocol("bad".into())));
    }
}
