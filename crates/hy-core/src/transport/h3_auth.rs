//! HTTP/3 `/auth` only. After 233, TCP/UDP leave h3.

use crate::error::Error;
use crate::protocol::{
    auth_request_from_headers, auth_request_to_headers, auth_response_from_headers,
    auth_response_to_headers, AuthRequest, AuthResponse, STATUS_AUTH_OK, URL_HOST, URL_PATH,
};
use crate::server::{Authenticator, MasqHandler, MasqResponse};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use std::net::SocketAddr;
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

    let req_body = AuthRequest {
        auth: auth.to_string(),
        rx: max_rx,
    };
    let headers = auth_request_to_headers(&req_body);

    let request = async move {
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
        // Drain body (auth has none meaningful).
        while stream
            .recv_data()
            .await
            .map_err(|e| Error::Connect(format!("auth body: {e}")))?
            .is_some()
        {}

        let auth_resp = auth_response_from_headers(&hdrs);
        // Keep send_request alive until here so Drop does not race the response.
        Ok::<_, Error>((status, auth_resp, send_request))
    };

    match request.await {
        Ok((status, auth_resp, send_request)) => Ok((
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
    let host = req
        .uri()
        .host()
        .map(|h| h.to_string())
        .or_else(|| {
            req.headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

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
/// On success, the `h3::server::Connection` is returned so the caller can keep it
/// alive (its Drop would otherwise close the QUIC connection).
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
        h3::server::Connection<h3_quinn::Connection, Bytes>,
    ),
    Error,
> {
    let remote = conn.remote_address();
    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| Error::Connect(format!("h3 server: {e}")))?;

    let resolver = match h3_conn.accept().await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok((None, h3_conn)),
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

    Ok((result, h3_conn))
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
}
