//! P1 integration: password auth + TCP echo over local random ports.

#![cfg(all(test, feature = "transport"))]

use crate::client::{self, Config as ClientConfig, TlsConfig as ClientTls};
use crate::error::Error;
use crate::io::{DatagramIo, StdUdp};
use crate::protocol::{read_tcp_response_bytes, write_tcp_request_bytes, STATUS_AUTH_OK};
use crate::server::{
    self, Authenticator, Config as ServerConfig, PasswordAuthenticator, TlsConfig as ServerTls,
};
use crate::transport::h3_auth;
use crate::transport::quic;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn self_signed_pem() -> (Vec<u8>, Vec<u8>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (
        certified.cert.pem().into_bytes(),
        certified.key_pair.serialize_pem().into_bytes(),
    )
}

fn client_cfg(server_addr: std::net::SocketAddr, auth: &str) -> ClientConfig {
    let mut c = ClientConfig::default();
    c.server_addr = Some(server_addr);
    c.auth = auth.into();
    c.tls = ClientTls {
        server_name: "localhost".into(),
        insecure_skip_verify: true,
        ..Default::default()
    };
    c
}

#[tokio::test]
async fn p1_auth_and_tcp_echo() {
    let (cert_pem, key_pem) = self_signed_pem();

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = udp.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);

    let mut scfg = ServerConfig {
        tls: ServerTls { cert_pem, key_pem, ..Default::default() },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    match client::connect(client_cfg(server_addr, "wrong")).await {
        Err(Error::Auth { .. }) => {}
        Err(e) => panic!("expected Auth, got {e:?}"),
        Ok(_) => panic!("expected Auth error, connect succeeded"),
    }

    let (cli, info) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    assert_eq!(info.server_addr, server_addr);
    assert!(!info.udp_enabled);

    let echo_s = format!("{echo_addr}");
    let mut tcp = cli.tcp(&echo_s).await.expect("tcp");
    tcp.write(b"hello").await.unwrap();
    let mut out = [0u8; 5];
    let mut got = 0;
    while got < 5 {
        let n = tcp.read(&mut out[got..]).await.unwrap();
        assert!(n > 0, "eof before echo complete");
        got += n;
    }
    assert_eq!(&out, b"hello");

    let _ = tcp.close().await;
    let _ = cli.close().await;
    let _ = server.close().await;
}

fn client_ca_and_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::new(vec!["hy-ca".into()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let client_params = rcgen::CertificateParams::new(vec!["hy-client".into()]).unwrap();
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key).unwrap();
    (
        ca_cert.pem().into_bytes(),
        client_cert.pem().into_bytes(),
        client_key.serialize_pem().into_bytes(),
    )
}

async fn echo_listener() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let h = tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (h, echo_addr)
}

#[tokio::test]
async fn p1_client_cert_mtls() {
    let (cert_pem, key_pem) = self_signed_pem();
    let (ca_pem, client_cert, client_key) = client_ca_and_cert();
    let (_echo_h, echo_addr) = echo_listener().await;

    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_addr = udp.local_addr().unwrap();
    let mut scfg = ServerConfig {
        tls: ServerTls {
            cert_pem,
            key_pem,
            client_ca_pem: ca_pem,
        },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    match client::connect(client_cfg(server_addr, "test")).await {
        Err(Error::Connect(_)) | Err(Error::Closed(_)) | Err(Error::Quic(_)) => {}
        Err(e) => panic!("expected TLS reject without client cert, got {e}"),
        Ok(_) => panic!("connect without client cert must fail"),
    }

    let mut c = client_cfg(server_addr, "test");
    c.tls.client_cert_pem = client_cert;
    c.tls.client_key_pem = client_key;
    let (cli, _) = client::connect(c).await.expect("mtls connect");
    let echo_s = format!("{echo_addr}");
    let tcp = cli.tcp(&echo_s).await.expect("tcp");
    tcp.write(b"hello").await.unwrap();
    let mut out = [0u8; 5];
    let mut got = 0;
    while got < 5 {
        let n = tcp.read(&mut out[got..]).await.unwrap();
        assert!(n > 0);
        got += n;
    }
    assert_eq!(&out, b"hello");
    let _ = tcp.close().await;
    let _ = cli.close().await;
    let _ = server.close().await;
}

struct CountAuth {
    password: String,
    n: AtomicUsize,
}

#[async_trait]
impl Authenticator for CountAuth {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        self.n.fetch_add(1, Ordering::SeqCst);
        if auth == self.password {
            (true, "user".into())
        } else {
            (false, String::new())
        }
    }
}

/// After first 233, H3 is left: extra non-0x401 bidi must not close QUIC, and
/// hy↔hy TCP still works via native `accept_bi` (0x401). A second 233 is **not**
/// required (P9.B product item cancelled).
#[tokio::test]
async fn p9_second_auth_same_quic_returns_233() {
    let (cert_pem, key_pem) = self_signed_pem();
    let (_echo_h, echo_addr) = echo_listener().await;

    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_addr = udp.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);

    let counter = Arc::new(CountAuth {
        password: "test".into(),
        n: AtomicUsize::new(0),
    });
    let mut scfg = ServerConfig {
        tls: ServerTls {
            cert_pem,
            key_pem,
            ..Default::default()
        },
        conn: Some(Arc::new(udp)),
        authenticator: Some(counter.clone()),
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    let mut c = client_cfg(server_addr, "test");
    c.verify_and_fill().unwrap();
    let client_udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (endpoint, _) = quic::build_client_endpoint(
        Arc::new(client_udp),
        &c.tls,
        &c.quic,
        &c.congestion.ty,
        c.bandwidth.disable_loss_compensation,
    )
    .unwrap();
    let conn = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("quic connect");

    let (status, _auth, hold) = tokio::time::timeout(
        Duration::from_secs(5),
        h3_auth::client_auth(conn.clone(), "test", 0),
    )
    .await
    .expect("first auth timeout")
    .expect("first auth");
    assert_eq!(status, STATUS_AUTH_OK);
    assert_eq!(counter.n.load(Ordering::SeqCst), 1);

    // Extra bidi that is not 0x401: finish/stop that stream only; QUIC stays up.
    let (mut junk_send, junk_recv) = conn.open_bi().await.expect("junk bi");
    junk_send.write_all(&[0x00]).await.expect("junk write");
    let _ = junk_send.finish();
    drop(junk_recv);

    // A late uni after 233 must not close QUIC (H3 session ended; not fed to h3).
    let mut junk_uni = conn.open_uni().await.expect("junk uni");
    junk_uni.write_all(&[0x00]).await.expect("junk uni write");
    let _ = junk_uni.finish();

    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        conn.close_reason().is_none(),
        "QUIC must stay up after non-0x401 bidi / late uni"
    );

    let echo_s = format!("{echo_addr}");
    let (mut send, mut recv) = conn.open_bi().await.expect("tcp bi");
    send.write_all(&write_tcp_request_bytes(&echo_s))
        .await
        .expect("tcp req");
    send.write_all(b"hello").await.expect("payload");

    let mut buf = Vec::new();
    let (_ok, _msg, consumed) = loop {
        let mut tmp = [0u8; 256];
        let n = recv
            .read(&mut tmp)
            .await
            .expect("tcp resp read")
            .expect("eof before tcp response");
        buf.extend_from_slice(&tmp[..n]);
        match read_tcp_response_bytes(&buf) {
            Ok(v) => break v,
            Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
            Err(e) => panic!("tcp resp: {e}"),
        }
    };
    assert!(_ok, "tcp response ok");
    let mut rest = buf[consumed..].to_vec();
    let mut got = rest.len();
    while got < 5 {
        let mut tmp = [0u8; 16];
        let n = recv.read(&mut tmp).await.expect("echo").expect("eof echo");
        rest.extend_from_slice(&tmp[..n]);
        got = rest.len();
    }
    assert_eq!(&rest[..5], b"hello");
    assert!(conn.close_reason().is_none());

    let _ = send.finish();
    drop(hold);
    conn.close(quinn::VarInt::from_u32(0x100), b"");
    let _ = server.close().await;
}

/// Extra 0x00 uni before `POST /auth`: wrapper hides it from rust `h3`, so
/// `accept()` still gets `/auth` and QUIC stays up.
#[tokio::test]
async fn p9_extra_control_uni_before_auth_still_gets_auth() {
    let (cert_pem, key_pem) = self_signed_pem();
    let (_echo_h, echo_addr) = echo_listener().await;

    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let server_addr = udp.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);

    let mut scfg = ServerConfig {
        tls: ServerTls {
            cert_pem,
            key_pem,
            ..Default::default()
        },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    let mut c = client_cfg(server_addr, "test");
    c.verify_and_fill().unwrap();
    let client_udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (endpoint, _) = quic::build_client_endpoint(
        Arc::new(client_udp),
        &c.tls,
        &c.quic,
        &c.congestion.ty,
        c.bandwidth.disable_loss_compensation,
    )
    .unwrap();
    let conn = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("quic connect");

    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, mut send_request) = h3::client::new(h3_conn)
        .await
        .expect("h3 client");
    let drive = tokio::spawn(async move {
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut driver).poll_close(cx)).await;
    });

    // First 0x00 (and QPACK 0x02/0x03) already sent by h3::client::new.
    // Second 0x00 must not make rust h3 close the connection.
    let mut extra = conn.open_uni().await.expect("extra control uni");
    extra.write_all(&[0x00]).await.expect("write extra 0x00");
    let _ = extra.finish();

    let (status, _) = tokio::time::timeout(
        Duration::from_secs(5),
        h3_auth::post_hysteria_auth(&mut send_request, "test", 0),
    )
    .await
    .expect("auth timeout")
    .expect("auth");
    assert_eq!(status, STATUS_AUTH_OK);
    assert!(
        conn.close_reason().is_none(),
        "QUIC must stay up after extra 0x00 control uni: {:?}",
        conn.close_reason()
    );

    let echo_s = format!("{echo_addr}");
    let (mut send, mut recv) = conn.open_bi().await.expect("tcp bi");
    send.write_all(&write_tcp_request_bytes(&echo_s))
        .await
        .expect("tcp req");
    send.write_all(b"hello").await.expect("payload");

    let mut buf = Vec::new();
    let (_ok, _msg, consumed) = loop {
        let mut tmp = [0u8; 256];
        let n = recv
            .read(&mut tmp)
            .await
            .expect("tcp resp read")
            .expect("eof before tcp response");
        buf.extend_from_slice(&tmp[..n]);
        match read_tcp_response_bytes(&buf) {
            Ok(v) => break v,
            Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
            Err(e) => panic!("tcp resp: {e}"),
        }
    };
    assert!(_ok, "tcp response ok");
    let mut rest = buf[consumed..].to_vec();
    let mut got = rest.len();
    while got < 5 {
        let mut tmp = [0u8; 16];
        let n = recv.read(&mut tmp).await.expect("echo").expect("eof echo");
        rest.extend_from_slice(&tmp[..n]);
        got = rest.len();
    }
    assert_eq!(&rest[..5], b"hello");
    assert!(conn.close_reason().is_none());

    let _ = send.finish();
    drive.abort();
    conn.close(quinn::VarInt::from_u32(0x100), b"");
    let _ = server.close().await;
}

/// After `server_authenticate` returns, `handle_conn` only `accept_bi` / `closed`
/// (and optional uni drain). No `h3.accept()` in that loop.
#[test]
fn p9_handle_conn_leaves_h3_after_authenticate() {
    let src = include_str!("server/impl.rs");
    let start = src.find("async fn handle_conn").expect("handle_conn");
    let rest = &src[start + 1..];
    let end = rest
        .find("\nasync fn ")
        .map(|i| start + 1 + i)
        .unwrap_or(src.len());
    let fn_src = &src[start..end];
    let auth_at = fn_src
        .find("server_authenticate")
        .expect("server_authenticate");
    let after = &fn_src[auth_at..];
    assert!(
        after.contains("conn.accept_bi()"),
        "after auth the loop must accept_bi"
    );
    assert!(
        after.contains("conn.closed()"),
        "after auth the loop must wait on closed"
    );
    assert!(
        !after.contains("h3_conn.accept()")
            && !after.contains("h3.accept()")
            && !after.contains("h3_conn.accept"),
        "must not call h3.accept after authenticate returns"
    );
}

async fn read_tcp_echo(recv: &mut quinn::RecvStream, want: &[u8]) {
    use crate::protocol::read_tcp_response_bytes;
    let mut buf = Vec::new();
    let (_ok, _msg, consumed) = loop {
        let mut tmp = [0u8; 256];
        let n = recv
            .read(&mut tmp)
            .await
            .expect("tcp resp read")
            .expect("eof before tcp response");
        buf.extend_from_slice(&tmp[..n]);
        match read_tcp_response_bytes(&buf) {
            Ok(v) => break v,
            Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
            Err(e) => panic!("tcp resp: {e}"),
        }
    };
    assert!(_ok, "tcp response ok");
    let mut rest = buf[consumed..].to_vec();
    while rest.len() < want.len() {
        let mut tmp = [0u8; 16];
        let n = recv.read(&mut tmp).await.expect("echo").expect("eof echo");
        rest.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(&rest[..want.len()], want);
}

async fn p9e_start_server(
    outbound: Option<Arc<dyn crate::server::Outbound>>,
) -> (Arc<dyn crate::server::Server>, std::net::SocketAddr, std::net::SocketAddr) {
    let (cert_pem, key_pem) = self_signed_pem();
    let (_echo_h, echo_addr) = echo_listener().await;
    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = udp.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);
    let mut scfg = ServerConfig {
        tls: ServerTls {
            cert_pem,
            key_pem,
            ..Default::default()
        },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        outbound,
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;
    (server, server_addr, echo_addr)
}

async fn p9e_h3_client(
    server_addr: std::net::SocketAddr,
) -> (
    quinn::Connection,
    h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let mut c = client_cfg(server_addr, "test");
    c.verify_and_fill().unwrap();
    let client_udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let (endpoint, _) = quic::build_client_endpoint(
        Arc::new(client_udp),
        &c.tls,
        &c.quic,
        &c.congestion.ty,
        c.bandwidth.disable_loss_compensation,
    )
    .unwrap();
    let conn = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .expect("quic connect");
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let (mut driver, send_request) = h3::client::new(h3_conn).await.expect("h3 client");
    let drive = tokio::spawn(async move {
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut driver).poll_close(cx)).await;
    });
    (conn, send_request, drive)
}

/// Auth HTTP bidi plus an immediate `0x401`: 233 succeeds, TCP reaches
/// `handle_tcp` (echo), does not stall in `resolve_request`.
#[tokio::test]
async fn p9_auth_http_then_immediate_tcp_request() {
    let (server, server_addr, echo_addr) = p9e_start_server(None).await;
    let (conn, mut send_request, drive) = p9e_h3_client(server_addr).await;
    let echo_s = format!("{echo_addr}");
    let conn_tcp = conn.clone();
    let echo_tcp = echo_s.clone();
    let tcp_task = tokio::spawn(async move {
        let (mut send, mut recv) = conn_tcp.open_bi().await.expect("tcp bi");
        send.write_all(&write_tcp_request_bytes(&echo_tcp))
            .await
            .expect("tcp req");
        send.write_all(b"hello").await.expect("payload");
        read_tcp_echo(&mut recv, b"hello").await;
        let _ = send.finish();
    });

    let (status, _) = tokio::time::timeout(
        Duration::from_secs(5),
        h3_auth::post_hysteria_auth(&mut send_request, "test", 0),
    )
    .await
    .expect("auth timeout — 0x401 must not enter resolve_request")
    .expect("auth");
    assert_eq!(status, STATUS_AUTH_OK);

    tokio::time::timeout(Duration::from_secs(5), tcp_task)
        .await
        .expect("queued/concurrent 0x401 must reach handle_tcp")
        .expect("tcp task");
    drive.abort();
    conn.close(quinn::VarInt::from_u32(0x100), b"");
    let _ = server.close().await;
}

/// First bidi is `0x401`, `/auth` comes later: no Timeout; after 233 the queued
/// TCP is handled. Outbound is not dialed before authenticate succeeds.
#[tokio::test]
async fn p9_tcp_request_before_auth_is_queued() {
    struct GateOutbound {
        authed: Arc<std::sync::atomic::AtomicBool>,
        illegal: Arc<std::sync::atomic::AtomicBool>,
        inner: crate::server::DefaultOutbound,
    }
    #[async_trait]
    impl crate::server::Outbound for GateOutbound {
        async fn tcp(
            &self,
            req_addr: &str,
        ) -> Result<Box<dyn crate::server::HyTcpStream>, Error> {
            if !self.authed.load(Ordering::SeqCst) {
                self.illegal.store(true, Ordering::SeqCst);
            }
            self.inner.tcp(req_addr).await
        }
        async fn udp(
            &self,
            req_addr: &str,
        ) -> Result<Box<dyn crate::server::HyUdpSocket>, Error> {
            self.inner.udp(req_addr).await
        }
        async fn check_udp(&self, req_addr: &str) -> Result<(), Error> {
            self.inner.check_udp(req_addr).await
        }
    }
    struct GateAuth {
        password: String,
        authed: Arc<std::sync::atomic::AtomicBool>,
    }
    #[async_trait]
    impl Authenticator for GateAuth {
        async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
            let ok = auth == self.password;
            if ok {
                self.authed.store(true, Ordering::SeqCst);
            }
            (ok, if ok { "user".into() } else { String::new() })
        }
    }

    let (cert_pem, key_pem) = self_signed_pem();
    let (_echo_h, echo_addr) = echo_listener().await;
    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = udp.local_addr().unwrap();
    let authed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let illegal = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut scfg = ServerConfig {
        tls: ServerTls {
            cert_pem,
            key_pem,
            ..Default::default()
        },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(GateAuth {
            password: "test".into(),
            authed: authed.clone(),
        })),
        outbound: Some(Arc::new(GateOutbound {
            authed: authed.clone(),
            illegal: illegal.clone(),
            inner: crate::server::DefaultOutbound,
        })),
        disable_udp: true,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    let (conn, mut send_request, drive) = p9e_h3_client(server_addr).await;
    let echo_s = format!("{echo_addr}");

    // 0x401 first, then POST /auth.
    let (mut send, mut recv) = conn.open_bi().await.expect("tcp bi first");
    send.write_all(&write_tcp_request_bytes(&echo_s))
        .await
        .expect("tcp req");
    send.write_all(b"hello").await.expect("payload");

    let (status, _) = tokio::time::timeout(
        Duration::from_secs(5),
        h3_auth::post_hysteria_auth(&mut send_request, "test", 0),
    )
    .await
    .expect("auth timeout — first bidi 0x401 must not enter resolve_request")
    .expect("auth");
    assert_eq!(status, STATUS_AUTH_OK);

    tokio::time::timeout(Duration::from_secs(5), read_tcp_echo(&mut recv, b"hello"))
        .await
        .expect("queued 0x401 after 233");
    assert!(
        !illegal.load(Ordering::SeqCst),
        "must not dial outbound before 233"
    );

    let _ = send.finish();
    drive.abort();
    conn.close(quinn::VarInt::from_u32(0x100), b"");
    let _ = server.close().await;
}
