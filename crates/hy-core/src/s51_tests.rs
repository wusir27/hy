//! S5.1: `trace_stream` / `untrace_stream` wiring (fake TrafficLogger).

#![cfg(all(test, feature = "transport"))]

use crate::client::{self, Config as ClientConfig, TlsConfig as ClientTls};
use crate::io::{DatagramIo, StdUdp};
use crate::server::{
    self, Config as ServerConfig, PasswordAuthenticator, StreamStats, TlsConfig as ServerTls,
    TrafficLogger,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

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

struct FakeTrafficLogger {
    streams: Mutex<HashMap<u64, Arc<StreamStats>>>,
    kick: AtomicBool,
}

impl FakeTrafficLogger {
    fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            kick: AtomicBool::new(false),
        }
    }

    fn len(&self) -> usize {
        self.streams.lock().unwrap().len()
    }

    fn entries(&self) -> Vec<(String, String)> {
        self.streams
            .lock()
            .unwrap()
            .values()
            .map(|s| (s.auth_id.clone(), s.req_addr.clone()))
            .collect()
    }

    fn set_kick(&self, v: bool) {
        self.kick.store(v, Ordering::SeqCst);
    }
}

impl TrafficLogger for FakeTrafficLogger {
    fn log_traffic(&self, _id: &str, _tx: u64, _rx: u64) -> bool {
        !self.kick.load(Ordering::SeqCst)
    }

    fn log_online_state(&self, _id: &str, _online: bool) {}

    fn trace_stream(&self, stream_id: u64, stats: Arc<StreamStats>) {
        self.streams.lock().unwrap().insert(stream_id, stats);
    }

    fn untrace_stream(&self, stream_id: u64) {
        self.streams.lock().unwrap().remove(&stream_id);
    }
}

async fn wait_len(logger: &FakeTrafficLogger, n: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if logger.len() == n {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timeout waiting for traced stream count {n}, have {}", logger.len());
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

async fn echo_tcp() -> (tokio::task::JoinHandle<()>, std::net::SocketAddr) {
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

async fn serve_with_logger(
    logger: Arc<FakeTrafficLogger>,
    disable_udp: bool,
) -> (Arc<dyn crate::server::Server>, std::net::SocketAddr) {
    let (cert_pem, key_pem) = self_signed_pem();
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
        disable_udp,
        traffic_logger: Some(logger as Arc<dyn TrafficLogger>),
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;
    (server, server_addr)
}

#[tokio::test]
async fn tcp_trace_open_and_close() {
    let logger = Arc::new(FakeTrafficLogger::new());
    let (_echo_h, echo_addr) = echo_tcp().await;
    let (server, server_addr) = serve_with_logger(Arc::clone(&logger), true).await;
    let echo_s = format!("{echo_addr}");

    let (cli, _) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    let tcp = cli.tcp(&echo_s).await.expect("tcp");
    tcp.write(b"hello").await.unwrap();
    let mut out = [0u8; 5];
    let mut got = 0;
    while got < 5 {
        let n = tcp.read(&mut out[got..]).await.unwrap();
        assert!(n > 0, "eof before echo complete");
        got += n;
    }
    assert_eq!(&out, b"hello");

    wait_len(&logger, 1).await;
    let entries = logger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "user");
    assert_eq!(entries[0].1, echo_s);

    let _ = tcp.close().await;
    wait_len(&logger, 0).await;

    let _ = cli.close().await;
    let _ = server.close().await;
}

#[tokio::test]
async fn udp_trace_init_and_close_session() {
    let logger = Arc::new(FakeTrafficLogger::new());
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match echo.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    let (server, server_addr) = serve_with_logger(Arc::clone(&logger), false).await;
    let dest = format!("{echo_addr}");

    let (cli, info) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    assert!(info.udp_enabled);
    let session = cli.udp().await.expect("udp session");
    session.send(b"ping", &dest).await.expect("udp send");
    let (got, addr) = tokio::time::timeout(Duration::from_secs(5), session.receive())
        .await
        .expect("recv timeout")
        .expect("udp recv");
    assert_eq!(got, b"ping");
    assert_eq!(addr, dest);

    wait_len(&logger, 1).await;
    let entries = logger.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "user");
    assert_eq!(entries[0].1, dest);

    let _ = session.close().await;
    let _ = cli.close().await;
    wait_len(&logger, 0).await;

    let _ = server.close().await;
}

#[tokio::test]
async fn tcp_kick_untraces() {
    let logger = Arc::new(FakeTrafficLogger::new());
    let (_echo_h, echo_addr) = echo_tcp().await;
    let (server, server_addr) = serve_with_logger(Arc::clone(&logger), true).await;
    let echo_s = format!("{echo_addr}");

    let (cli, _) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    let tcp = cli.tcp(&echo_s).await.expect("tcp");
    tcp.write(b"hello").await.unwrap();
    let mut out = [0u8; 5];
    let mut got = 0;
    while got < 5 {
        let n = tcp.read(&mut out[got..]).await.unwrap();
        assert!(n > 0);
        got += n;
    }

    wait_len(&logger, 1).await;
    let entries = logger.entries();
    assert_eq!(entries[0].0, "user");
    assert_eq!(entries[0].1, echo_s);

    logger.set_kick(true);
    let _ = tcp.write(b"more").await;
    wait_len(&logger, 0).await;

    let _ = tcp.close().await;
    let _ = cli.close().await;
    let _ = server.close().await;
}

#[tokio::test]
async fn udp_kick_untraces() {
    let logger = Arc::new(FakeTrafficLogger::new());
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match echo.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    let (server, server_addr) = serve_with_logger(Arc::clone(&logger), false).await;
    let dest = format!("{echo_addr}");

    let (cli, _) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    let session = cli.udp().await.expect("udp session");
    session.send(b"ping", &dest).await.expect("udp send");
    let _ = tokio::time::timeout(Duration::from_secs(5), session.receive())
        .await
        .expect("recv timeout")
        .expect("udp recv");

    wait_len(&logger, 1).await;
    logger.set_kick(true);
    session.send(b"pong", &dest).await.expect("udp send kick");
    wait_len(&logger, 0).await;

    let _ = session.close().await;
    let _ = cli.close().await;
    let _ = server.close().await;
}
