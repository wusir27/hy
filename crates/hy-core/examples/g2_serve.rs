//! Product-test harness: hy-core P2 server + TCP/UDP echo.
//! HY_LISTEN, HY_DISABLE_UDP=1, HY_MAX_TX, HY_MAX_RX.

use hy_core::io::{DatagramIo, StdUdp};
use hy_core::server::{
    self, BandwidthConfig, Config as ServerConfig, PasswordAuthenticator, TlsConfig,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[tokio::main]
async fn main() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.key_pair.serialize_pem().into_bytes();

    let echo = TcpListener::bind("127.0.0.1:0").await.expect("tcp echo");
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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

    let uecho = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo");
    let uecho_addr = uecho.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match uecho.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = uecho.send_to(&buf[..n], peer).await;
        }
    });

    let listen: std::net::SocketAddr = std::env::var("HY_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:18443".parse().unwrap());
    let disable_udp = std::env::var("HY_DISABLE_UDP").ok().as_deref() == Some("1");
    let max_tx = std::env::var("HY_MAX_TX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12_500_000);
    let max_rx = std::env::var("HY_MAX_RX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12_500_000);

    let udp = StdUdp::bind(listen).await.expect("udp bind");
    let server_addr = udp.local_addr().unwrap();

    let mut scfg = ServerConfig {
        tls: TlsConfig { cert_pem, key_pem, ..Default::default() },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp,
        bandwidth: BandwidthConfig {
            max_tx,
            max_rx,
            disable_loss_compensation: false,
        },
        ..Default::default()
    };
    scfg.fill().expect("fill");
    let server = server::serve(scfg).await.expect("serve build");
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });

    println!("SERVER={server_addr}");
    println!("ECHO={echo_addr}");
    println!("UECHO={uecho_addr}");
    println!("AUTH=test");
    println!("DISABLE_UDP={disable_udp}");
    println!("ready");

    std::future::pending::<()>().await;
    let _ = server.close().await;
}
