//! Product-test harness: hy-core P1 server + local TCP echo.
//! Prints SERVER=host:port and ECHO=host:port then serves until killed.

use hy_core::io::{DatagramIo, StdUdp};
use hy_core::server::{self, Config as ServerConfig, PasswordAuthenticator, TlsConfig};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.key_pair.serialize_pem().into_bytes();

    let echo = TcpListener::bind("127.0.0.1:0").await.expect("echo bind");
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

    let listen: std::net::SocketAddr = std::env::var("HY_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:18443".parse().unwrap());
    let udp = StdUdp::bind(listen).await.expect("udp bind");
    let server_addr = udp.local_addr().unwrap();

    let mut scfg = ServerConfig {
        tls: TlsConfig { cert_pem, key_pem, ..Default::default() },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp: true,
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
    println!("AUTH=test");
    println!("ready");

    std::future::pending::<()>().await;
    let _ = server.close().await;
}
