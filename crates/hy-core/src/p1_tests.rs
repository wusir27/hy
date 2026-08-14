//! P1 integration: password auth + TCP echo over local random ports.

#![cfg(all(test, feature = "transport"))]

use crate::client::{self, Config as ClientConfig, TlsConfig as ClientTls};
use crate::error::Error;
use crate::io::{DatagramIo, StdUdp};
use crate::server::{
    self, Config as ServerConfig, PasswordAuthenticator, TlsConfig as ServerTls,
};
use std::sync::Arc;
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
