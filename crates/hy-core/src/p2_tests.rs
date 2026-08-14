//! P2 integration: UDP fragment roundtrip over local random ports.

#![cfg(all(test, feature = "transport"))]

use crate::client::{self, Config as ClientConfig, TlsConfig as ClientTls};
use crate::io::{DatagramIo, StdUdp};
use crate::server::{
    self, Config as ServerConfig, PasswordAuthenticator, TlsConfig as ServerTls,
};
use std::sync::Arc;
use tokio::net::UdpSocket;

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
async fn p2_udp_fragment_roundtrip() {
    let (cert_pem, key_pem) = self_signed_pem();

    // Echo UDP target on a random port.
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

    let udp = StdUdp::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let server_addr = udp.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);

    let mut scfg = ServerConfig {
        tls: ServerTls { cert_pem, key_pem, ..Default::default() },
        conn: Some(Arc::new(udp)),
        authenticator: Some(Arc::new(PasswordAuthenticator::new("test"))),
        disable_udp: false,
        ..Default::default()
    };
    scfg.fill().unwrap();
    let server = server::serve(scfg).await.unwrap();
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });
    tokio::task::yield_now().await;

    let (cli, info) = client::connect(client_cfg(server_addr, "test"))
        .await
        .expect("connect");
    assert!(info.udp_enabled);

    let mut session = cli.udp().await.expect("udp session");

    // Official 2.8.1 client timed out at >=1400 while 800/1200 passed.
    let dest = format!("{echo_addr}");
    for len in [800usize, 1200, 1400, 1800, 2000, 2500] {
        let payload: Vec<u8> = (0..len as u32).map(|i| (i % 256) as u8).collect();
        session.send(&payload, &dest).await.expect("udp send");
        let (got, addr) = tokio::time::timeout(std::time::Duration::from_secs(5), session.receive())
            .await
            .unwrap_or_else(|_| panic!("recv timeout len={len}"))
            .expect("udp recv");
        assert_eq!(got, payload, "echo mismatch len={len}");
        assert_eq!(addr, dest);
    }

    let _ = session.close().await;
    let _ = cli.close().await;
    let _ = server.close().await;
}


#[test]
fn advertised_max_datagram_frame_size_is_1200() {
    // §5.1.4: vendor must advertise 1200, not the recv window. A quinn bump
    // that restores datagram_receive_buffer_size as the TP fails this.
    let src = include_str!("../../../vendor/quinn-proto/src/transport_parameters.rs");
    assert!(
        src.contains("map(|_| 1200u16.into())"),
        "quinn-proto patch missing: max_datagram_frame_size must be 1200"
    );
    assert_eq!(crate::protocol::MAX_DATAGRAM_FRAME_SIZE, 1200);
}
