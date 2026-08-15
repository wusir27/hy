//! P5.E3: Chrome parrot = client Initial SCID length 0.

#![cfg(all(test, feature = "transport"))]

use crate::client::{self, Config as ClientConfig, TlsConfig as ClientTls};
use std::time::Duration;

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

/// RFC 9000 §17.2: after DCID, the next byte is Source Connection ID Length.
fn long_header_scid_len(payload: &[u8]) -> Option<u8> {
    if payload.len() < 6 || payload[0] & 0x80 == 0 {
        return None;
    }
    let dcid_len = payload[5] as usize;
    payload.get(6 + dcid_len).copied()
}

async fn first_client_initial(disable_chrome_parrot: bool) -> Vec<u8> {
    let sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = sink.local_addr().unwrap();
    assert_ne!(server_addr.port(), 443);

    let mut cfg = client_cfg(server_addr, "x");
    cfg.quic.disable_chrome_parrot = disable_chrome_parrot;

    let connect_task = tokio::spawn(async move {
        let _ = client::connect(cfg).await;
    });

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sink.recv_from(&mut buf))
        .await
        .expect("timed out waiting for client Initial")
        .expect("recv");
    connect_task.abort();
    buf.truncate(n);
    buf
}

#[tokio::test]
async fn chrome_parrot_on_zero_length_scid() {
    let pkt = first_client_initial(false).await;
    let scid = long_header_scid_len(&pkt).expect("client Initial must be a long-header packet");
    assert_eq!(scid, 0, "parrot ON → Initial SCID length 0");
}

#[tokio::test]
async fn chrome_parrot_off_nonzero_scid() {
    let pkt = first_client_initial(true).await;
    let scid = long_header_scid_len(&pkt).expect("client Initial must be a long-header packet");
    assert_ne!(scid, 0, "disableChromeParrot → SCID length is not 0");
    assert_eq!(scid, 8, "quinn default hashed CID is 8 bytes");
}
