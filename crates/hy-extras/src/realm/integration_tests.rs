//! Integration-style unit tests (no public STUN / realm server required).

use std::sync::Arc;
use std::time::Duration;

use hy_core::io::{DatagramIo, StdUdp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use super::stun::{
    build_binding_request, encode_binding_success, parse_binding_request_txid,
};

#[tokio::test]
async fn punch_packet_conn_hello_ack_and_passthrough() {
    let a = Arc::new(StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap());
    let b = Arc::new(StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap());
    let a_addr = a.local_addr().unwrap();
    let b_addr = b.local_addr().unwrap();

    let punch_a = PunchPacketConn::new(a.clone(), 8).unwrap();
    let punch_b = Arc::new(PunchPacketConn::new(b.clone(), 8).unwrap());

    let meta = PunchMetadata {
        nonce: "00112233445566778899aabbccddeeff".into(),
        obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
    };
    punch_a.add_punch_attempt("att", meta.clone()).unwrap();
    punch_b.add_punch_attempt("att", meta.clone()).unwrap();

    let mut events = punch_b.take_events().unwrap();

    // Hello should be siphoned (not returned to QUIC reader).
    let hello = encode_punch_packet(PunchPacketType::Hello, &meta).unwrap();
    punch_a.send_to(&hello, b_addr).await.unwrap();

    let b_recv = punch_b.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        b_recv.recv_from(&mut buf).await.map(|(n, addr)| (buf[..n].to_vec(), addr))
    });

    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    let quic = b"\xc0quic-looking-bytes";
    a.send_to(quic, b_addr).await.unwrap();

    let (got, from) = recv_task.await.unwrap().unwrap();
    assert_eq!(got, quic);
    assert_eq!(from, a_addr);

    let ev = tokio::time::timeout(std::time::Duration::from_secs(1), events.recv())
        .await
        .expect("timeout")
        .expect("punch event");
    assert_eq!(ev.packet.ty, PunchPacketType::Hello);
    assert_eq!(ev.from, a_addr);

    // Ack via PunchPacketConn
    let ack = encode_punch_packet(PunchPacketType::Ack, &meta).unwrap();
    punch_b.send_to(&ack, a_addr).await.unwrap();
    let mut buf = [0u8; 1500];
    // On A with attempt registered, Ack is siphoned — send a passthrough probe after.
    let a_recv = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        punch_a.recv_from(&mut buf).await.map(|(n, _)| buf[..n].to_vec())
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    b.send_to(b"pass", a_addr).await.unwrap();
    let got = a_recv.await.unwrap().unwrap();
    assert_eq!(got, b"pass");
    let _ = buf;
}

/// A: Binding Success is returned as-is from PunchPacketConn::recv_from (not siphoned).
#[tokio::test]
async fn punch_packet_conn_recv_from_returns_binding_success_bytes() {
    let client = Arc::new(StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap());
    let peer = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let stun_addr = peer.local_addr().unwrap();
    let mapped: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();

    let punch = Arc::new(PunchPacketConn::new(client, 8).unwrap());
    let punch_recv = punch.clone();

    let peer_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        let txid = parse_binding_request_txid(&buf[..n]).expect("Binding Request txid");
        let success = encode_binding_success(&txid, mapped);
        peer.send_to(&success, from).await.unwrap();
        success
    });

    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        punch_recv
            .recv_from(&mut buf)
            .await
            .map(|(n, _)| buf[..n].to_vec())
    });

    let txid = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];
    let req = build_binding_request(&txid);
    punch.send_to(&req, stun_addr).await.unwrap();

    let got = tokio::time::timeout(Duration::from_secs(3), recv_task)
        .await
        .expect("recv_from timed out waiting for Binding Success")
        .unwrap()
        .expect("recv_from failed");
    let expected = peer_task.await.unwrap();
    assert_eq!(got, expected, "Binding Success must be returned as-is from recv_from, not siphoned");
}

/// B: discover() on PunchPacketConn gets XOR-MAPPED-ADDRESS via the same recv_from.
#[tokio::test]
async fn discover_on_punch_packet_conn_gets_mapped_addr() {
    let client = Arc::new(StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap());
    let peer = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let stun_addr = peer.local_addr().unwrap();
    let mapped: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();

    let punch = PunchPacketConn::new(client, 8).unwrap();

    let peer_task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        let txid = parse_binding_request_txid(&buf[..n]).expect("Binding Request txid");
        let success = encode_binding_success(&txid, mapped);
        peer.send_to(&success, from).await.unwrap();
    });

    let addrs = tokio::time::timeout(
        Duration::from_secs(3),
        discover(
            &punch,
            STUNConfig {
                servers: vec![stun_addr.to_string()],
                timeout: Duration::from_secs(2),
                family: AddrFamily::V4,
            },
        ),
    )
    .await
    .expect("discover timed out")
    .unwrap_or_else(|e| panic!("discover failed (must not be 'no STUN responses received'): {e}"));

    assert!(
        addrs.contains(&mapped),
        "expected mapped addr {mapped}, got {addrs:?}"
    );
    peer_task.await.unwrap();
}

#[tokio::test]
async fn fake_http_signaling_register_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let meta = PunchMetadata {
        nonce: "aabbccddeeff00112233445566778899".into(),
        obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".into(),
    };

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("POST /v1/myid "));
        assert!(req.contains("Authorization: Bearer tok"));
        let body = r#"{"session_id":"sess-1","ttl":60}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = RealmClient::new(&format!("http://127.0.0.1:{port}"), "tok", false).unwrap();
    let reg = client
        .register("myid", &["127.0.0.1:40000".into()])
        .await
        .unwrap();
    assert_eq!(reg.session_id, "sess-1");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let meta2 = meta.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = sock.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains("POST /v1/myid/connect "));
        assert!(req.contains("Authorization: Bearer tok"));
        let body = format!(
            r#"{{"addresses":["127.0.0.1:50000"],"nonce":"{}","obfs":"{}"}}"#,
            meta2.nonce, meta2.obfs
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = RealmClient::new(&format!("http://127.0.0.1:{port}"), "tok", false).unwrap();
    let resp = client
        .connect(
            "myid",
            &ConnectRequest {
                addresses: vec!["127.0.0.1:40000".into()],
                meta: meta.clone(),
            },
        )
        .await
        .unwrap();
    assert_eq!(resp.addresses, vec!["127.0.0.1:50000"]);
    assert_eq!(resp.meta.nonce, meta.nonce);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let nonce = meta.nonce.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = sock.read(&mut buf).await.unwrap();
        let req = String::from_utf8_lossy(&buf[..n]);
        assert!(req.contains(&format!("POST /v1/myid/connects/{nonce}")));
        assert!(req.contains("Authorization: Bearer sess-1"));
        sock.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let client = RealmClient::new(&format!("http://127.0.0.1:{port}"), "tok", false).unwrap();
    client
        .connect_response("myid", "sess-1", &meta.nonce, &["127.0.0.1:40000".into()])
        .await
        .unwrap();
}
