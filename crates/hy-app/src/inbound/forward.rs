use bytes::Bytes;
use crate::listen::parse_listen;
use hy_core::client::{Client, HyTcpConn};
use hy_core::Error;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

pub async fn run_tcp(listen: &str, remote: &str, client: Arc<dyn Client>) -> Result<(), Error> {
    let addr = parse_listen(listen, "tcpForwarding.listen")?;
    let ln = TcpListener::bind(addr).await.map_err(Error::Io)?;
    tracing::info!("tcpForwarding listen {addr} -> {remote}");
    loop {
        let (inc, _) = ln.accept().await.map_err(Error::Io)?;
        let client = Arc::clone(&client);
        let remote = remote.to_string();
        tokio::spawn(async move {
            let Ok(out) = client.tcp(&remote).await else { return };
            let _ = relay_tcp(inc, out).await;
        });
    }
}

pub async fn relay_tcp(mut local: tokio::net::TcpStream, remote: Box<dyn HyTcpConn>) -> Result<(), Error> {
    let remote: Arc<dyn HyTcpConn> = Arc::from(remote);
    let (mut lr, mut lw) = local.split();
    let up_r = Arc::clone(&remote);
    let up = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = lr.read(&mut buf).await.map_err(Error::Io)?;
            if n == 0 {
                break;
            }
            up_r.write(&buf[..n]).await?;
        }
        Ok::<_, Error>(())
    };
    let down_r = Arc::clone(&remote);
    let down = async {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = down_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            lw.write_all(&buf[..n]).await.map_err(Error::Io)?;
        }
        Ok::<_, Error>(())
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

/// Kernel UDP buffer for burst (4 MiB). OS may clamp; ignore failure.
const UDP_SOCK_BUF: u32 = 4 * 1024 * 1024;
/// Per-session uplink / local-downlink queues. Full → drop, never block sendto.
const UDP_SESS_Q: usize = 256;

pub async fn run_udp(
    listen: &str,
    remote: &str,
    timeout: Duration,
    client: Arc<dyn Client>,
) -> Result<(), Error> {
    let addr = parse_listen(listen, "udpForwarding.listen")?;
    let sock = UdpSocket::bind(addr).await.map_err(Error::Io)?;
    {
        let sref = socket2::SockRef::from(&sock);
        let _ = sref.set_recv_buffer_size(UDP_SOCK_BUF as usize);
        let _ = sref.set_send_buffer_size(UDP_SOCK_BUF as usize);
    }
    let sock = Arc::new(sock);
    tracing::info!("udpForwarding listen {addr} -> {remote}");
    let mut txs: HashMap<SocketAddr, mpsc::Sender<Bytes>> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await.map_err(Error::Io)?;
        txs.retain(|_, tx| !tx.is_closed());
        let pkt = Bytes::copy_from_slice(&buf[..n]);
        if let Some(tx) = txs.get(&src) {
            let _ = tx.try_send(pkt);
            continue;
        }
        let (tx, mut rx) = mpsc::channel::<Bytes>(UDP_SESS_Q);
        let _ = tx.try_send(pkt);
        txs.insert(src, tx);
        let udp = match client.udp().await {
            Ok(u) => u,
            Err(_) => continue,
        };
        let remote = remote.to_string();
        let sock2 = Arc::clone(&sock);
        tokio::spawn(async move {
            let (down_tx, mut down_rx) = mpsc::channel::<Bytes>(UDP_SESS_Q);
            let writer = {
                let sock_w = Arc::clone(&sock2);
                tokio::spawn(async move {
                    while let Some(payload) = down_rx.recv().await {
                        if sock_w.send_to(&payload, src).await.is_err() {
                            break;
                        }
                    }
                })
            };
            // Drain queued uplink with try_recv so one wakeup ships a burst.
            async fn send_all(
                udp: &dyn hy_core::client::HyUdpConn,
                first: Bytes,
                rx: &mut mpsc::Receiver<Bytes>,
                remote: &str,
            ) -> bool {
                if udp.send(&first, remote).await.is_err() {
                    return false;
                }
                while let Ok(more) = rx.try_recv() {
                    if udp.send(&more, remote).await.is_err() {
                        return false;
                    }
                }
                true
            }
            while let Some(pkt) = rx.recv().await {
                if !send_all(&*udp, pkt, &mut rx, &remote).await {
                    break;
                }
                loop {
                    tokio::select! {
                        Some(more) = rx.recv() => {
                            if !send_all(&*udp, more, &mut rx, &remote).await {
                                let _ = udp.close().await;
                                writer.abort();
                                return;
                            }
                        }
                        r = tokio::time::timeout(timeout, udp.receive()) => {
                            match r {
                                Ok(Ok((payload, _))) => {
                                    let _ = down_tx.try_send(Bytes::from(payload));
                                }
                                Ok(Err(_)) => {
                                    let _ = udp.close().await;
                                    writer.abort();
                                    return;
                                }
                                Err(_) => {
                                    if rx.is_empty() {
                                        let _ = udp.close().await;
                                        writer.abort();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            let _ = udp.close().await;
            drop(down_tx);
            let _ = writer.await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hy_core::client::{HyTcpConn, HyUdpConn};

    struct EchoUdp {
        q: tokio::sync::Mutex<std::collections::VecDeque<(Vec<u8>, String)>>,
        notify: tokio::sync::Notify,
        closed: std::sync::atomic::AtomicBool,
    }

    impl EchoUdp {
        fn new() -> Self {
            Self {
                q: tokio::sync::Mutex::new(std::collections::VecDeque::new()),
                notify: tokio::sync::Notify::new(),
                closed: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl HyUdpConn for EchoUdp {
        async fn receive(&self) -> Result<(Vec<u8>, String), Error> {
            loop {
                if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(Error::Closed(None));
                }
                if let Some(v) = self.q.lock().await.pop_front() {
                    return Ok(v);
                }
                self.notify.notified().await;
            }
        }
        async fn send(&self, data: &[u8], addr: &str) -> Result<(), Error> {
            self.q
                .lock()
                .await
                .push_back((data.to_vec(), addr.to_string()));
            self.notify.notify_waiters();
            Ok(())
        }
        async fn close(&self) -> Result<(), Error> {
            self.closed
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self.notify.notify_waiters();
            Ok(())
        }
    }

    struct EchoClient;

    #[async_trait]
    impl Client for EchoClient {
        async fn tcp(&self, _addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
            Err(Error::Closed(None))
        }
        async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
            Ok(Box::new(EchoUdp::new()))
        }
        async fn close(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn udp_forward_echoes_more_than_first_packet() {
        let ln = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = ln.local_addr().unwrap();
        drop(ln);
        let listen_s = listen.to_string();
        let client: Arc<dyn Client> = Arc::new(EchoClient);
        tokio::spawn(async move {
            let _ = run_udp(&listen_s, "1.1.1.1:9", Duration::from_secs(2), client).await;
        });
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 2048];
        let mut ready = false;
        for i in 0..50 {
            let msg = format!("p{i}").into_bytes();
            let _ = probe.send_to(&msg, listen).await;
            if tokio::time::timeout(Duration::from_millis(50), probe.recv_from(&mut buf))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready, "forwarder did not come up");
        let mut got = 0usize;
        for i in 0..8 {
            let msg = format!("pkt-{i}").into_bytes();
            probe.send_to(&msg, listen).await.unwrap();
            match tokio::time::timeout(Duration::from_millis(400), probe.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    assert_eq!(&buf[..n], msg.as_slice());
                    got += 1;
                }
                _ => {}
            }
        }
        assert!(got >= 6, "expected most packets echoed, got {got}");
    }
}

