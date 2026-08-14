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

pub async fn run_udp(
    listen: &str,
    remote: &str,
    timeout: Duration,
    client: Arc<dyn Client>,
) -> Result<(), Error> {
    let addr = parse_listen(listen, "udpForwarding.listen")?;
    let sock = Arc::new(UdpSocket::bind(addr).await.map_err(Error::Io)?);
    tracing::info!("udpForwarding listen {addr} -> {remote}");
    let mut txs: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = sock.recv_from(&mut buf).await.map_err(Error::Io)?;
        txs.retain(|_, tx| !tx.is_closed());
        if let Some(tx) = txs.get(&src) {
            let _ = tx.try_send(buf[..n].to_vec());
            continue;
        }
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let _ = tx.try_send(buf[..n].to_vec());
        txs.insert(src, tx);
        let mut udp = match client.udp().await {
            Ok(u) => u,
            Err(_) => continue,
        };
        let remote = remote.to_string();
        let sock2 = Arc::clone(&sock);
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                let _ = udp.send(&pkt, &remote).await;
                loop {
                    match tokio::time::timeout(timeout, udp.receive()).await {
                        Ok(Ok((payload, _))) => {
                            let _ = sock2.send_to(&payload, src).await;
                        }
                        Ok(Err(_)) => return,
                        Err(_) => {
                            if rx.is_empty() {
                                break;
                            }
                        }
                    }
                    while let Ok(more) = rx.try_recv() {
                        let _ = udp.send(&more, &remote).await;
                    }
                }
            }
            let _ = udp.close().await;
        });
    }
}
