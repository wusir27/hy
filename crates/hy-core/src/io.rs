//! Packet I/O hook. extras wraps this; core/transport adapts it to quinn.

use crate::error::Error;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[async_trait]
pub trait DatagramIo: Send + Sync {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> std::io::Result<usize>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn set_read_buffer(&self, n: usize) -> std::io::Result<()>;
    fn set_write_buffer(&self, n: usize) -> std::io::Result<()>;
}

#[async_trait]
pub trait ConnFactory: Send + Sync {
    async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error>;
}

/// Plain `tokio::net::UdpSocket`. `n` is plaintext length.
pub struct StdUdp {
    sock: UdpSocket,
}

impl StdUdp {
    pub fn new(sock: UdpSocket) -> Self {
        Self { sock }
    }

    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        Ok(Self {
            sock: UdpSocket::bind(addr).await?,
        })
    }
}

#[async_trait]
impl DatagramIo for StdUdp {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
        self.sock.send_to(buf, dest).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    fn set_read_buffer(&self, _n: usize) -> std::io::Result<()> {
        // v1: OS default. socket2 comes if we need it.
        Ok(())
    }

    fn set_write_buffer(&self, _n: usize) -> std::io::Result<()> {
        Ok(())
    }
}

/// Default factory: ephemeral UDP bind, independent of `server`.
pub struct StdUdpFactory;

#[async_trait]
impl ConnFactory for StdUdpFactory {
    async fn open(&self, _server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Arc::new(StdUdp::new(sock)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_send_recv() {
        let a = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dest = b.local_addr().unwrap();
        let n = a.send_to(b"ping", dest).await.unwrap();
        assert_eq!(n, 4);
        let mut buf = [0u8; 16];
        let (got, src) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..got], b"ping");
        assert_eq!(src, a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn factory_opens() {
        let f = StdUdpFactory;
        let io = f
            .open("127.0.0.1:1".parse().unwrap())
            .await
            .unwrap();
        assert!(io.local_addr().unwrap().port() != 0);
    }
}
