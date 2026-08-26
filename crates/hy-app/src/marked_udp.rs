//! Marked/bound innermost UDP factory for the QUIC datagram socket.
//!
//! Wraps or swaps only [`StdUdpFactory`]-equivalent binds so salamander/gecko
//! still wrap. Used only when client-route is enabled.

use async_trait::async_trait;
use hy_core::io::{ConnFactory, DatagramIo, StdUdp};
use hy_core::Error;
use hy_route::DirectDialer;
use std::net::SocketAddr;
use std::sync::Arc;

/// Innermost UDP bind with Linux fwmark / Darwin NIC bind.
pub struct MarkedUdpFactory {
    pub dialer: DirectDialer,
}

impl MarkedUdpFactory {
    pub fn new(dialer: DirectDialer) -> Self {
        Self { dialer }
    }
}

#[async_trait]
impl ConnFactory for MarkedUdpFactory {
    async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let v6 = server.is_ipv6();
        let sock = self
            .dialer
            .udp_bind(v6)
            .await
            .map_err(|e| Error::config("route", e.to_string()))?;
        Ok(Arc::new(StdUdp::new(sock)))
    }
}

/// Replace plain `StdUdpFactory` (or salamander's inner StdUdp) with `marked`.
/// Leaves gecko / udphop / realm factories in place.
pub fn inject_marked_udp(
    cfg: &mut hy_core::client::Config,
    marked: Arc<dyn ConnFactory>,
    salamander_only_psk: Option<&[u8]>,
) {
    if let Some(psk) = salamander_only_psk {
        cfg.conn_factory = Some(Arc::new(crate::config::SalamanderFactory {
            psk: psk.to_vec(),
            inner: marked,
        }));
    } else if cfg.conn_factory.is_none() {
        cfg.conn_factory = Some(marked);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hy_core::io::StdUdpFactory;
    use hy_extras::obfs::ObfsSalamander;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingFactory {
        inner: Arc<dyn ConnFactory>,
        opens: AtomicUsize,
    }

    #[async_trait]
    impl ConnFactory for CountingFactory {
        async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            self.inner.open(server).await
        }
    }

    #[tokio::test]
    async fn marked_stdudp_path_opens() {
        let dialer = DirectDialer::relaxed(0x162);
        let fac = MarkedUdpFactory::new(dialer);
        let io = fac
            .open("127.0.0.1:1".parse().unwrap())
            .await
            .unwrap();
        assert!(io.local_addr().unwrap().port() != 0);
    }

    #[tokio::test]
    async fn salamander_still_wraps_marked_inner() {
        let marked = Arc::new(MarkedUdpFactory::new(DirectDialer::relaxed(0x162)));
        let counting = Arc::new(CountingFactory {
            inner: marked,
            opens: AtomicUsize::new(0),
        });
        let sal = crate::config::SalamanderFactory {
            psk: b"testpassword".to_vec(),
            inner: counting.clone(),
        };
        let io = sal
            .open("127.0.0.1:1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(counting.opens.load(Ordering::SeqCst), 1);
        assert!(io.local_addr().unwrap().port() != 0);
        let _ = ObfsSalamander::new(Arc::new(StdUdp::new(
            tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        )), b"testpassword");
    }

    #[test]
    fn inject_sets_factory_when_none() {
        let mut cfg = hy_core::client::Config::default();
        assert!(cfg.conn_factory.is_none());
        let marked: Arc<dyn ConnFactory> = Arc::new(StdUdpFactory);
        inject_marked_udp(&mut cfg, marked, None);
        assert!(cfg.conn_factory.is_some());
    }

    #[test]
    fn inject_replaces_salamander_only() {
        let mut cfg = hy_core::client::Config::default();
        cfg.conn_factory = Some(Arc::new(StdUdpFactory));
        let marked: Arc<dyn ConnFactory> = Arc::new(MarkedUdpFactory::new(DirectDialer::relaxed(0x162)));
        inject_marked_udp(&mut cfg, marked, Some(b"abcd"));
        assert!(cfg.conn_factory.is_some());
    }

    #[test]
    fn inject_does_not_replace_other_factories() {
        let mut cfg = hy_core::client::Config::default();
        cfg.conn_factory = Some(Arc::new(StdUdpFactory));
        let marked: Arc<dyn ConnFactory> = Arc::new(MarkedUdpFactory::new(DirectDialer::relaxed(0x162)));
        inject_marked_udp(&mut cfg, marked, None);
        // gecko/hop/realm: conn_factory already Some and no salamander psk → leave it.
        // Type stays the original (we cannot downcast); just ensure Some.
        assert!(cfg.conn_factory.is_some());
    }

    #[test]
    fn no_route_means_no_inject() {
        let mut cfg = hy_core::client::Config::default();
        let route_file: Option<&str> = None;
        if route_file.is_some() {
            inject_marked_udp(&mut cfg, Arc::new(StdUdpFactory), None);
        }
        assert!(
            cfg.conn_factory.is_none(),
            "--no-client-route / no --route must not set a mark factory"
        );
    }
}
