//! Marked/bound innermost UDP factory for the QUIC datagram socket.
//!
//! Wraps or swaps only [`StdUdpFactory`]-equivalent binds so salamander/gecko
//! still wrap. Used only when client-route is enabled.

use async_trait::async_trait;
use hy_core::io::{ConnFactory, DatagramIo, StdUdp};
use hy_core::Error;
use hy_extras::obfs::GeckoFactory;
use hy_extras::realm::{Addr as RealmAddr, RealmFactory, RealmOptions};
use hy_extras::udphop::{HopInterval, UdpHopFactory};
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

/// Which existing datagram factory to wrap with `marked`.
pub enum UdpMarkKind {
    Plain,
    Salamander(Vec<u8>),
    Hop {
        ports: Vec<u16>,
        interval: HopInterval,
        salamander: Option<Vec<u8>>,
    },
    Gecko {
        password: Vec<u8>,
        min: usize,
        max: usize,
        hop_ports: Option<Vec<u16>>,
        hop_interval: HopInterval,
    },
    Realm {
        addr: RealmAddr,
        opts: RealmOptions,
    },
}

/// Inject marked innermost UDP. Hop/gecko/realm bind via `inner` when set.
pub fn inject_marked_udp(
    cfg: &mut hy_core::client::Config,
    marked: Arc<dyn ConnFactory>,
    kind: UdpMarkKind,
) {
    match kind {
        UdpMarkKind::Salamander(psk) => {
            cfg.conn_factory = Some(Arc::new(crate::config::SalamanderFactory {
                psk,
                inner: marked,
            }));
        }
        UdpMarkKind::Hop {
            ports,
            interval,
            salamander,
        } => {
            let mut fac = UdpHopFactory::new(ports, interval).with_inner(marked);
            if let Some(psk) = salamander {
                fac = fac.with_salamander(psk);
            }
            cfg.conn_factory = Some(Arc::new(fac));
        }
        UdpMarkKind::Gecko {
            password,
            min,
            max,
            hop_ports,
            hop_interval,
        } => {
            let mut fac = GeckoFactory::new(password, min, max).with_inner(marked);
            if let Some(ports) = hop_ports {
                fac = fac.with_hop(ports, hop_interval);
            }
            cfg.conn_factory = Some(Arc::new(fac));
        }
        UdpMarkKind::Realm { addr, opts } => {
            let slot = cfg
                .server_addr_slot
                .clone()
                .unwrap_or_else(|| Arc::new(std::sync::Mutex::new(None)));
            let fac = RealmFactory::with_slot(addr, opts, slot).with_inner(marked);
            cfg.conn_factory = Some(Arc::new(fac));
        }
        UdpMarkKind::Plain => {
            if cfg.conn_factory.is_none() {
                cfg.conn_factory = Some(marked);
            }
        }
    }
}

pub fn mark_kind_from_app(app: &crate::config::ClientApp) -> UdpMarkKind {
    if let Some((ports, interval, salamander)) = &app.hop_mark {
        return UdpMarkKind::Hop {
            ports: ports.clone(),
            interval: *interval,
            salamander: salamander.clone(),
        };
    }
    if let Some((password, min, max, hop_ports, hop_interval)) = &app.gecko_mark {
        return UdpMarkKind::Gecko {
            password: password.clone(),
            min: *min,
            max: *max,
            hop_ports: hop_ports.clone(),
            hop_interval: *hop_interval,
        };
    }
    if let Some((addr, opts)) = &app.realm_mark {
        return UdpMarkKind::Realm {
            addr: addr.clone(),
            opts: opts.clone(),
        };
    }
    if let Some(psk) = &app.salamander_only_psk {
        return UdpMarkKind::Salamander(psk.clone());
    }
    UdpMarkKind::Plain
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
        inject_marked_udp(&mut cfg, marked, UdpMarkKind::Plain);
        assert!(cfg.conn_factory.is_some());
    }

    #[test]
    fn inject_replaces_salamander_only() {
        let mut cfg = hy_core::client::Config::default();
        cfg.conn_factory = Some(Arc::new(StdUdpFactory));
        let marked: Arc<dyn ConnFactory> = Arc::new(MarkedUdpFactory::new(DirectDialer::relaxed(0x162)));
        inject_marked_udp(&mut cfg, marked, UdpMarkKind::Salamander(b"abcd".to_vec()));
        assert!(cfg.conn_factory.is_some());
    }

    #[tokio::test]
    async fn inject_wraps_hop_inner_when_route_on() {
        let counting = Arc::new(CountingFactory {
            inner: Arc::new(StdUdpFactory),
            opens: AtomicUsize::new(0),
        });
        let mut cfg = hy_core::client::Config::default();
        inject_marked_udp(
            &mut cfg,
            counting.clone(),
            UdpMarkKind::Hop {
                ports: vec![443],
                interval: HopInterval::fixed(std::time::Duration::from_secs(60)),
                salamander: None,
            },
        );
        let fac = cfg.conn_factory.expect("hop factory");
        let _ = fac.open("127.0.0.1:1".parse().unwrap()).await.unwrap();
        assert!(
            counting.opens.load(Ordering::SeqCst) >= 1,
            "hop must bind via marked inner"
        );
    }

    #[tokio::test]
    async fn inject_wraps_gecko_inner_when_route_on() {
        let counting = Arc::new(CountingFactory {
            inner: Arc::new(StdUdpFactory),
            opens: AtomicUsize::new(0),
        });
        let mut cfg = hy_core::client::Config::default();
        inject_marked_udp(
            &mut cfg,
            counting.clone(),
            UdpMarkKind::Gecko {
                password: b"test".to_vec(),
                min: 0,
                max: 0,
                hop_ports: None,
                hop_interval: HopInterval::default_30s(),
            },
        );
        let fac = cfg.conn_factory.expect("gecko factory");
        let _ = fac.open("127.0.0.1:1".parse().unwrap()).await.unwrap();
        assert_eq!(counting.opens.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn inject_wraps_realm_inner_when_route_on() {
        let counting = Arc::new(CountingFactory {
            inner: Arc::new(StdUdpFactory),
            opens: AtomicUsize::new(0),
        });
        let mut cfg = hy_core::client::Config::default();
        let addr = hy_extras::realm::parse_addr("realm://tok@127.0.0.1:9/myid").unwrap();
        let mut opts = RealmOptions::default();
        opts.inject_local_addrs = Some(vec!["127.0.0.1:1".parse().unwrap()]);
        inject_marked_udp(
            &mut cfg,
            counting.clone(),
            UdpMarkKind::Realm { addr, opts },
        );
        let fac = cfg.conn_factory.expect("realm factory");
        let _ = fac.open("127.0.0.1:1".parse().unwrap()).await;
        assert!(
            counting.opens.load(Ordering::SeqCst) >= 1,
            "realm must bind via marked inner"
        );
    }

    #[test]
    fn no_route_means_no_inject() {
        let mut cfg = hy_core::client::Config::default();
        let route_file: Option<&str> = None;
        if route_file.is_some() {
            inject_marked_udp(&mut cfg, Arc::new(StdUdpFactory), UdpMarkKind::Plain);
        }
        assert!(
            cfg.conn_factory.is_none(),
            "--no-client-route / no --route must not set a mark factory"
        );
    }

    #[test]
    fn inject_plain_leaves_existing_factory() {
        let mut cfg = hy_core::client::Config::default();
        cfg.conn_factory = Some(Arc::new(StdUdpFactory));
        let marked: Arc<dyn ConnFactory> =
            Arc::new(MarkedUdpFactory::new(DirectDialer::relaxed(0x162)));
        inject_marked_udp(&mut cfg, marked, UdpMarkKind::Plain);
        assert!(cfg.conn_factory.is_some());
    }
}
