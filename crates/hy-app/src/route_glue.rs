//! Inbound dial glue: [`PassthroughDial`] or (feature on + `--route`) [`RouteDial`].
//!
//! `FlowDial` lives here because it uses hy-core types. When `client-route` is
//! off, dest types are a local stub so tun/socks/http never name `hy_route::`.

use async_trait::async_trait;
use hy_core::client::{Client, HyTcpConn, HyUdpConn};
use hy_core::Error;
use std::sync::Arc;

#[cfg(feature = "client-route")]
pub use hy_route::{Dest, Proto};

#[cfg(not(feature = "client-route"))]
#[path = "../../hy-route/src/dest.rs"]
mod dest_stub;

#[cfg(not(feature = "client-route"))]
pub use dest_stub::{Dest, Proto};

/// Dial TCP/UDP for TUN, SOCKS5, and HTTP inbounds.
///
/// UDP keeps today's session model: one `HyUdpConn` from `Client::udp()`, then
/// send to many addresses. `dest` is ignored by [`PassthroughDial`].
#[async_trait]
pub trait FlowDial: Send + Sync {
    async fn tcp(&self, dest: Dest) -> Result<Box<dyn HyTcpConn>, Error>;
    async fn udp(&self, dest: Dest) -> Result<Box<dyn HyUdpConn>, Error>;
}

pub struct PassthroughDial {
    pub client: Arc<dyn Client>,
}

#[async_trait]
impl FlowDial for PassthroughDial {
    async fn tcp(&self, dest: Dest) -> Result<Box<dyn HyTcpConn>, Error> {
        let s = dest.addr_string();
        self.client.tcp(&s).await
    }

    async fn udp(&self, _dest: Dest) -> Result<Box<dyn HyUdpConn>, Error> {
        self.client.udp().await
    }
}

/// Decide then PROXY (unique Client) / REJECT / DIRECT-not-implemented.
#[cfg(feature = "client-route")]
pub struct RouteDial {
    pub router: hy_route::Router,
    pub client: Arc<dyn Client>,
}

#[cfg(feature = "client-route")]
#[async_trait]
impl FlowDial for RouteDial {
    async fn tcp(&self, dest: Dest) -> Result<Box<dyn HyTcpConn>, Error> {
        match self.router.decide(&dest) {
            hy_route::Action::Proxy => {
                let s = dest.addr_string();
                self.client.tcp(&s).await
            }
            hy_route::Action::Reject => Err(Error::Dial("rejected".into())),
            hy_route::Action::Direct => Err(Error::config("route", "DIRECT not implemented")),
        }
    }

    async fn udp(&self, dest: Dest) -> Result<Box<dyn HyUdpConn>, Error> {
        match self.router.decide(&dest) {
            hy_route::Action::Proxy => self.client.udp().await,
            hy_route::Action::Reject => Err(Error::Dial("rejected".into())),
            hy_route::Action::Direct => Err(Error::config("route", "DIRECT not implemented")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hy_core::client::{HyTcpConn, HyUdpConn};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct RecClient {
        tcp_addrs: Mutex<Vec<String>>,
        udp_calls: AtomicUsize,
    }

    impl RecClient {
        fn new() -> Self {
            Self {
                tcp_addrs: Mutex::new(Vec::new()),
                udp_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Client for RecClient {
        async fn tcp(&self, addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
            self.tcp_addrs.lock().unwrap().push(addr.to_string());
            Err(Error::Dial("rec".into()))
        }
        async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
            self.udp_calls.fetch_add(1, Ordering::SeqCst);
            Err(Error::Dial("rec".into()))
        }
        async fn close(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn dest_addr_string_host_and_ip() {
        let host = Dest {
            host: Some("example.com".into()),
            ip: None,
            port: 443,
            proto: Proto::Tcp,
        };
        assert_eq!(host.addr_string(), "example.com:443");

        let v4 = Dest::from_socket_addr(
            SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 80)),
            Proto::Tcp,
        );
        assert_eq!(v4.addr_string(), "1.2.3.4:80");

        let v6 = Dest::from_socket_addr(
            SocketAddr::from((Ipv6Addr::LOCALHOST, 443)),
            Proto::Udp,
        );
        assert_eq!(v6.addr_string(), "[::1]:443");
        assert_eq!(v6.addr_string(), SocketAddr::from((Ipv6Addr::LOCALHOST, 443)).to_string());
    }

    #[tokio::test]
    async fn passthrough_tcp_dest_string_matches_host_and_ip() {
        let rec = Arc::new(RecClient::new());
        let dial = PassthroughDial {
            client: rec.clone(),
        };

        let _ = dial
            .tcp(Dest {
                host: Some("example.com".into()),
                ip: None,
                port: 443,
                proto: Proto::Tcp,
            })
            .await;
        let _ = dial
            .tcp(Dest::from_socket_addr(
                "8.8.8.8:53".parse().unwrap(),
                Proto::Tcp,
            ))
            .await;
        let _ = dial
            .tcp(Dest::from_socket_addr(
                "[2001:db8::1]:443".parse().unwrap(),
                Proto::Tcp,
            ))
            .await;

        let addrs = rec.tcp_addrs.lock().unwrap().clone();
        assert_eq!(
            addrs,
            vec![
                "example.com:443".to_string(),
                "8.8.8.8:53".to_string(),
                "[2001:db8::1]:443".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn passthrough_udp_ignores_dest_and_opens_one_session() {
        let rec = Arc::new(RecClient::new());
        let dial = PassthroughDial {
            client: rec.clone(),
        };
        let d1 = Dest {
            host: None,
            ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            port: 53,
            proto: Proto::Udp,
        };
        let d2 = Dest {
            host: Some("other.example".into()),
            ip: None,
            port: 9,
            proto: Proto::Udp,
        };
        let _ = dial.udp(d1).await;
        let _ = dial.udp(d2).await;
        assert_eq!(rec.udp_calls.load(Ordering::SeqCst), 2);
        assert!(rec.tcp_addrs.lock().unwrap().is_empty());
    }

    #[cfg(feature = "client-route")]
    #[tokio::test]
    async fn route_dial_proxy_reject_direct_not_faked() {
        let rec = Arc::new(RecClient::new());
        let router = hy_route::compile(
            "[Rule]\nDOMAIN,proxy.example,PROXY\nDOMAIN,rej.example,REJECT\nDOMAIN,dir.example,DIRECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        let dial = RouteDial {
            router,
            client: rec.clone(),
        };

        let _ = dial
            .tcp(Dest {
                host: Some("proxy.example".into()),
                ip: None,
                port: 443,
                proto: Proto::Tcp,
            })
            .await;
        assert_eq!(
            rec.tcp_addrs.lock().unwrap().as_slice(),
            &["proxy.example:443".to_string()]
        );

        rec.tcp_addrs.lock().unwrap().clear();
        let rej = match dial
            .tcp(Dest {
                host: Some("rej.example".into()),
                ip: None,
                port: 80,
                proto: Proto::Tcp,
            })
            .await
        {
            Ok(_) => panic!("REJECT must fail"),
            Err(e) => e,
        };
        assert!(
            rec.tcp_addrs.lock().unwrap().is_empty(),
            "REJECT must not open a tunnel"
        );
        match rej {
            Error::Dial(s) => assert!(s.contains("reject"), "{s}"),
            other => panic!("expected Dial reject, got {other:?}"),
        }

        let dir = match dial
            .tcp(Dest {
                host: Some("dir.example".into()),
                ip: None,
                port: 443,
                proto: Proto::Tcp,
            })
            .await
        {
            Ok(_) => panic!("DIRECT must fail"),
            Err(e) => e,
        };
        assert!(
            rec.tcp_addrs.lock().unwrap().is_empty(),
            "DIRECT must not fake via the hy tunnel"
        );
        match dir {
            Error::Config { field, reason } => {
                assert_eq!(field, "route");
                assert!(
                    reason.contains("DIRECT not implemented"),
                    "{reason}"
                );
            }
            other => panic!("expected config DIRECT not implemented, got {other:?}"),
        }
        assert_eq!(rec.udp_calls.load(Ordering::SeqCst), 0);
    }
}
