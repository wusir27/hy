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

/// Decide then PROXY (unique Client) / REJECT / DIRECT (local marked/bound).
#[cfg(feature = "client-route")]
pub struct RouteDial {
    pub router: hy_route::Router,
    pub client: Arc<dyn Client>,
    pub direct: hy_route::DirectDialer,
    pub dns_cache: Arc<hy_route::dns::DnsCache>,
}

#[cfg(feature = "client-route")]
struct DirectTcp {
    inner: tokio::sync::Mutex<tokio::net::TcpStream>,
}

#[cfg(feature = "client-route")]
#[async_trait]
impl HyTcpConn for DirectTcp {
    async fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        use tokio::io::AsyncReadExt;
        self.inner.lock().await.read(buf).await.map_err(Error::Io)
    }
    async fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        use tokio::io::AsyncWriteExt;
        self.inner.lock().await.write(buf).await.map_err(Error::Io)
    }
    async fn close(&self) -> Result<(), Error> {
        use tokio::io::AsyncWriteExt;
        self.inner.lock().await.shutdown().await.map_err(Error::Io)
    }
}

#[cfg(feature = "client-route")]
struct DirectUdp {
    sock: tokio::net::UdpSocket,
}

#[cfg(feature = "client-route")]
#[async_trait]
impl HyUdpConn for DirectUdp {
    async fn receive(&self) -> Result<(Vec<u8>, String), Error> {
        let mut buf = vec![0u8; 65535];
        let (n, src) = self.sock.recv_from(&mut buf).await.map_err(Error::Io)?;
        buf.truncate(n);
        Ok((buf, src.to_string()))
    }
    async fn send(&self, data: &[u8], addr: &str) -> Result<(), Error> {
        let dest: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| Error::Dial(format!("direct udp dest {addr}: {e}")))?;
        self.sock.send_to(data, dest).await.map_err(Error::Io)?;
        Ok(())
    }
    async fn close(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(feature = "client-route")]
#[async_trait]
impl FlowDial for RouteDial {
    async fn tcp(&self, mut dest: Dest) -> Result<Box<dyn HyTcpConn>, Error> {
        hy_route::dns::fill_host_from_cache(&mut dest, &self.dns_cache);
        match self.router.decide(&dest) {
            hy_route::Action::Proxy => {
                let s = dest.addr_string();
                self.client.tcp(&s).await
            }
            hy_route::Action::Reject => Err(Error::Dial("rejected".into())),
            hy_route::Action::Direct => {
                let s = self
                    .direct
                    .tcp(&dest)
                    .await
                    .map_err(|e| Error::Dial(e.to_string()))?;
                Ok(Box::new(DirectTcp {
                    inner: tokio::sync::Mutex::new(s),
                }))
            }
        }
    }

    async fn udp(&self, mut dest: Dest) -> Result<Box<dyn HyUdpConn>, Error> {
        hy_route::dns::fill_host_from_cache(&mut dest, &self.dns_cache);
        match self.router.decide(&dest) {
            hy_route::Action::Proxy => self.client.udp().await,
            hy_route::Action::Reject => Err(Error::Dial("rejected".into())),
            hy_route::Action::Direct => {
                let v6 = dest.ip.map(|i| i.is_ipv6()).unwrap_or(false);
                let sock = self
                    .direct
                    .udp_bind(v6)
                    .await
                    .map_err(|e| Error::Dial(e.to_string()))?;
                Ok(Box::new(DirectUdp { sock }))
            }
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
    async fn route_dial_proxy_reject_unchanged() {
        let rec = Arc::new(RecClient::new());
        let router = hy_route::compile(
            "[Rule]\nDOMAIN,proxy.example,PROXY\nDOMAIN,rej.example,REJECT\nDOMAIN,dir.example,DIRECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        let dial = RouteDial {
            router,
            client: rec.clone(),
            direct: hy_route::DirectDialer::relaxed(0x162),
            dns_cache: Arc::new(hy_route::dns::DnsCache::new()),
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
        assert_eq!(rec.udp_calls.load(Ordering::SeqCst), 0);
    }

    #[cfg(feature = "client-route")]
    #[tokio::test]
    async fn route_dial_direct_local_does_not_call_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let eaddr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let (n, src) = echo.recv_from(&mut buf).await.unwrap();
            let _ = echo.send_to(&buf[..n], src).await;
        });

        let rec = Arc::new(RecClient::new());
        let router = hy_route::compile(
            "[Rule]\nIP-CIDR,127.0.0.0/8,DIRECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        let dial = RouteDial {
            router,
            client: rec.clone(),
            direct: hy_route::DirectDialer::relaxed(0x162),
            dns_cache: Arc::new(hy_route::dns::DnsCache::new()),
        };

        let conn = dial
            .tcp(Dest::from_socket_addr(addr, Proto::Tcp))
            .await
            .expect("DIRECT tcp local");
        conn.write(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert!(
            rec.tcp_addrs.lock().unwrap().is_empty(),
            "DIRECT must not call Client::tcp"
        );

        let u = dial
            .udp(Dest::from_socket_addr(eaddr, Proto::Udp))
            .await
            .expect("DIRECT udp local");
        u.send(b"hi", &eaddr.to_string()).await.unwrap();
        let (got, _) = u.receive().await.unwrap();
        assert_eq!(got, b"hi");
        assert_eq!(
            rec.udp_calls.load(Ordering::SeqCst),
            0,
            "DIRECT must not call Client::udp"
        );
    }

    #[cfg(feature = "client-route")]
    #[tokio::test]
    async fn route_dial_fills_host_from_dns_cache_before_decide() {
        let rec = Arc::new(RecClient::new());
        let router = hy_route::compile(
            "[Rule]\nDOMAIN-SUFFIX,ads.example,REJECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        let cache = Arc::new(hy_route::dns::DnsCache::new());
        let ip: std::net::IpAddr = "9.9.9.9".parse().unwrap();
        cache.insert("tracker.ads.example", hy_route::dns::TYPE_A, &[ip], 60);
        let dial = RouteDial {
            router,
            client: rec.clone(),
            direct: hy_route::DirectDialer::relaxed(0x162),
            dns_cache: cache,
        };
        let err = dial
            .tcp(Dest {
                host: None,
                ip: Some(ip),
                port: 443,
                proto: Proto::Tcp,
            })
            .await
            .err()
            .expect("REJECT");
        match err {
            Error::Dial(s) => assert!(s.contains("reject"), "{s}"),
            other => panic!("{other:?}"),
        }
        assert!(
            rec.tcp_addrs.lock().unwrap().is_empty(),
            "cached suffix REJECT must not open a tunnel"
        );
    }
}
