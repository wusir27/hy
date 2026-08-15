//! Adapter + direct + reject + system DNS + speedtest + custom resolvers.

use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, HyUdpSocket, Outbound};
use crate::acl::{CompiledRuleSet, Proto};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

mod speedtest;
pub use speedtest::{is_speedtest_host, SpeedtestHandler, SPEEDTEST_DEST};

pub mod resolver;
pub use resolver::{DohResolver, StandardResolver};

mod socks5;
pub use socks5::Socks5Outbound;

mod http;
pub use http::HttpOutbound;

#[derive(Debug, Clone, Default)]
pub struct ResolveInfo {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
    pub err: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AddrEx {
    pub host: String,
    pub port: u16,
    pub resolve: Option<ResolveInfo>,
}

pub fn split_host_port(s: &str) -> Result<AddrEx, Error> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(AddrEx {
            host: sa.ip().to_string(),
            port: sa.port(),
            resolve: Some(match sa.ip() {
                IpAddr::V4(v) => ResolveInfo {
                    v4: Some(v),
                    v6: None,
                    err: None,
                },
                IpAddr::V6(v) => ResolveInfo {
                    v4: None,
                    v6: Some(v),
                    err: None,
                },
            }),
        });
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(|| Error::Dial("bad v6 addr".into()))?;
        let port: u16 = tail
            .strip_prefix(':')
            .ok_or_else(|| Error::Dial("missing port".into()))?
            .parse()
            .map_err(|_| Error::Dial("bad port".into()))?;
        return Ok(AddrEx {
            host: host.to_string(),
            port,
            resolve: None,
        });
    }
    let (host, port) = s.rsplit_once(':').ok_or_else(|| Error::Dial("missing port".into()))?;
    let port: u16 = port.parse().map_err(|_| Error::Dial("bad port".into()))?;
    Ok(AddrEx {
        host: host.to_string(),
        port,
        resolve: None,
    })
}

#[async_trait]
pub trait PluggableOutbound: Send + Sync {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error>;
    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error>;
    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error>;
}

pub struct Adapter(pub Arc<dyn PluggableOutbound>);

#[async_trait]
impl Outbound for Adapter {
    async fn tcp(&self, req_addr: &str) -> Result<Box<dyn HyTcpStream>, Error> {
        let mut a = split_host_port(req_addr)?;
        self.0.tcp(&mut a).await
    }
    async fn udp(&self, req_addr: &str) -> Result<Box<dyn HyUdpSocket>, Error> {
        let mut a = split_host_port(req_addr)?;
        self.0.udp(&mut a).await
    }
    async fn check_udp(&self, req_addr: &str) -> Result<(), Error> {
        let mut a = split_host_port(req_addr)?;
        self.0.check_udp(&mut a).await
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum DirectMode {
    #[default]
    Auto,
    Prefer64,
    Prefer46,
    V6,
    V4,
}

pub struct Direct {
    pub mode: DirectMode,
}

impl Direct {
    pub fn new(mode: DirectMode) -> Self {
        Self { mode }
    }
}

#[async_trait]
impl PluggableOutbound for Direct {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        let dests = candidates(addr, self.mode).await?;
        let fut = async {
            match dests.as_slice() {
                [one] => TcpStream::connect(*one).await.map_err(|e| Error::Dial(e.to_string())),
                [a, b] => {
                    let fa = TcpStream::connect(*a);
                    let fb = TcpStream::connect(*b);
                    tokio::pin!(fa, fb);
                    tokio::select! {
                        r = &mut fa => match r {
                            Ok(s) => Ok(s),
                            Err(e1) => match fb.await {
                                Ok(s) => Ok(s),
                                Err(e2) => Err(Error::Dial(format!("{e1}; {e2}"))),
                            },
                        },
                        r = &mut fb => match r {
                            Ok(s) => Ok(s),
                            Err(e1) => match fa.await {
                                Ok(s) => Ok(s),
                                Err(e2) => Err(Error::Dial(format!("{e1}; {e2}"))),
                            },
                        },
                    }
                }
                _ => Err(Error::Dial("no address".into())),
            }
        };
        match tokio::time::timeout(Duration::from_secs(10), fut).await {
            Ok(Ok(s)) => Ok(Box::new(TokioTcp(s))),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::Dial("tcp dial timeout".into())),
        }
    }

    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        let bind = match self.mode {
            DirectMode::V4 => "0.0.0.0:0",
            DirectMode::V6 => "[::]:0",
            _ => "[::]:0",
        };
        let sock = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(_) if bind != "0.0.0.0:0" => UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| Error::Dial(e.to_string()))?,
            Err(e) => return Err(Error::Dial(e.to_string())),
        };
        let _ = addr;
        Ok(Box::new(TokioUdp(sock)))
    }

    async fn check_udp(&self, _addr: &mut AddrEx) -> Result<(), Error> {
        Ok(())
    }
}

/// §10.4: first-match name → outbound; hijack rewrites AddrEx.
pub struct AclEngine {
    pub rules: CompiledRuleSet,
    pub table: HashMap<String, Arc<dyn PluggableOutbound>>,
}

impl AclEngine {
    pub fn new(rules: CompiledRuleSet, table: HashMap<String, Arc<dyn PluggableOutbound>>) -> Self {
        Self { rules, table }
    }

    fn apply_hijack(addr: &mut AddrEx, ip: IpAddr) {
        addr.host = ip.to_string();
        addr.resolve = Some(match ip {
            IpAddr::V4(v) => ResolveInfo {
                v4: Some(v),
                v6: None,
                err: None,
            },
            IpAddr::V6(v) => ResolveInfo {
                v4: None,
                v6: Some(v),
                err: None,
            },
        });
    }

    fn pick(&self, addr: &mut AddrEx, proto: Proto) -> Result<Arc<dyn PluggableOutbound>, Error> {
        let (v4, v6) = match &addr.resolve {
            Some(r) => (r.v4, r.v6),
            None => (None, None),
        };
        let hit = self.rules.match_info(&addr.host, v4, v6, proto, addr.port);
        if let Some(ip) = hit.hijack {
            Self::apply_hijack(addr, ip);
        }
        let name = hit.outbound.to_ascii_lowercase();
        if name == "reject" {
            return Err(Error::Dial("rejected".into()));
        }
        if let Some(ob) = self.table.get(&name) {
            return Ok(Arc::clone(ob));
        }
        self.table
            .get("default")
            .cloned()
            .ok_or_else(|| Error::Dial(format!("unknown outbound {name}")))
    }
}

#[async_trait]
impl PluggableOutbound for AclEngine {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        self.pick(addr, Proto::Tcp)?.tcp(addr).await
    }
    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        self.pick(addr, Proto::Udp)?.udp(addr).await
    }
    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
        self.pick(addr, Proto::Udp)?.check_udp(addr).await
    }
}

pub struct Reject;

#[async_trait]
impl PluggableOutbound for Reject {
    async fn tcp(&self, _: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        Err(Error::Dial("rejected".into()))
    }
    async fn udp(&self, _: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        Err(Error::Dial("rejected".into()))
    }
    async fn check_udp(&self, _: &mut AddrEx) -> Result<(), Error> {
        Err(Error::Dial("rejected".into()))
    }
}

/// System DNS then next. Fills first A and AAAA.
pub struct SystemResolver {
    pub next: Arc<dyn PluggableOutbound>,
}

#[async_trait]
impl PluggableOutbound for SystemResolver {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        fill_resolve(addr).await;
        self.next.tcp(addr).await
    }
    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        fill_resolve(addr).await;
        self.next.udp(addr).await
    }
    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
        fill_resolve(addr).await;
        self.next.check_udp(addr).await
    }
}

async fn fill_resolve(addr: &mut AddrEx) {
    if addr.resolve.is_some() {
        return;
    }
    let hostport = format!("{}:{}", addr.host, addr.port);
    let Ok(iter) = tokio::net::lookup_host(hostport).await else {
        return;
    };
    let mut info = ResolveInfo::default();
    for sa in iter {
        match sa.ip() {
            IpAddr::V4(v) if info.v4.is_none() => info.v4 = Some(v),
            IpAddr::V6(v) if info.v6.is_none() => info.v6 = Some(v),
            _ => {}
        }
    }
    addr.resolve = Some(info);
}

async fn candidates(addr: &AddrEx, mode: DirectMode) -> Result<Vec<SocketAddr>, Error> {
    let mut v4 = addr.resolve.as_ref().and_then(|r| r.v4);
    let mut v6 = addr.resolve.as_ref().and_then(|r| r.v6);
    if v4.is_none() && v6.is_none() {
        let hostport = format!("{}:{}", addr.host, addr.port);
        if let Ok(iter) = tokio::net::lookup_host(hostport).await {
            for sa in iter {
                match sa.ip() {
                    IpAddr::V4(v) if v4.is_none() => v4 = Some(v),
                    IpAddr::V6(v) if v6.is_none() => v6 = Some(v),
                    _ => {}
                }
            }
        }
    }
    let port = addr.port;
    let v4s = v4.map(|ip| SocketAddr::from((ip, port)));
    let v6s = v6.map(|ip| SocketAddr::from((ip, port)));
    match mode {
        DirectMode::Auto => match (v4s, v6s) {
            (Some(a), Some(b)) => Ok(vec![a, b]),
            (Some(a), None) => Ok(vec![a]),
            (None, Some(b)) => Ok(vec![b]),
            _ => Err(Error::Dial("no address".into())),
        },
        DirectMode::Prefer64 => match (v6s, v4s) {
            (Some(v6), _) => Ok(vec![v6]),
            (None, Some(v4)) => Ok(vec![v4]),
            (None, None) => Err(Error::Dial("no address".into())),
        },
        DirectMode::Prefer46 => match (v4s, v6s) {
            (Some(v4), _) => Ok(vec![v4]),
            (None, Some(v6)) => Ok(vec![v6]),
            (None, None) => Err(Error::Dial("no address".into())),
        },
        DirectMode::V4 => v4s.ok_or_else(|| Error::Dial("no IPv4 address".into())).map(|a| vec![a]),
        DirectMode::V6 => v6s.ok_or_else(|| Error::Dial("no IPv6 address".into())).map(|a| vec![a]),
    }
}

pub(crate) struct TokioTcp(pub(crate) TcpStream);
#[async_trait]
impl HyTcpStream for TokioTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0.read(buf).await.map_err(Error::Io)
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf).await.map_err(Error::Io)
    }
    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.0.shutdown().await;
        Ok(())
    }
}

struct TokioUdp(UdpSocket);
#[async_trait]
impl HyUdpSocket for TokioUdp {
    async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, String), Error> {
        let (n, addr) = self.0.recv_from(buf).await.map_err(Error::Io)?;
        Ok((n, addr.to_string()))
    }
    async fn write_to(&mut self, buf: &[u8], addr: &str) -> Result<usize, Error> {
        let dest = if let Ok(sa) = addr.parse::<SocketAddr>() {
            sa
        } else {
            tokio::net::lookup_host(addr)
                .await
                .map_err(|e| Error::Dial(e.to_string()))?
                .next()
                .ok_or_else(|| Error::Dial(format!("cannot resolve {addr}")))?
        };
        self.0.send_to(buf, dest).await.map_err(Error::Io)
    }
    async fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_v4() {
        let a = split_host_port("1.2.3.4:80").unwrap();
        assert_eq!(a.host, "1.2.3.4");
        assert_eq!(a.port, 80);
        assert!(a.resolve.unwrap().v4.is_some());
    }

    #[test]
    fn split_name() {
        let a = split_host_port("example.com:443").unwrap();
        assert_eq!(a.host, "example.com");
        assert_eq!(a.port, 443);
    }

    #[test]
    fn split_speedtest_dest() {
        let a = split_host_port("@SpeedTest:0").unwrap();
        assert_eq!(a.host, "@SpeedTest");
        assert_eq!(a.port, 0);
        let b = split_host_port("@speedtest:0").unwrap();
        assert_eq!(b.host, "@speedtest");
        assert_eq!(b.port, 0);
    }

    #[tokio::test]
    async fn reject_dial() {
        let a = Adapter(Arc::new(Reject));
        let e = match a.tcp("1.2.3.4:80").await {
            Err(e) => e,
            Ok(_) => panic!("expected reject"),
        };
        match e {
            Error::Dial(s) => assert_eq!(s, "rejected"),
            other => panic!("{other:?}"),
        }
    }

    struct Rec(std::sync::Mutex<Option<AddrEx>>);
    #[async_trait]
    impl PluggableOutbound for Rec {
        async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
            *self.0.lock().unwrap() = Some(addr.clone());
            Err(Error::Dial("rec".into()))
        }
        async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
            *self.0.lock().unwrap() = Some(addr.clone());
            Err(Error::Dial("rec".into()))
        }
        async fn check_udp(&self, _: &mut AddrEx) -> Result<(), Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn acl_engine_reject_and_default() {
        let rec = Arc::new(Rec(std::sync::Mutex::new(None)));
        let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
        table.insert("default".into(), rec.clone());
        let rules = CompiledRuleSet::compile("reject(10.0.0.0/8)\ndirect(*)\n").unwrap();
        // no "direct" in table → falls through? 10.x is reject; others match direct name missing → default
        let eng = AclEngine::new(rules, table);
        let mut bad = split_host_port("10.1.2.3:53").unwrap();
        let e = match eng.udp(&mut bad).await {
            Err(e) => e,
            Ok(_) => panic!("expected reject"),
        };
        match e {
            Error::Dial(s) => assert_eq!(s, "rejected"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn acl_engine_hijack_rewrites_addrex() {
        let rec = Arc::new(Rec(std::sync::Mutex::new(None)));
        let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
        table.insert("hijack_ob".into(), rec.clone());
        table.insert("default".into(), Arc::new(Reject));
        let rules = CompiledRuleSet::compile("hijack_ob(1.2.3.4, *, 9.9.9.9)\n").unwrap();
        let eng = AclEngine::new(rules, table);
        let mut a = split_host_port("1.2.3.4:80").unwrap();
        let _ = eng.tcp(&mut a).await;
        assert_eq!(a.host, "9.9.9.9");
        assert_eq!(a.resolve.as_ref().unwrap().v4.unwrap(), "9.9.9.9".parse::<Ipv4Addr>().unwrap());
        let seen = rec.0.lock().unwrap().clone().unwrap();
        assert_eq!(seen.host, "9.9.9.9");
    }

    #[tokio::test]
    async fn acl_engine_picks_named() {
        let rec = Arc::new(Rec(std::sync::Mutex::new(None)));
        let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
        table.insert("proxy".into(), rec.clone());
        table.insert("default".into(), Arc::new(Reject));
        let rules = CompiledRuleSet::compile("proxy(suffix:example.com)\n").unwrap();
        let eng = AclEngine::new(rules, table);
        let mut a = split_host_port("foo.example.com:443").unwrap();
        let _ = eng.tcp(&mut a).await;
        assert_eq!(rec.0.lock().unwrap().as_ref().unwrap().host, "foo.example.com");
    }

    fn dual_stack_addr() -> AddrEx {
        AddrEx {
            host: "example.com".into(),
            port: 443,
            resolve: Some(ResolveInfo {
                v4: Some(Ipv4Addr::new(1, 2, 3, 4)),
                v6: Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                err: None,
            }),
        }
    }

    #[tokio::test]
    async fn prefer64_with_both_returns_only_v6() {
        let addr = dual_stack_addr();
        let dests = candidates(&addr, DirectMode::Prefer64).await.unwrap();
        assert_eq!(dests.len(), 1);
        assert_eq!(
            dests[0],
            SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443))
        );
    }

    #[tokio::test]
    async fn prefer46_with_both_returns_only_v4() {
        let addr = dual_stack_addr();
        let dests = candidates(&addr, DirectMode::Prefer46).await.unwrap();
        assert_eq!(dests.len(), 1);
        assert_eq!(
            dests[0],
            SocketAddr::from((Ipv4Addr::new(1, 2, 3, 4), 443))
        );
    }
}
