//! SOCKS5 CONNECT / UDP ASSOCIATE outbound (RFC 1928 / 1929).
//! Always uses AddrEx.host — ignores resolve (same as official Go).

use super::{AddrEx, PluggableOutbound, TokioTcp};
use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, HyUdpSocket};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks5Outbound {
    pub addr: String,
    pub username: String,
    pub password: String,
}

impl Socks5Outbound {
    pub fn new(addr: String, username: String, password: String) -> Self {
        Self {
            addr,
            username,
            password,
        }
    }
}

#[async_trait]
impl PluggableOutbound for Socks5Outbound {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        let mut conn = self.dial_and_negotiate().await?;
        let req = encode_request(0x01, addr);
        self.request(&mut conn, &req).await?;
        Ok(Box::new(TokioTcp(conn)))
    }

    async fn udp(&self, _addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        let mut conn = self.dial_and_negotiate().await?;
        // CMD UDP ASSOCIATE with ATYP IPv4 0.0.0.0:0
        let req = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let reply_addr = self.request(&mut conn, &req).await?;
        let relay = fix_relay_addr(&reply_addr, &self.addr)?;
        let udp = UdpSocket::bind(unspecified_bind(&relay))
            .await
            .map_err(|e| Error::Dial(e.to_string()))?;
        udp.connect(relay)
            .await
            .map_err(|e| Error::Dial(e.to_string()))?;
        let hold = tokio::spawn(async move {
            let mut tcp = conn;
            let mut buf = [0u8; 256];
            loop {
                match tcp.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            let _ = tcp.shutdown().await;
        });
        Ok(Box::new(Socks5Udp {
            udp,
            _hold: hold,
        }))
    }

    async fn check_udp(&self, _addr: &mut AddrEx) -> Result<(), Error> {
        Ok(())
    }
}

impl Socks5Outbound {
    async fn dial_and_negotiate(&self) -> Result<TcpStream, Error> {
        let conn = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&self.addr)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(Error::Dial(e.to_string())),
            Err(_) => return Err(Error::Dial("socks5 dial timeout".into())),
        };
        let fut = async {
            let mut conn = conn;
            let offer_userpass = !self.username.is_empty() && !self.password.is_empty();
            if offer_userpass {
                conn.write_all(&[0x05, 0x02, 0x00, 0x02]).await.map_err(Error::Io)?;
            } else {
                conn.write_all(&[0x05, 0x01, 0x00]).await.map_err(Error::Io)?;
            }
            let mut resp = [0u8; 2];
            conn.read_exact(&mut resp).await.map_err(Error::Io)?;
            if resp[0] != 0x05 {
                return Err(Error::Dial("invalid SOCKS5 version".into()));
            }
            match resp[1] {
                0x00 => {}
                0x02 => {
                    if !offer_userpass {
                        return Err(Error::Dial(
                            "unsupported SOCKS5 authentication method: 2".into(),
                        ));
                    }
                    // RFC 1929
                    let u = self.username.as_bytes();
                    let p = self.password.as_bytes();
                    if u.len() > 255 || p.len() > 255 {
                        return Err(Error::Dial("SOCKS5 username/password too long".into()));
                    }
                    let mut auth = Vec::with_capacity(3 + u.len() + p.len());
                    auth.push(0x01);
                    auth.push(u.len() as u8);
                    auth.extend_from_slice(u);
                    auth.push(p.len() as u8);
                    auth.extend_from_slice(p);
                    conn.write_all(&auth).await.map_err(Error::Io)?;
                    let mut st = [0u8; 2];
                    conn.read_exact(&mut st).await.map_err(Error::Io)?;
                    if st[1] != 0x00 {
                        return Err(Error::Dial("SOCKS5 authentication failed".into()));
                    }
                }
                0xff => return Err(Error::Dial("SOCKS5 no acceptable authentication method".into())),
                m => {
                    return Err(Error::Dial(format!(
                        "unsupported SOCKS5 authentication method: {m}"
                    )));
                }
            }
            Ok(conn)
        };
        match tokio::time::timeout(NEGOTIATION_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(Error::Dial("socks5 negotiation timeout".into())),
        }
    }

    /// Send request; on success return BND address as `host:port` (for UDP ASSOCIATE).
    async fn request(&self, conn: &mut TcpStream, req: &[u8]) -> Result<String, Error> {
        let fut = async {
            conn.write_all(req).await.map_err(Error::Io)?;
            let mut hdr = [0u8; 4];
            conn.read_exact(&mut hdr).await.map_err(Error::Io)?;
            if hdr[0] != 0x05 {
                return Err(Error::Dial("invalid SOCKS5 reply version".into()));
            }
            if hdr[1] != 0x00 {
                return Err(Error::Dial(socks5_rep_error(hdr[1])));
            }
            let (host, port) = read_socks_addr(conn, hdr[3]).await?;
            Ok(join_host_port(&host, port))
        };
        match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(Error::Dial("socks5 request timeout".into())),
        }
    }
}

fn socks5_rep_error(rep: u8) -> String {
    let msg = match rep {
        0x00 => "succeeded",
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _ => "undefined",
    };
    format!("SOCKS5 request failed: {msg} ({rep})")
}

fn encode_request(cmd: u8, addr: &AddrEx) -> Vec<u8> {
    let mut out = vec![0x05, cmd, 0x00];
    encode_socks_addr(&mut out, &addr.host, addr.port);
    out
}

fn encode_socks_addr(out: &mut Vec<u8>, host: &str, port: u16) {
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v) => {
                out.push(0x01);
                out.extend_from_slice(&v.octets());
            }
            IpAddr::V6(v) => {
                out.push(0x04);
                out.extend_from_slice(&v.octets());
            }
        }
    } else {
        let b = host.as_bytes();
        let len = b.len().min(255);
        out.push(0x03);
        out.push(len as u8);
        out.extend_from_slice(&b[..len]);
    }
    out.extend_from_slice(&port.to_be_bytes());
}

async fn read_socks_addr(conn: &mut TcpStream, atyp: u8) -> Result<(String, u16), Error> {
    let host = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).await.map_err(Error::Io)?;
            Ipv4Addr::from(b).to_string()
        }
        0x04 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).await.map_err(Error::Io)?;
            Ipv6Addr::from(b).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            conn.read_exact(&mut len).await.map_err(Error::Io)?;
            let mut b = vec![0u8; len[0] as usize];
            conn.read_exact(&mut b).await.map_err(Error::Io)?;
            String::from_utf8(b).map_err(|_| Error::Dial("bad SOCKS5 domain".into()))?
        }
        _ => return Err(Error::Dial(format!("unsupported SOCKS5 atyp {atyp}"))),
    };
    let mut pb = [0u8; 2];
    conn.read_exact(&mut pb).await.map_err(Error::Io)?;
    Ok((host, u16::from_be_bytes(pb)))
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn proxy_host(proxy_addr: &str) -> &str {
    if let Some(rest) = proxy_addr.strip_prefix('[') {
        return rest.split_once(']').map(|(h, _)| h).unwrap_or(proxy_addr);
    }
    proxy_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(proxy_addr)
}

fn fix_relay_addr(reply: &str, proxy_addr: &str) -> Result<SocketAddr, Error> {
    let sa: SocketAddr = reply
        .parse()
        .map_err(|_| Error::Dial(format!("bad SOCKS5 relay addr {reply}")))?;
    if sa.ip().is_unspecified() {
        let host = proxy_host(proxy_addr);
        let fixed = join_host_port(host, sa.port());
        fixed
            .parse::<SocketAddr>()
            .map_err(|_| Error::Dial(format!("cannot form relay addr from {fixed}")))
    } else {
        Ok(sa)
    }
}

fn unspecified_bind(relay: &SocketAddr) -> SocketAddr {
    match relay {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

struct Socks5Udp {
    udp: UdpSocket,
    _hold: tokio::task::JoinHandle<()>,
}

#[async_trait]
impl HyUdpSocket for Socks5Udp {
    async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, String), Error> {
        let mut pkt = vec![0u8; 65535];
        let n = self.udp.recv(&mut pkt).await.map_err(Error::Io)?;
        let (payload, addr) = decode_udp_datagram(&pkt[..n])?;
        let len = payload.len().min(buf.len());
        buf[..len].copy_from_slice(&payload[..len]);
        Ok((len, addr))
    }

    async fn write_to(&mut self, buf: &[u8], addr: &str) -> Result<usize, Error> {
        let a = super::split_host_port(addr)?;
        let mut pkt = vec![0u8, 0u8, 0u8]; // RSV=0 FRAG=0
        // Prefer hostname ATYP 3 (even for IPs that look like hostnames we still
        // encode by parse: IPs get ATYP 1/4; names get ATYP 3).
        encode_socks_addr(&mut pkt, &a.host, a.port);
        pkt.extend_from_slice(buf);
        self.udp.send(&pkt).await.map_err(Error::Io)?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> Result<(), Error> {
        self._hold.abort();
        Ok(())
    }
}

fn decode_udp_datagram(pkt: &[u8]) -> Result<(Vec<u8>, String), Error> {
    if pkt.len() < 4 {
        return Err(Error::Dial("short SOCKS5 UDP datagram".into()));
    }
    // RSV(2) FRAG(1) ATYP(1) ...
    if pkt[2] != 0 {
        return Err(Error::Dial("SOCKS5 UDP fragmentation not supported".into()));
    }
    let atyp = pkt[3];
    let (host, port, data_off) = match atyp {
        0x01 => {
            if pkt.len() < 10 {
                return Err(Error::Dial("short SOCKS5 UDP v4".into()));
            }
            let ip = Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
            let port = u16::from_be_bytes([pkt[8], pkt[9]]);
            (ip.to_string(), port, 10)
        }
        0x04 => {
            if pkt.len() < 22 {
                return Err(Error::Dial("short SOCKS5 UDP v6".into()));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[4..20]);
            let port = u16::from_be_bytes([pkt[20], pkt[21]]);
            (Ipv6Addr::from(o).to_string(), port, 22)
        }
        0x03 => {
            if pkt.len() < 5 {
                return Err(Error::Dial("short SOCKS5 UDP domain".into()));
            }
            let len = pkt[4] as usize;
            if pkt.len() < 5 + len + 2 {
                return Err(Error::Dial("short SOCKS5 UDP domain body".into()));
            }
            let host = String::from_utf8_lossy(&pkt[5..5 + len]).into_owned();
            let port = u16::from_be_bytes([pkt[5 + len], pkt[5 + len + 1]]);
            (host, port, 5 + len + 2)
        }
        _ => return Err(Error::Dial(format!("bad SOCKS5 UDP atyp {atyp}"))),
    };
    Ok((pkt[data_off..].to_vec(), join_host_port(&host, port)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_connect_uses_domain_atyp3() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let rec = Arc::clone(&recorded);
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            assert_eq!(g[0], 5);
            let n = g[1] as usize;
            let mut methods = vec![0u8; n];
            s.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0x00));
            s.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(hdr, [0x05, 0x01, 0x00, 0x03]);
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; len[0] as usize];
            s.read_exact(&mut host).await.unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            let mut full = Vec::new();
            full.extend_from_slice(&hdr);
            full.push(len[0]);
            full.extend_from_slice(&host);
            full.extend_from_slice(&port);
            *rec.lock().unwrap() = full;
            // success reply: VER REP RSV ATYP IPv4 0.0.0.0:0
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            // keep conn open briefly
            let mut sink = [0u8; 1];
            let _ = s.read(&mut sink).await;
        });

        let ob = Socks5Outbound::new(addr.to_string(), String::new(), String::new());
        let mut dest = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: Some(super::super::ResolveInfo {
                v4: Some(Ipv4Addr::new(1, 2, 3, 4)),
                v6: None,
                err: None,
            }),
        };
        let _stream = ob.tcp(&mut dest).await.expect("tcp");
        let bytes = recorded.lock().unwrap().clone();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(bytes[1], 0x01); // CONNECT
        assert_eq!(bytes[3], 0x03); // ATYP domain
        assert_eq!(bytes[4] as usize, b"example.test".len());
        assert_eq!(&bytes[5..5 + 12], b"example.test");
        assert_eq!(&bytes[5 + 12..], &443u16.to_be_bytes());
        // must NOT be a resolved IPv4 ATYP
        assert_ne!(bytes[3], 0x01);
    }

    #[tokio::test]
    async fn greeting_offers_userpass_when_creds_set() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let m = Arc::clone(&methods);
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let n = g[1] as usize;
            let mut meth = vec![0u8; n];
            s.read_exact(&mut meth).await.unwrap();
            *m.lock().unwrap() = meth;
            // demand user/pass then reject
            s.write_all(&[0x05, 0x02]).await.unwrap();
            let mut h = [0u8; 2];
            s.read_exact(&mut h).await.unwrap();
            let ulen = h[1] as usize;
            let mut u = vec![0u8; ulen];
            s.read_exact(&mut u).await.unwrap();
            let mut plen = [0u8; 1];
            s.read_exact(&mut plen).await.unwrap();
            let mut p = vec![0u8; plen[0] as usize];
            s.read_exact(&mut p).await.unwrap();
            s.write_all(&[0x01, 0x01]).await.unwrap(); // fail
        });

        let ob = Socks5Outbound::new(addr.to_string(), "user".into(), "pass".into());
        let mut dest = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        let err = match ob.tcp(&mut dest).await {
            Err(e) => e,
            Ok(_) => panic!("expected auth failure"),
        };
        match err {
            Error::Dial(s) => assert_eq!(s, "SOCKS5 authentication failed"),
            other => panic!("{other:?}"),
        }
        let meth = methods.lock().unwrap().clone();
        assert!(meth.contains(&0x00));
        assert!(meth.contains(&0x02));
    }

    #[tokio::test]
    async fn reject_userpass_when_no_creds() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut g = [0u8; 2];
            s.read_exact(&mut g).await.unwrap();
            let n = g[1] as usize;
            let mut meth = vec![0u8; n];
            s.read_exact(&mut meth).await.unwrap();
            s.write_all(&[0x05, 0x02]).await.unwrap(); // demand user/pass
        });
        let ob = Socks5Outbound::new(addr.to_string(), String::new(), String::new());
        let mut dest = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        let err = match ob.tcp(&mut dest).await {
            Err(e) => e,
            Ok(_) => panic!("expected method rejection"),
        };
        match err {
            Error::Dial(s) => assert!(s.contains("unsupported SOCKS5 authentication method")),
            other => panic!("{other:?}"),
        }
    }
}
