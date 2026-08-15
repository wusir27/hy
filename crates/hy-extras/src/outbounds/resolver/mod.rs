//! TCP / UDP / DoT / DoH resolvers. Pipeline: Speedtest → Resolver → ACL → Outbound.

use super::{AddrEx, PluggableOutbound, ResolveInfo};
use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, HyUdpSocket};
use rand::Rng;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream as StdTcp, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_TIMES: usize = 2;

#[derive(Clone)]
pub enum DnsTransport {
    Udp,
    Tcp,
    Tls { sni: String, insecure: bool },
}

/// Standard DNS over UDP, TCP, or TLS (DoT).
pub struct StandardResolver {
    pub addr: String,
    pub timeout: Duration,
    pub transport: DnsTransport,
    pub next: Arc<dyn PluggableOutbound>,
}

impl StandardResolver {
    pub fn udp(addr: String, timeout: Duration, next: Arc<dyn PluggableOutbound>) -> Self {
        Self {
            addr: add_default_port(&addr, 53),
            timeout: timeout_or_default(timeout),
            transport: DnsTransport::Udp,
            next,
        }
    }

    pub fn tcp(addr: String, timeout: Duration, next: Arc<dyn PluggableOutbound>) -> Self {
        Self {
            addr: add_default_port(&addr, 53),
            timeout: timeout_or_default(timeout),
            transport: DnsTransport::Tcp,
            next,
        }
    }

    pub fn tls(
        addr: String,
        timeout: Duration,
        sni: String,
        insecure: bool,
        next: Arc<dyn PluggableOutbound>,
    ) -> Self {
        Self {
            addr: add_default_port(&addr, 853),
            timeout: timeout_or_default(timeout),
            transport: DnsTransport::Tls { sni, insecure },
            next,
        }
    }

    async fn resolve(&self, addr: &mut AddrEx) {
        if skip_or_fill_ip(addr) {
            return;
        }
        let host = addr.host.clone();
        let (r4, r6) = tokio::join!(self.lookup_a(&host), self.lookup_aaaa(&host));
        let mut info = ResolveInfo::default();
        match r4 {
            Ok(ip) => info.v4 = ip,
            Err(e) => info.err = Some(e),
        }
        match r6 {
            Ok(ip) => info.v6 = ip,
            Err(e) => {
                if info.err.is_none() {
                    info.err = Some(e);
                }
            }
        }
        addr.resolve = Some(info);
    }

    async fn lookup_a(&self, host: &str) -> Result<Option<Ipv4Addr>, String> {
        let mut last = String::new();
        for _ in 0..RETRY_TIMES {
            match self.exchange(host, TYPE_A).await {
                Ok(msg) => return Ok(parse_a(&msg)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn lookup_aaaa(&self, host: &str) -> Result<Option<Ipv6Addr>, String> {
        let mut last = String::new();
        for _ in 0..RETRY_TIMES {
            match self.exchange(host, TYPE_AAAA).await {
                Ok(msg) => return Ok(parse_aaaa(&msg)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn exchange(&self, host: &str, qtype: u16) -> Result<Vec<u8>, String> {
        let id = rand::thread_rng().gen::<u16>();
        let query = encode_query(id, host, qtype);
        let timeout = self.timeout;
        let addr = self.addr.clone();
        match &self.transport {
            DnsTransport::Udp => {
                tokio::time::timeout(timeout, exchange_udp(&addr, &query))
                    .await
                    .map_err(|_| "dns udp timeout".to_string())?
            }
            DnsTransport::Tcp => {
                tokio::time::timeout(timeout, exchange_tcp(&addr, &query))
                    .await
                    .map_err(|_| "dns tcp timeout".to_string())?
            }
            DnsTransport::Tls { sni, insecure } => {
                let sni = sni.clone();
                let insecure = *insecure;
                let query = query.clone();
                tokio::task::spawn_blocking(move || {
                    exchange_tls(&addr, &query, &sni, insecure, timeout)
                })
                .await
                .map_err(|e| e.to_string())?
            }
        }
    }
}

#[async_trait]
impl PluggableOutbound for StandardResolver {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        self.resolve(addr).await;
        self.next.tcp(addr).await
    }
    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        self.resolve(addr).await;
        self.next.udp(addr).await
    }
    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
        self.resolve(addr).await;
        self.next.check_udp(addr).await
    }
}

/// DNS-over-HTTPS (RFC 8484 POST application/dns-message).
pub struct DohResolver {
    pub url: String,
    pub timeout: Duration,
    pub sni: String,
    pub insecure: bool,
    pub next: Arc<dyn PluggableOutbound>,
}

impl DohResolver {
    pub fn new(
        addr: String,
        timeout: Duration,
        sni: String,
        insecure: bool,
        next: Arc<dyn PluggableOutbound>,
    ) -> Self {
        let url = if addr.starts_with("https://") || addr.starts_with("http://") {
            addr
        } else {
            format!("https://{addr}/dns-query")
        };
        Self {
            url,
            timeout: timeout_or_default(timeout),
            sni,
            insecure,
            next,
        }
    }

    async fn resolve(&self, addr: &mut AddrEx) {
        if skip_or_fill_ip(addr) {
            return;
        }
        let host = addr.host.clone();
        let (r4, r6) = tokio::join!(self.lookup_a(&host), self.lookup_aaaa(&host));
        let mut info = ResolveInfo::default();
        match r4 {
            Ok(ip) => info.v4 = ip,
            Err(e) => info.err = Some(e),
        }
        match r6 {
            Ok(ip) => info.v6 = ip,
            Err(e) => {
                if info.err.is_none() {
                    info.err = Some(e);
                }
            }
        }
        addr.resolve = Some(info);
    }

    async fn lookup_a(&self, host: &str) -> Result<Option<Ipv4Addr>, String> {
        let msg = self.exchange(host, TYPE_A).await?;
        Ok(parse_a(&msg))
    }

    async fn lookup_aaaa(&self, host: &str) -> Result<Option<Ipv6Addr>, String> {
        let msg = self.exchange(host, TYPE_AAAA).await?;
        Ok(parse_aaaa(&msg))
    }

    async fn exchange(&self, host: &str, qtype: u16) -> Result<Vec<u8>, String> {
        let id = rand::thread_rng().gen::<u16>();
        let query = encode_query(id, host, qtype);
        let url = self.url.clone();
        let sni = self.sni.clone();
        let insecure = self.insecure;
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || exchange_doh(&url, &query, &sni, insecure, timeout))
            .await
            .map_err(|e| e.to_string())?
    }
}

#[async_trait]
impl PluggableOutbound for DohResolver {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        self.resolve(addr).await;
        self.next.tcp(addr).await
    }
    async fn udp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        self.resolve(addr).await;
        self.next.udp(addr).await
    }
    async fn check_udp(&self, addr: &mut AddrEx) -> Result<(), Error> {
        self.resolve(addr).await;
        self.next.check_udp(addr).await
    }
}

fn timeout_or_default(t: Duration) -> Duration {
    if t.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        t
    }
}

fn add_default_port(addr: &str, port: u16) -> String {
    if addr.parse::<SocketAddr>().is_ok() {
        return addr.to_string();
    }
    // host:port or bare host / [v6]
    if addr.starts_with('[') {
        if addr.contains("]:") {
            return addr.to_string();
        }
        return format!("{addr}:{port}");
    }
    match addr.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() && !h.contains(':') => {
            addr.to_string()
        }
        _ => format!("{addr}:{port}"),
    }
}

/// Skip if already resolved; if host is an IP, fill ResolveInfo and skip query.
fn skip_or_fill_ip(addr: &mut AddrEx) -> bool {
    if addr.resolve.is_some() {
        return true;
    }
    if let Ok(ip) = addr.host.parse::<IpAddr>() {
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
        return true;
    }
    false
}

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&mut buf, name);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        let b = label.as_bytes();
        buf.push(b.len() as u8);
        buf.extend_from_slice(b);
    }
    buf.push(0);
}

fn parse_a(msg: &[u8]) -> Option<Ipv4Addr> {
    for (ty, rdata) in iter_answers(msg) {
        if ty == TYPE_A && rdata.len() == 4 {
            return Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
    }
    None
}

fn parse_aaaa(msg: &[u8]) -> Option<Ipv6Addr> {
    for (ty, rdata) in iter_answers(msg) {
        if ty == TYPE_AAAA && rdata.len() == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata);
            return Some(Ipv6Addr::from(a));
        }
    }
    None
}

fn iter_answers(msg: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        i = skip_name(msg, i);
        i = i.saturating_add(4);
        if i > msg.len() {
            return out;
        }
    }
    for _ in 0..an {
        i = skip_name(msg, i);
        if i + 10 > msg.len() {
            break;
        }
        let ty = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if i + rdlen > msg.len() {
            break;
        }
        out.push((ty, &msg[i..i + rdlen]));
        i += rdlen;
    }
    out
}

fn skip_name(msg: &[u8], mut i: usize) -> usize {
    while i < msg.len() {
        let len = msg[i] as usize;
        if len == 0 {
            return i + 1;
        }
        if len & 0xc0 == 0xc0 {
            return i + 2;
        }
        i += 1 + len;
    }
    msg.len()
}

async fn exchange_udp(server: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    sock.send_to(query, server)
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
    Ok(buf[..n].to_vec())
}

async fn exchange_tcp(server: &str, query: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|e| e.to_string())?;
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await.map_err(|e| e.to_string())?;
    stream.write_all(query).await.map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; n];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| e.to_string())?;
    Ok(resp)
}

fn ensure_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_tls_config(insecure: bool) -> Result<ClientConfig, String> {
    ensure_crypto();
    if insecure {
        #[derive(Debug)]
        struct Skip;
        impl rustls::client::danger::ServerCertVerifier for Skip {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }
        let mut cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Skip))
            .with_no_client_auth();
        cfg.enable_sni = true;
        return Ok(cfg);
    }
    let mut roots = RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn resolve_server_addrs(addr: &str) -> Result<SocketAddr, String> {
    addr.to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {addr}"))
}

fn exchange_tls(
    server: &str,
    query: &[u8],
    sni: &str,
    insecure: bool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let sa = resolve_server_addrs(server)?;
    let tcp = StdTcp::connect_timeout(&sa, timeout).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    let cfg = Arc::new(build_tls_config(insecure)?);
    let host = if sni.is_empty() {
        server
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(server)
            .trim_matches(|c| c == '[' || c == ']')
            .to_string()
    } else {
        sni.to_string()
    };
    let name = ServerName::try_from(host).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    let len = (query.len() as u16).to_be_bytes();
    tls.write_all(&len).map_err(|e| e.to_string())?;
    tls.write_all(query).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; n];
    tls.read_exact(&mut resp).map_err(|e| e.to_string())?;
    Ok(resp)
}

fn exchange_doh(
    url: &str,
    query: &[u8],
    sni: &str,
    insecure: bool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let https = url
        .strip_prefix("https://")
        .ok_or("DoH requires https:// URL")?;
    let (hostport, path) = match https.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (https, "/dns-query".into()),
    };
    let connect_hp = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:443")
    };
    let sa = resolve_server_addrs(&connect_hp)?;
    let tcp = StdTcp::connect_timeout(&sa, timeout).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(timeout)).ok();
    let cfg = Arc::new(build_tls_config(insecure)?);
    let host_only = hostport
        .rsplit_once(':')
        .filter(|(h, p)| p.parse::<u16>().is_ok() && !h.contains(':'))
        .map(|(h, _)| h)
        .unwrap_or(hostport);
    let server_name = if sni.is_empty() { host_only } else { sni };
    let name = ServerName::try_from(server_name.to_string()).map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_only}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    );
    tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    tls.write_all(query).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("DoH: bad HTTP response")?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|e| e.to_string())?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or("DoH: no status")?;
    if status != "200" {
        return Err(format!("DoH: status {status}"));
    }
    Ok(raw[sep + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct Rec(Mutex<Option<AddrEx>>);

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

    fn build_response(query: &[u8], v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Vec<u8> {
        if query.len() < 12 {
            return Vec::new();
        }
        let qtype = {
            // find end of QNAME then read type
            let mut i = 12usize;
            while i < query.len() && query[i] != 0 {
                if query[i] & 0xc0 == 0xc0 {
                    i += 2;
                    break;
                }
                i += 1 + query[i] as usize;
            }
            if i < query.len() && query[i] == 0 {
                i += 1;
            }
            if i + 2 <= query.len() {
                u16::from_be_bytes([query[i], query[i + 1]])
            } else {
                0
            }
        };
        let mut resp = query.to_vec();
        resp[2] = 0x81; // QR RD
        resp[3] = 0x80; // RA
        let answers: Vec<(u16, Vec<u8>)> = match qtype {
            TYPE_A => v4
                .map(|ip| (TYPE_A, ip.octets().to_vec()))
                .into_iter()
                .collect(),
            TYPE_AAAA => v6
                .map(|ip| (TYPE_AAAA, ip.octets().to_vec()))
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        let an = answers.len() as u16;
        resp[6] = (an >> 8) as u8;
        resp[7] = (an & 0xff) as u8;
        for (ty, rdata) in answers {
            resp.push(0xc0);
            resp.push(0x0c); // pointer to QNAME
            resp.extend_from_slice(&ty.to_be_bytes());
            resp.extend_from_slice(&CLASS_IN.to_be_bytes());
            resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
            resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            resp.extend_from_slice(&rdata);
        }
        resp
    }

    async fn spawn_udp_dns(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    break;
                };
                let resp = build_response(&buf[..n], v4, v6);
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    async fn spawn_tcp_dns(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    continue;
                }
                let n = u16::from_be_bytes(len_buf) as usize;
                let mut q = vec![0u8; n];
                if stream.read_exact(&mut q).await.is_err() {
                    continue;
                }
                let resp = build_response(&q, v4, v6);
                let len = (resp.len() as u16).to_be_bytes();
                let _ = stream.write_all(&len).await;
                let _ = stream.write_all(&resp).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn udp_resolver_fills_v4_and_calls_next() {
        let dns = spawn_udp_dns(Some(Ipv4Addr::new(1, 2, 3, 4)), None).await;
        let rec = Arc::new(Rec(Mutex::new(None)));
        let r = StandardResolver::udp(dns.to_string(), Duration::from_secs(2), rec.clone());
        let mut addr = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        let _ = r.tcp(&mut addr).await;
        let seen = rec.0.lock().unwrap().clone().unwrap();
        assert_eq!(seen.resolve.as_ref().unwrap().v4, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(seen.resolve.as_ref().unwrap().err.is_none());
    }

    #[tokio::test]
    async fn udp_resolver_fills_aaaa() {
        let dns = spawn_udp_dns(
            None,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        )
        .await;
        let rec = Arc::new(Rec(Mutex::new(None)));
        let r = StandardResolver::udp(dns.to_string(), Duration::from_secs(2), rec.clone());
        let mut addr = AddrEx {
            host: "example.test".into(),
            port: 80,
            resolve: None,
        };
        let _ = r.udp(&mut addr).await;
        let seen = rec.0.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.resolve.as_ref().unwrap().v6,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[tokio::test]
    async fn tcp_resolver_fills_v4() {
        let dns = spawn_tcp_dns(Some(Ipv4Addr::new(9, 8, 7, 6)), None).await;
        let rec = Arc::new(Rec(Mutex::new(None)));
        let r = StandardResolver::tcp(dns.to_string(), Duration::from_secs(2), rec.clone());
        let mut addr = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        let _ = r.tcp(&mut addr).await;
        assert_eq!(
            rec.0.lock().unwrap().as_ref().unwrap().resolve.as_ref().unwrap().v4,
            Some(Ipv4Addr::new(9, 8, 7, 6))
        );
    }

    #[tokio::test]
    async fn resolve_failure_sets_err_and_calls_next() {
        let rec = Arc::new(Rec(Mutex::new(None)));
        // closed / wrong port
        let r = StandardResolver::udp(
            "127.0.0.1:1".into(),
            Duration::from_millis(200),
            rec.clone(),
        );
        let mut addr = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        let _ = r.tcp(&mut addr).await;
        let seen = rec.0.lock().unwrap().clone().unwrap();
        let info = seen.resolve.as_ref().unwrap();
        assert!(info.err.is_some(), "expected err, got {info:?}");
        assert!(info.v4.is_none() && info.v6.is_none());
    }

    #[tokio::test]
    async fn skips_when_already_resolved() {
        let rec = Arc::new(Rec(Mutex::new(None)));
        let r = StandardResolver::udp(
            "127.0.0.1:1".into(),
            Duration::from_millis(50),
            rec.clone(),
        );
        let mut addr = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: Some(ResolveInfo {
                v4: Some(Ipv4Addr::new(1, 1, 1, 1)),
                v6: None,
                err: None,
            }),
        };
        let _ = r.tcp(&mut addr).await;
        let seen = rec.0.lock().unwrap().clone().unwrap();
        assert_eq!(seen.resolve.as_ref().unwrap().v4, Some(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(seen.resolve.as_ref().unwrap().err.is_none());
    }

    #[test]
    fn add_default_port_udp() {
        assert_eq!(add_default_port("8.8.8.8", 53), "8.8.8.8:53");
        assert_eq!(add_default_port("8.8.8.8:5353", 53), "8.8.8.8:5353");
    }
}
