//! TUN DNS hijack: parse/cache, stub, plain UDP/TCP, and DoH over DirectDialer.
//!
//! DoH TCP is marked/bound via [`crate::DirectDialer`] so it cannot loop into TUN.
//! This crate must not use ureq, hy-core, quinn, or h3.

use crate::dest::{Dest, Proto};
use crate::direct::DirectDialer;
use crate::error::Error;
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Minimum cached TTL (seconds).
pub const TTL_MIN_SECS: u32 = 30;
/// Maximum cached TTL (seconds).
pub const TTL_MAX_SECS: u32 = 3600;

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Clamp a DNS TTL into 30s–1h.
pub fn clamp_ttl(secs: u32) -> u32 {
    secs.clamp(TTL_MIN_SECS, TTL_MAX_SECS)
}

/// Parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub id: u16,
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// A/AAAA record from an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub typ: u16,
    pub ttl: u32,
    pub ip: IpAddr,
}

/// Bidirectional A/AAAA ↔ qname cache (TTL clamped 30s–1h).
#[derive(Debug)]
pub struct DnsCache {
    inner: Mutex<CacheInner>,
}

#[derive(Debug, Default)]
struct CacheInner {
    by_name: HashMap<(String, u16), NameEnt>,
    by_ip: HashMap<IpAddr, IpEnt>,
}

#[derive(Debug, Clone)]
struct NameEnt {
    ips: Vec<IpAddr>,
    expiry: Instant,
}

#[derive(Debug, Clone)]
struct IpEnt {
    qname: String,
    expiry: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CacheInner::default()),
        }
    }

    /// Insert A/AAAA answers. `qname` is the question name (TUN reverse lookup).
    pub fn insert(&self, qname: &str, typ: u16, ips: &[IpAddr], ttl_secs: u32) {
        let qname = normalize_qname(qname);
        if qname.is_empty() || ips.is_empty() {
            return;
        }
        if typ != TYPE_A && typ != TYPE_AAAA {
            return;
        }
        let ttl = Duration::from_secs(clamp_ttl(ttl_secs) as u64);
        let expiry = Instant::now() + ttl;
        let mut g = self.inner.lock().unwrap();
        g.by_name.insert(
            (qname.clone(), typ),
            NameEnt {
                ips: ips.to_vec(),
                expiry,
            },
        );
        for ip in ips {
            g.by_ip.insert(
                *ip,
                IpEnt {
                    qname: qname.clone(),
                    expiry,
                },
            );
        }
    }

    /// Insert from a parsed response. Maps IPs back to the question qname.
    pub fn insert_from_message(&self, query_qname: &str, records: &[DnsRecord]) {
        let mut a = Vec::new();
        let mut aaaa = Vec::new();
        let mut ttl_a = TTL_MIN_SECS;
        let mut ttl_aaaa = TTL_MIN_SECS;
        for r in records {
            match r.typ {
                TYPE_A => {
                    a.push(r.ip);
                    ttl_a = r.ttl;
                }
                TYPE_AAAA => {
                    aaaa.push(r.ip);
                    ttl_aaaa = r.ttl;
                }
                _ => {}
            }
        }
        if !a.is_empty() {
            self.insert(query_qname, TYPE_A, &a, ttl_a);
        }
        if !aaaa.is_empty() {
            self.insert(query_qname, TYPE_AAAA, &aaaa, ttl_aaaa);
        }
    }

    pub fn lookup_ips(&self, qname: &str, typ: u16) -> Option<Vec<IpAddr>> {
        let qname = normalize_qname(qname);
        let now = Instant::now();
        let g = self.inner.lock().unwrap();
        let e = g.by_name.get(&(qname, typ))?;
        if e.expiry <= now {
            return None;
        }
        Some(e.ips.clone())
    }

    /// Reverse: dest IP → cached qname (for TUN suffix/GEOIP before `decide`).
    pub fn lookup_qname(&self, ip: IpAddr) -> Option<String> {
        let now = Instant::now();
        let g = self.inner.lock().unwrap();
        let e = g.by_ip.get(&ip)?;
        if e.expiry <= now {
            return None;
        }
        Some(e.qname.clone())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// If `dest.host` is empty and `dest.ip` is cached, fill host from the cache.
pub fn fill_host_from_cache(dest: &mut Dest, cache: &DnsCache) {
    if dest.host.is_some() {
        return;
    }
    let Some(ip) = dest.ip else {
        return;
    };
    if let Some(h) = cache.lookup_qname(ip) {
        dest.host = Some(h);
    }
}

fn normalize_qname(n: &str) -> String {
    n.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// DNS query/response wire helpers.
pub fn parse_question(msg: &[u8]) -> Result<DnsQuestion, Error> {
    if msg.len() < 12 {
        return Err(Error::dns("short dns header"));
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    if qd == 0 {
        return Err(Error::dns("no question"));
    }
    let (qname, i) = parse_name(msg, 12)?;
    if i + 4 > msg.len() {
        return Err(Error::dns("short question"));
    }
    let qtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
    let qclass = u16::from_be_bytes([msg[i + 2], msg[i + 3]]);
    Ok(DnsQuestion {
        id,
        qname,
        qtype,
        qclass,
    })
}

/// Parse A/AAAA answers (and their TTLs).
pub fn parse_answers(msg: &[u8]) -> Result<Vec<DnsRecord>, Error> {
    if msg.len() < 12 {
        return Err(Error::dns("short dns header"));
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        let (_, ni) = parse_name(msg, i)?;
        i = ni + 4;
        if i > msg.len() {
            return Err(Error::dns("truncated questions"));
        }
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let (name, ni) = parse_name(msg, i)?;
        i = ni;
        if i + 10 > msg.len() {
            break;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let _class = u16::from_be_bytes([msg[i + 2], msg[i + 3]]);
        let ttl = u32::from_be_bytes([msg[i + 4], msg[i + 5], msg[i + 6], msg[i + 7]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if i + rdlen > msg.len() {
            break;
        }
        let rdata = &msg[i..i + rdlen];
        i += rdlen;
        match typ {
            TYPE_A if rdata.len() == 4 => out.push(DnsRecord {
                name: name.clone(),
                typ,
                ttl,
                ip: IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            }),
            TYPE_AAAA if rdata.len() == 16 => {
                let mut a = [0u8; 16];
                a.copy_from_slice(rdata);
                out.push(DnsRecord {
                    name,
                    typ,
                    ttl,
                    ip: IpAddr::V6(Ipv6Addr::from(a)),
                });
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Encode a standard recursive query.
pub fn encode_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    encode_name(&mut buf, qname);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());
    buf
}

/// Build a response for `q` with the given A/AAAA rdata.
pub fn encode_response(q: &DnsQuestion, records: &[(IpAddr, u32)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&q.id.to_be_bytes());
    buf.extend_from_slice(&0x8180u16.to_be_bytes()); // QR RD RA
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&(records.len() as u16).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, 0]);
    encode_name(&mut buf, &q.qname);
    buf.extend_from_slice(&q.qtype.to_be_bytes());
    buf.extend_from_slice(&q.qclass.to_be_bytes());
    for (ip, ttl) in records {
        encode_name(&mut buf, &q.qname);
        let (typ, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v) => (TYPE_A, v.octets().to_vec()),
            IpAddr::V6(v) => (TYPE_AAAA, v.octets().to_vec()),
        };
        buf.extend_from_slice(&typ.to_be_bytes());
        buf.extend_from_slice(&CLASS_IN.to_be_bytes());
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);
    }
    buf
}

fn encode_name(buf: &mut Vec<u8>, name: &str) {
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            let b = label.as_bytes();
            buf.push(b.len() as u8);
            buf.extend_from_slice(b);
        }
    }
    buf.push(0);
}

fn parse_name(msg: &[u8], mut i: usize) -> Result<(String, usize), Error> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = i;
    let mut hops = 0u8;
    loop {
        if i >= msg.len() {
            return Err(Error::dns("bad name"));
        }
        let len = msg[i];
        if len & 0xc0 == 0xc0 {
            if i + 1 >= msg.len() {
                return Err(Error::dns("bad compression"));
            }
            let ptr = (((len as usize) & 0x3f) << 8) | (msg[i + 1] as usize);
            if !jumped {
                end = i + 2;
                jumped = true;
            }
            i = ptr;
            hops += 1;
            if hops > 10 {
                return Err(Error::dns("compression loop"));
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                end = i + 1;
            }
            break;
        }
        i += 1;
        let n = len as usize;
        if i + n > msg.len() {
            return Err(Error::dns("bad label"));
        }
        labels.push(String::from_utf8_lossy(&msg[i..i + n]).into_owned());
        i += n;
    }
    Ok((labels.join("."), end))
}

fn servfail(q: &DnsQuestion) -> Vec<u8> {
    let mut buf = encode_query(q.id, &q.qname, q.qtype);
    buf[2] = 0x81;
    buf[3] = 0x82; // QR + RD + RA + SERVFAIL
    buf
}

/// Upstream that answers a raw DNS message (tests inject a mock).
#[async_trait]
pub trait DnsUpstream: Send + Sync {
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Error>;
}

/// TCP connect used by DoH. Production: [`DirectDialer`]. Tests: mock.
#[async_trait]
pub trait PlainTcp: Send + Sync {
    async fn tcp(&self, dest: &Dest) -> Result<TcpStream, Error>;
}

#[async_trait]
impl PlainTcp for DirectDialer {
    async fn tcp(&self, dest: &Dest) -> Result<TcpStream, Error> {
        DirectDialer::tcp(self, dest).await
    }
}

/// Default DoH URL when Darwin a-only has empty `--route-dns` and conf `dns-server`.
pub const DARWIN_A_ONLY_DOH: &str = "https://1.1.1.1/dns-query";

/// TUN stub: cache + upstreams. Answers on the TUN; never uses hy Client.
pub struct DnsStub {
    pub cache: Arc<DnsCache>,
    pub upstreams: Vec<Arc<dyn DnsUpstream>>,
    aaaa_nodata: bool,
}

impl DnsStub {
    pub fn new(cache: Arc<DnsCache>, upstreams: Vec<Arc<dyn DnsUpstream>>) -> Self {
        Self {
            cache,
            upstreams,
            aaaa_nodata: false,
        }
    }

    /// Darwin a-only: AAAA → NOERROR / ANCOUNT=0; never cache AAAA.
    pub fn with_aaaa_nodata(mut self, on: bool) -> Self {
        self.aaaa_nodata = on;
        self
    }

    pub fn aaaa_nodata(&self) -> bool {
        self.aaaa_nodata
    }

    /// Answer a UDP (or already de-framed TCP) DNS query payload.
    pub async fn answer(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let q = parse_question(query)?;
        if self.aaaa_nodata && q.qtype == TYPE_AAAA {
            return Ok(encode_response(&q, &[]));
        }
        if q.qtype == TYPE_A || q.qtype == TYPE_AAAA {
            if let Some(ips) = self.cache.lookup_ips(&q.qname, q.qtype) {
                let recs: Vec<(IpAddr, u32)> =
                    ips.into_iter().map(|ip| (ip, TTL_MIN_SECS)).collect();
                return Ok(encode_response(&q, &recs));
            }
        }
        let mut last = Error::dns("no upstream");
        for u in &self.upstreams {
            match u.exchange(query).await {
                Ok(raw) => {
                    if let Ok(recs) = parse_answers(&raw) {
                        if self.aaaa_nodata {
                            let recs: Vec<DnsRecord> =
                                recs.into_iter().filter(|r| r.typ != TYPE_AAAA).collect();
                            self.cache.insert_from_message(&q.qname, &recs);
                            if q.qtype == TYPE_AAAA {
                                return Ok(encode_response(&q, &[]));
                            }
                            let pairs: Vec<(IpAddr, u32)> =
                                recs.iter().map(|r| (r.ip, r.ttl)).collect();
                            return Ok(encode_response(&q, &pairs));
                        }
                        self.cache.insert_from_message(&q.qname, &recs);
                    }
                    return Ok(raw);
                }
                Err(e) => last = e,
            }
        }
        tracing::debug!(error = %last, qname = %q.qname, "dns upstream failed");
        Ok(servfail(&q))
    }
}

/// Resolver list entry: DoH URL or plain `ip:53`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverSpec {
    Doh { url: String },
    Plain { addr: SocketAddr },
}

/// Parse `--route-dns` / `[General] dns-server` (comma-separated).
pub fn parse_dns_list(s: &str) -> Result<Vec<ResolverSpec>, Error> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        out.push(parse_one_resolver(part)?);
    }
    Ok(out)
}

fn parse_one_resolver(s: &str) -> Result<ResolverSpec, Error> {
    if s.starts_with("https://") {
        return Ok(ResolverSpec::Doh { url: s.to_string() });
    }
    if s.starts_with("http://") {
        return Err(Error::dns("DoH requires https://"));
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(ResolverSpec::Plain { addr: sa });
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ResolverSpec::Plain {
            addr: SocketAddr::new(ip, 53),
        });
    }
    Err(Error::dns(format!("bad dns server {s}")))
}

/// Nameservers from `/etc/resolv.conf`. If none, `8.8.8.8:53`.
pub fn system_dns_servers() -> Vec<ResolverSpec> {
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let ip = rest.trim();
        if ip.is_empty() {
            continue;
        }
        if let Ok(spec) = parse_one_resolver(ip) {
            out.push(spec);
        }
    }
    if out.is_empty() {
        out.push(ResolverSpec::Plain {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        });
    }
    out
}

/// CLI `--route-dns` wins over conf; both empty → system DNS, or Darwin a-only DoH.
pub fn resolve_server_list(
    cli: Option<&str>,
    conf: &[String],
    darwin_a_only_default: bool,
) -> Result<Vec<ResolverSpec>, Error> {
    if let Some(s) = cli.map(str::trim).filter(|s| !s.is_empty()) {
        return parse_dns_list(s);
    }
    if !conf.is_empty() {
        return parse_dns_list(&conf.join(","));
    }
    if darwin_a_only_default {
        return Ok(vec![ResolverSpec::Doh {
            url: DARWIN_A_ONLY_DOH.to_string(),
        }]);
    }
    Ok(system_dns_servers())
}

/// Darwin TUN with no `address.ipv6`: AAAA NODATA + DoH default + system DNS magnet.
pub fn darwin_a_only_mode(is_darwin: bool, tun_present: bool, has_address_ipv6: bool) -> bool {
    is_darwin && tun_present && !has_address_ipv6
}

/// Enable the :53 stub: route file (existing) or Darwin a-only even without a route file.
/// Linux without a route file stays off. `--route-no-hijack-dns` always wins.
pub fn want_tun_dns_stub(has_route_file: bool, no_hijack: bool, darwin_a_only: bool) -> bool {
    if no_hijack {
        return false;
    }
    has_route_file || darwin_a_only
}

/// Build a TUN stub from CLI/conf resolvers. `aaaa_nodata` also selects the Darwin DoH default.
pub fn build_dns_stub(
    cache: Arc<DnsCache>,
    cli: Option<&str>,
    conf: &[String],
    dialer: DirectDialer,
    aaaa_nodata: bool,
) -> Result<DnsStub, Error> {
    let specs = resolve_server_list(cli, conf, aaaa_nodata)?;
    let upstreams = build_upstreams(&specs, dialer)?;
    Ok(DnsStub::new(cache, upstreams).with_aaaa_nodata(aaaa_nodata))
}

/// Parsed DoH URL (RFC 8484 POST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohTarget {
    pub dest: Dest,
    pub host_header: String,
    pub sni: String,
    pub path: String,
}

/// Parse `https://host[:port]/path` into a DirectDialer dest + HTTP parts.
pub fn parse_doh_url(url: &str) -> Result<DohTarget, Error> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| Error::dns("DoH requires https:// URL"))?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/dns-query".to_string()),
    };
    let (host, port, dest) = parse_hostport(hostport, 443)?;
    Ok(DohTarget {
        dest,
        host_header: host_header(&host, port, 443),
        sni: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        path,
    })
}

fn host_header(host: &str, port: u16, default: u16) -> String {
    if port == default {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn parse_hostport(hostport: &str, default_port: u16) -> Result<(String, u16, Dest), Error> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| Error::dns("bad DoH IPv6 URL"))?;
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse().map_err(|_| Error::dns("bad DoH port"))?
        } else {
            default_port
        };
        let ip: IpAddr = host.parse().map_err(|_| Error::dns("bad DoH IPv6"))?;
        return Ok((
            format!("[{host}]"),
            port,
            Dest {
                host: None,
                ip: Some(ip),
                port,
                proto: Proto::Tcp,
            },
        ));
    }
    if let Ok(sa) = hostport.parse::<SocketAddr>() {
        return Ok((
            sa.ip().to_string(),
            sa.port(),
            Dest::from_socket_addr(sa, Proto::Tcp),
        ));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() && !h.contains(':') => {
            (h.to_string(), p.parse().unwrap())
        }
        _ => (hostport.to_string(), default_port),
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((
            host,
            port,
            Dest {
                host: None,
                ip: Some(ip),
                port,
                proto: Proto::Tcp,
            },
        ));
    }
    Ok((
        host.clone(),
        port,
        Dest {
            host: Some(host),
            ip: None,
            port,
            proto: Proto::Tcp,
        },
    ))
}

/// RFC 8484 HTTP/1.1 POST body (no TLS). Used by tests and DoH client.
pub fn build_doh_http_request(host: &str, path: &str, query: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        query.len()
    )
    .into_bytes();
    req.extend_from_slice(query);
    req
}

/// Split HTTP/1.1 response; return the DNS body.
pub fn parse_doh_http_response(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::dns("DoH: bad HTTP response"))?;
    let head = std::str::from_utf8(&raw[..sep]).map_err(|e| Error::dns(e.to_string()))?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or_else(|| Error::dns("DoH: no status"))?;
    if status != "200" {
        return Err(Error::dns(format!("DoH: status {status}")));
    }
    Ok(raw[sep + 4..].to_vec())
}

/// POST a DNS query over an already-connected stream (TLS or mock).
pub async fn doh_http_exchange<S>(
    mut stream: S,
    host: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = build_doh_http_request(host, path, query);
    stream
        .write_all(&req)
        .await
        .map_err(|e| Error::dns(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| Error::dns(e.to_string()))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| Error::dns(e.to_string()))?;
    parse_doh_http_response(&raw)
}

/// Dial DoH's TCP via `tcp` (DirectDialer in production). No TLS.
pub async fn doh_tcp_connect(
    tcp: &dyn PlainTcp,
    url: &str,
) -> Result<(TcpStream, DohTarget), Error> {
    let target = parse_doh_url(url)?;
    let stream = tcp.tcp(&target.dest).await?;
    Ok((stream, target))
}

fn ensure_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn rustls_client_config() -> Result<ClientConfig, Error> {
    ensure_crypto();
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(c);
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// DoH upstream: DirectDialer TCP + rustls + RFC 8484 POST.
pub struct DohUpstream {
    pub url: String,
    tcp: Arc<dyn PlainTcp>,
    tls: TlsConnector,
}

impl DohUpstream {
    pub fn new(url: String, tcp: Arc<dyn PlainTcp>) -> Result<Self, Error> {
        let cfg = Arc::new(rustls_client_config()?);
        Ok(Self {
            url,
            tcp,
            tls: TlsConnector::from(cfg),
        })
    }

    pub fn with_direct(url: String, dialer: DirectDialer) -> Result<Self, Error> {
        Self::new(url, Arc::new(dialer))
    }
}

#[async_trait]
impl DnsUpstream for DohUpstream {
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let (stream, target) = doh_tcp_connect(&*self.tcp, &self.url).await?;
        let name =
            ServerName::try_from(target.sni.clone()).map_err(|e| Error::dns(e.to_string()))?;
        let tls = self
            .tls
            .connect(name, stream)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        doh_http_exchange(tls, &target.host_header, &target.path, query).await
    }
}

/// Plain DNS over DirectDialer UDP (TCP fallback if TC bit).
pub struct PlainUpstream {
    pub addr: SocketAddr,
    dialer: DirectDialer,
}

impl PlainUpstream {
    pub fn new(addr: SocketAddr, dialer: DirectDialer) -> Self {
        Self { addr, dialer }
    }
}

#[async_trait]
impl DnsUpstream for PlainUpstream {
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let sock = self.dialer.udp_bind(self.addr.is_ipv6()).await?;
        sock.send_to(query, self.addr)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .map_err(|_| Error::dns("udp timeout"))?
            .map_err(|e| Error::dns(e.to_string()))?;
        let resp = &buf[..n];
        if n >= 4 && resp[2] & 0x02 != 0 {
            return self.exchange_tcp(query).await;
        }
        Ok(resp.to_vec())
    }
}

impl PlainUpstream {
    async fn exchange_tcp(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
        let dest = Dest::from_socket_addr(self.addr, Proto::Tcp);
        let mut s = self.dialer.tcp(&dest).await?;
        let len = (query.len() as u16).to_be_bytes();
        s.write_all(&len)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        s.write_all(query)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        let mut lb = [0u8; 2];
        s.read_exact(&mut lb)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        let n = u16::from_be_bytes(lb) as usize;
        let mut resp = vec![0u8; n];
        s.read_exact(&mut resp)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        Ok(resp)
    }
}

/// Build upstreams from a resolver list. All TCP/UDP uses `dialer`.
pub fn build_upstreams(
    specs: &[ResolverSpec],
    dialer: DirectDialer,
) -> Result<Vec<Arc<dyn DnsUpstream>>, Error> {
    let mut out: Vec<Arc<dyn DnsUpstream>> = Vec::new();
    for s in specs {
        match s {
            ResolverSpec::Doh { url } => {
                out.push(Arc::new(DohUpstream::with_direct(
                    url.clone(),
                    dialer.clone(),
                )?));
            }
            ResolverSpec::Plain { addr } => {
                out.push(Arc::new(PlainUpstream::new(*addr, dialer.clone())));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DirectDialer;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture_query_example_a() -> Vec<u8> {
        encode_query(0x1234, "example.com", TYPE_A)
    }

    fn fixture_response_example_a() -> Vec<u8> {
        let q = DnsQuestion {
            id: 0x1234,
            qname: "example.com".into(),
            qtype: TYPE_A,
            qclass: CLASS_IN,
        };
        encode_response(&q, &[(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 60)])
    }

    #[test]
    fn parse_query_fixture() {
        let q = parse_question(&fixture_query_example_a()).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.qname, "example.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn parse_response_fixture() {
        let recs = parse_answers(&fixture_response_example_a()).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].typ, TYPE_A);
        assert_eq!(recs[0].ttl, 60);
        assert_eq!(recs[0].ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        let q = parse_question(&fixture_response_example_a()).unwrap();
        assert_eq!(q.qname, "example.com");
    }

    #[test]
    fn ttl_clamp_30s_and_1h() {
        assert_eq!(clamp_ttl(1), 30);
        assert_eq!(clamp_ttl(29), 30);
        assert_eq!(clamp_ttl(30), 30);
        assert_eq!(clamp_ttl(3600), 3600);
        assert_eq!(clamp_ttl(3601), 3600);
        assert_eq!(clamp_ttl(u32::MAX), 3600);
    }

    #[test]
    fn cache_insert_lookup_both_directions() {
        let c = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        c.insert("Ads.Example.", TYPE_A, &[ip], 5);
        assert_eq!(c.lookup_ips("ads.example", TYPE_A), Some(vec![ip]));
        assert_eq!(c.lookup_qname(ip).as_deref(), Some("ads.example"));
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        c.insert("v6.example", TYPE_AAAA, &[ip6], 7200);
        assert_eq!(c.lookup_ips("v6.example", TYPE_AAAA), Some(vec![ip6]));
        assert_eq!(c.lookup_qname(ip6).as_deref(), Some("v6.example"));
    }

    #[test]
    fn fill_host_from_cache_for_ip_only_dest() {
        let c = DnsCache::new();
        c.insert(
            "google.com",
            TYPE_A,
            &[IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))],
            60,
        );
        let mut d = Dest::from_socket_addr("8.8.4.4:443".parse().unwrap(), Proto::Tcp);
        assert!(d.host.is_none());
        fill_host_from_cache(&mut d, &c);
        assert_eq!(d.host.as_deref(), Some("google.com"));
        let mut keep = Dest {
            host: Some("already.example".into()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))),
            port: 443,
            proto: Proto::Tcp,
        };
        fill_host_from_cache(&mut keep, &c);
        assert_eq!(keep.host.as_deref(), Some("already.example"));
    }

    struct MockUp(Vec<u8>);

    #[async_trait]
    impl DnsUpstream for MockUp {
        async fn exchange(&self, _query: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn stub_answers_crafted_a_query() {
        let cache = Arc::new(DnsCache::new());
        let up = Arc::new(MockUp(fixture_response_example_a()));
        let stub = DnsStub::new(cache.clone(), vec![up]);
        let resp = stub.answer(&fixture_query_example_a()).await.unwrap();
        let recs = parse_answers(&resp).unwrap();
        assert_eq!(recs[0].ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(
            cache
                .lookup_qname(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                .as_deref(),
            Some("example.com")
        );
        let q = parse_question(&resp).unwrap();
        assert_eq!(q.id, 0x1234);
    }

    #[test]
    fn parse_dns_list_mix_doh_and_ip() {
        let v = parse_dns_list("https://dns.google/dns-query, 1.1.1.1, 8.8.8.8:53").unwrap();
        assert_eq!(v.len(), 3);
        match &v[0] {
            ResolverSpec::Doh { url } => assert_eq!(url, "https://dns.google/dns-query"),
            other => panic!("{other:?}"),
        }
        match &v[1] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"1.1.1.1:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
        match &v[2] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"8.8.8.8:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn route_dns_cli_wins_over_conf() {
        let cli = resolve_server_list(Some("9.9.9.9"), &["8.8.8.8".into()], false).unwrap();
        match &cli[0] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"9.9.9.9:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
        let conf = resolve_server_list(None, &["1.1.1.1".into()], false).unwrap();
        match &conf[0] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"1.1.1.1:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn darwin_a_only_default_doh_explicit_still_wins() {
        let d = resolve_server_list(None, &[], true).unwrap();
        assert_eq!(d.len(), 1);
        match &d[0] {
            ResolverSpec::Doh { url } => assert_eq!(url, DARWIN_A_ONLY_DOH),
            other => panic!("{other:?}"),
        }
        let linux = resolve_server_list(None, &[], false).unwrap();
        assert!(
            !linux.is_empty(),
            "Linux/default path must still yield system DNS"
        );
        match &linux[0] {
            ResolverSpec::Doh { url } => {
                assert_ne!(
                    url, DARWIN_A_ONLY_DOH,
                    "Linux must not default to Darwin DoH"
                )
            }
            ResolverSpec::Plain { addr } => {
                assert_eq!(addr.port(), 53);
            }
        }
        let cli = resolve_server_list(Some("9.9.9.9"), &[], true).unwrap();
        match &cli[0] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"9.9.9.9:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
        let conf = resolve_server_list(None, &["8.8.8.8".into()], true).unwrap();
        match &conf[0] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"8.8.8.8:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
        let both = resolve_server_list(Some("1.1.1.1"), &["8.8.8.8".into()], true).unwrap();
        match &both[0] {
            ResolverSpec::Plain { addr } => assert_eq!(addr, &"1.1.1.1:53".parse().unwrap()),
            other => panic!("{other:?}"),
        }
    }

    fn rcode(msg: &[u8]) -> u8 {
        msg[3] & 0x0f
    }

    fn ancount(msg: &[u8]) -> u16 {
        u16::from_be_bytes([msg[6], msg[7]])
    }

    struct TypedMock;

    #[async_trait]
    impl DnsUpstream for TypedMock {
        async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, Error> {
            let q = parse_question(query)?;
            if q.qtype == TYPE_AAAA {
                Ok(encode_response(
                    &q,
                    &[(IpAddr::V6("2001::1".parse().unwrap()), 60)],
                ))
            } else {
                Ok(encode_response(
                    &q,
                    &[(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 60)],
                ))
            }
        }
    }

    #[tokio::test]
    async fn aaaa_nodata_empty_answers_does_not_cache_aaaa() {
        let cache = Arc::new(DnsCache::new());
        let stub = DnsStub::new(cache.clone(), vec![Arc::new(TypedMock)]).with_aaaa_nodata(true);
        let q6 = encode_query(0x1111, "www.youtube.com", TYPE_AAAA);
        let resp = stub.answer(&q6).await.unwrap();
        assert_eq!(rcode(&resp), 0, "NOERROR, not SERVFAIL/NXDOMAIN");
        assert_eq!(ancount(&resp), 0);
        assert!(parse_answers(&resp).unwrap().is_empty());
        let q = parse_question(&resp).unwrap();
        assert_eq!(q.qtype, TYPE_AAAA);
        assert_eq!(q.id, 0x1111);
        let fake: IpAddr = "2001::1".parse().unwrap();
        assert!(cache.lookup_ips("www.youtube.com", TYPE_AAAA).is_none());
        assert!(cache.lookup_qname(fake).is_none());

        let q4 = encode_query(0x2222, "example.com", TYPE_A);
        let resp = stub.answer(&q4).await.unwrap();
        let recs = parse_answers(&resp).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(
            cache
                .lookup_qname(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                .as_deref(),
            Some("example.com")
        );
        assert!(cache.lookup_ips("example.com", TYPE_AAAA).is_none());
        assert!(cache.lookup_qname(fake).is_none());
    }

    #[tokio::test]
    async fn aaaa_forwarded_when_nodata_flag_off() {
        let cache = Arc::new(DnsCache::new());
        let stub = DnsStub::new(cache.clone(), vec![Arc::new(TypedMock)]);
        assert!(!stub.aaaa_nodata());
        let q6 = encode_query(0x3333, "www.youtube.com", TYPE_AAAA);
        let resp = stub.answer(&q6).await.unwrap();
        let recs = parse_answers(&resp).unwrap();
        assert_eq!(rcode(&resp), 0);
        assert_eq!(recs.len(), 1);
        let fake: IpAddr = "2001::1".parse().unwrap();
        assert_eq!(recs[0].ip, fake);
        assert_eq!(
            cache.lookup_ips("www.youtube.com", TYPE_AAAA),
            Some(vec![fake])
        );
        assert_eq!(cache.lookup_qname(fake).as_deref(), Some("www.youtube.com"));
    }

    #[test]
    fn darwin_without_route_enables_stub_linux_does_not() {
        assert!(
            darwin_a_only_mode(true, true, false),
            "Darwin TUN without address.ipv6"
        );
        assert!(
            !darwin_a_only_mode(true, true, true),
            "address.ipv6 turns the gate off"
        );
        assert!(!darwin_a_only_mode(false, true, false), "Linux: no a-only");
        assert!(!darwin_a_only_mode(true, false, false), "no TUN");

        assert!(
            want_tun_dns_stub(false, false, true),
            "Darwin a-only still hijacks :53 without a route file"
        );
        assert!(
            !want_tun_dns_stub(false, false, false),
            "Linux without a route file must not hijack"
        );
        assert!(
            want_tun_dns_stub(true, false, false),
            "Linux with route file"
        );
        assert!(
            !want_tun_dns_stub(true, true, true),
            "--route-no-hijack-dns wins"
        );

        let d = DirectDialer::relaxed(0x162);
        let stub = build_dns_stub(Arc::new(DnsCache::new()), None, &[], d, true).unwrap();
        assert!(stub.aaaa_nodata());
        let specs = resolve_server_list(None, &[], stub.aaaa_nodata()).unwrap();
        match &specs[0] {
            ResolverSpec::Doh { url } => assert_eq!(url, DARWIN_A_ONLY_DOH),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn doh_request_builder() {
        let q = fixture_query_example_a();
        let req = build_doh_http_request("dns.google", "/dns-query", &q);
        let s = String::from_utf8_lossy(&req);
        assert!(s.starts_with("POST /dns-query HTTP/1.1\r\n"));
        assert!(s.contains("Host: dns.google\r\n"));
        assert!(s.contains("Content-Type: application/dns-message\r\n"));
        assert!(s.contains(&format!("Content-Length: {}\r\n", q.len())));
        assert!(req.ends_with(q.as_slice()));
        let t = parse_doh_url("https://dns.google/dns-query").unwrap();
        assert_eq!(t.dest.host.as_deref(), Some("dns.google"));
        assert_eq!(t.dest.port, 443);
        assert_eq!(t.path, "/dns-query");
        assert_eq!(t.sni, "dns.google");
    }

    struct RecTcp {
        dests: Mutex<Vec<Dest>>,
        local: SocketAddr,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl PlainTcp for RecTcp {
        async fn tcp(&self, dest: &Dest) -> Result<TcpStream, Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.dests.lock().unwrap().push(dest.clone());
            TcpStream::connect(self.local)
                .await
                .map_err(|e| Error::dns(e.to_string()))
        }
    }

    #[tokio::test]
    async fn doh_tcp_uses_plain_tcp_mock_not_live() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let rec = RecTcp {
            dests: Mutex::new(Vec::new()),
            local,
            calls: AtomicUsize::new(0),
        };
        let url = "https://dns.google/dns-query";
        let (_s, target) = doh_tcp_connect(&rec, url).await.unwrap();
        assert_eq!(target.dest.host.as_deref(), Some("dns.google"));
        assert_eq!(target.dest.port, 443);
        assert_eq!(rec.calls.load(Ordering::SeqCst), 1);
        let d = rec.dests.lock().unwrap();
        assert_eq!(d[0].host.as_deref(), Some("dns.google"));
        assert_eq!(d[0].port, 443);
        assert_eq!(d[0].proto, Proto::Tcp);
    }

    #[tokio::test]
    async fn doh_http_roundtrip_on_duplex() {
        let (client, mut server) = tokio::io::duplex(8192);
        let q = fixture_query_example_a();
        let body = fixture_response_example_a();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let n = server.read(&mut buf).await.unwrap();
            let req = &buf[..n];
            assert!(req.windows(4).any(|w| w == b"POST"));
            let mut resp =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\n".to_vec();
            resp.extend_from_slice(&body);
            server.write_all(&resp).await.unwrap();
        });
        let got = doh_http_exchange(client, "dns.google", "/dns-query", &q)
            .await
            .unwrap();
        assert_eq!(
            parse_answers(&got).unwrap()[0].ip,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn decide_uses_cached_qname() {
        let r =
            crate::compile("[Rule]\nDOMAIN-SUFFIX,example,REJECT\nFINAL,PROXY\n", None).unwrap();
        let cache = DnsCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        cache.insert("ads.example", TYPE_A, &[ip], 60);
        let mut dest = Dest {
            host: None,
            ip: Some(ip),
            port: 443,
            proto: Proto::Tcp,
        };
        assert_eq!(r.decide(&dest), crate::Action::Proxy);
        fill_host_from_cache(&mut dest, &cache);
        assert_eq!(dest.host.as_deref(), Some("ads.example"));
        assert_eq!(r.decide(&dest), crate::Action::Reject);
    }
}
