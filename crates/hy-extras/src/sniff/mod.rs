//! Packet inspection RequestHook (HTTP Host / TLS SNI / QUIC SNI).

mod quic;

use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, RequestHook};
use std::net::IpAddr;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HTTP_HEADER_BYTES: usize = 256 * 1024;

/// Server RequestHook that rewrites `req_addr` from protocol headers.
pub struct Sniffer {
    pub timeout: Duration,
    pub rewrite_domain: bool,
    /// `None` or empty = all ports (like Go nil PortUnion).
    pub tcp_ports: Option<Vec<(u16, u16)>>,
    pub udp_ports: Option<Vec<(u16, u16)>>,
}

impl Default for Sniffer {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            rewrite_domain: false,
            tcp_ports: None,
            udp_ports: None,
        }
    }
}

impl Sniffer {
    fn timeout_or_default(&self) -> Duration {
        if self.timeout.is_zero() {
            DEFAULT_TIMEOUT
        } else {
            self.timeout
        }
    }

    fn port_allowed(ports: &Option<Vec<(u16, u16)>>, port: u16) -> bool {
        match ports {
            None => true,
            Some(list) if list.is_empty() => true,
            Some(list) => list.iter().any(|&(s, e)| port >= s && port <= e),
        }
    }

    fn is_http(buf: &[u8]) -> bool {
        if buf.len() < 3 {
            return false;
        }
        buf[..3]
            .iter()
            .all(|b| b.is_ascii_alphabetic())
    }

    fn is_tls(buf: &[u8]) -> bool {
        if buf.len() < 3 {
            return false;
        }
        buf[0] >= 0x16 && buf[0] <= 0x17 && buf[1] == 0x03 && buf[2] <= 0x09
    }
}

#[async_trait]
impl RequestHook for Sniffer {
    fn check(&self, is_udp: bool, req_addr: &str) -> bool {
        if req_addr.starts_with('@') {
            return false;
        }
        let Some((host, port_str)) = split_host_port(req_addr) else {
            return false;
        };
        if !self.rewrite_domain && host.parse::<IpAddr>().is_err() {
            return false;
        }
        let Ok(port) = port_str.parse::<u16>() else {
            return false;
        };
        if is_udp {
            Self::port_allowed(&self.udp_ports, port)
        } else {
            Self::port_allowed(&self.tcp_ports, port)
        }
    }

    async fn tcp(
        &self,
        stream: &mut dyn HyTcpStream,
        req_addr: &mut String,
    ) -> Result<Vec<u8>, Error> {
        let deadline = tokio::time::Instant::now() + self.timeout_or_default();
        let mut pre = vec![0u8; 3];
        let n = read_full_deadline(stream, &mut pre, deadline).await?;
        if n < 3 {
            pre.truncate(n);
            return Ok(pre);
        }

        if Self::is_http(&pre) {
            return sniff_http(stream, pre, req_addr, deadline).await;
        }
        if Self::is_tls(&pre) {
            return sniff_tls(stream, pre, req_addr, deadline).await;
        }
        Ok(pre)
    }

    async fn udp(&self, data: &[u8], req_addr: &mut String) -> Result<(), Error> {
        let Some(pl) = quic::read_crypto_payload(data) else {
            return Ok(());
        };
        if pl.len() < 4 || pl[0] != 0x01 {
            return Ok(());
        }
        if let Some(sni) = extract_sni_from_handshake(&pl) {
            if let Some((_, port)) = split_host_port(req_addr) {
                *req_addr = join_host_port(&sni, port);
            }
        }
        Ok(())
    }
}

async fn sniff_http(
    stream: &mut dyn HyTcpStream,
    pre: Vec<u8>,
    req_addr: &mut String,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, Error> {
    let mut buf = pre;
    while !has_header_end(&buf) && buf.len() < MAX_HTTP_HEADER_BYTES {
        let mut tmp = [0u8; 1024];
        let want = std::cmp::min(tmp.len(), MAX_HTTP_HEADER_BYTES - buf.len());
        let n = read_deadline(stream, &mut tmp[..want], deadline).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if let Some(host) = parse_http_host(&buf) {
        if let Some((_, port)) = split_host_port(req_addr) {
            *req_addr = join_host_port(&host, port);
        }
    }
    Ok(buf)
}

async fn sniff_tls(
    stream: &mut dyn HyTcpStream,
    mut pre: Vec<u8>,
    req_addr: &mut String,
    deadline: tokio::time::Instant,
) -> Result<Vec<u8>, Error> {
    pre.resize(5, 0);
    let n = read_full_deadline(stream, &mut pre[3..5], deadline).await?;
    if n < 2 {
        pre.truncate(3 + n);
        return Ok(pre);
    }
    let content_length = ((pre[3] as usize) << 8) | pre[4] as usize;
    let total = 5 + content_length;
    pre.resize(total, 0);
    let n = read_full_deadline(stream, &mut pre[5..], deadline).await?;
    if n < content_length {
        pre.truncate(5 + n);
        return Ok(pre);
    }
    if let Some(sni) = extract_sni_from_handshake(&pre[5..]) {
        if let Some((_, port)) = split_host_port(req_addr) {
            *req_addr = join_host_port(&sni, port);
        }
    }
    Ok(pre)
}

fn has_header_end(buf: &[u8]) -> bool {
    buf.windows(4).any(|w| w == b"\r\n\r\n")
}

fn parse_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    let header_end = text.find("\r\n\r\n").unwrap_or(text.len());
    let headers = &text[..header_end];
    for line in headers.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            if host.is_empty() {
                return None;
            }
            // Host may be host:port — keep host only.
            if let Some((h, _)) = split_host_port(host) {
                return Some(h.to_string());
            }
            return Some(host.to_string());
        }
    }
    None
}

/// `data` is a TLS handshake message starting with type byte (0x01 = ClientHello).
fn extract_sni_from_handshake(data: &[u8]) -> Option<String> {
    // HandshakeType(1) + length(3) + ClientHello
    if data.len() < 4 || data[0] != 0x01 {
        return None;
    }
    let hs_len = ((data[1] as usize) << 16) | ((data[2] as usize) << 8) | data[3] as usize;
    let body = data.get(4..4 + hs_len).unwrap_or(&data[4..]);
    parse_client_hello_sni(body)
}

fn parse_client_hello_sni(body: &[u8]) -> Option<String> {
    // legacy_version(2) + random(32) + session_id + cipher_suites + compression + extensions
    if body.len() < 34 {
        return None;
    }
    let mut i = 34; // after version + random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    if body.len() < i + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes(body[i..i + 2].try_into().ok()?) as usize;
    i += 2 + cs_len;
    if body.len() < i + 1 {
        return None;
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;
    if body.len() < i + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes(body[i..i + 2].try_into().ok()?) as usize;
    i += 2;
    let ext_end = std::cmp::min(i + ext_len, body.len());
    while i + 4 <= ext_end {
        let typ = u16::from_be_bytes(body[i..i + 2].try_into().ok()?);
        let len = u16::from_be_bytes(body[i + 2..i + 4].try_into().ok()?) as usize;
        i += 4;
        if i + len > ext_end {
            break;
        }
        if typ == 0 {
            return parse_sni_extension(&body[i..i + len]);
        }
        i += len;
    }
    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes(data[0..2].try_into().ok()?) as usize;
    let list = data.get(2..2 + list_len).unwrap_or(&data[2..]);
    let mut pos = 0;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes(list[pos + 1..pos + 3].try_into().ok()?) as usize;
        pos += 3;
        if pos + name_len > list.len() {
            break;
        }
        if name_type == 0 {
            return std::str::from_utf8(&list[pos..pos + name_len])
                .ok()
                .map(|s| s.to_string());
        }
        pos += name_len;
    }
    None
}

fn split_host_port(addr: &str) -> Option<(&str, &str)> {
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?;
        return Some((host, port));
    }
    let (host, port) = addr.rsplit_once(':')?;
    if host.contains(':') {
        // Ambiguous IPv6 without brackets
        return None;
    }
    Some((host, port))
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn read_deadline(
    stream: &mut dyn HyTcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<usize, Error> {
    let now = tokio::time::Instant::now();
    if now >= deadline {
        return Ok(0);
    }
    match tokio::time::timeout(deadline - now, stream.read(buf)).await {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(0),
    }
}

async fn read_full_deadline(
    stream: &mut dyn HyTcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<usize, Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = read_deadline(stream, &mut buf[filled..], deadline).await?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Parse official port-union string (`80,443,1000-2000`). `None` if invalid.
pub fn parse_port_union(s: &str) -> Option<Vec<(u16, u16)>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if s == "all" || s == "*" {
        return Some(vec![(0, 65535)]);
    }
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        if let Some((a, b)) = part.split_once('-') {
            let mut start: u16 = a.trim().parse().ok()?;
            let mut end: u16 = b.trim().parse().ok()?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            result.push((start, end));
        } else {
            let p: u16 = part.parse().ok()?;
            result.push((p, p));
        }
    }
    if result.is_empty() {
        return None;
    }
    normalize_ports(&mut result);
    Some(result)
}

fn normalize_ports(u: &mut Vec<(u16, u16)>) {
    if u.is_empty() {
        return;
    }
    u.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut out = vec![u[0]];
    for &(start, end) in u.iter().skip(1) {
        let last = out.last_mut().unwrap();
        if u32::from(start) <= u32::from(last.1) + 1 {
            if end > last.1 {
                last.1 = end;
            }
        } else {
            out.push((start, end));
        }
    }
    *u = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockStream {
        data: Mutex<Vec<u8>>,
        delay: Option<Duration>,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(data),
                delay: None,
            }
        }
        fn blocking(delay: Duration) -> Self {
            Self {
                data: Mutex::new(Vec::new()),
                delay: Some(delay),
            }
        }
    }

    #[async_trait]
    impl HyTcpStream for MockStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
            if let Some(d) = self.delay {
                tokio::time::sleep(d).await;
                return Ok(0);
            }
            let mut data = self.data.lock().unwrap();
            if data.is_empty() {
                return Ok(0);
            }
            let n = std::cmp::min(buf.len(), data.len());
            buf[..n].copy_from_slice(&data[..n]);
            data.drain(..n);
            Ok(n)
        }
        async fn write(&mut self, _buf: &[u8]) -> Result<usize, Error> {
            Ok(0)
        }
        async fn close(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn check_skips_speedtest() {
        let s = Sniffer::default();
        assert!(!s.check(false, "@speedtest"));
        assert!(!s.check(false, "@SpeedTest"));
        assert!(!s.check(true, "@speedtest:0"));
    }

    #[test]
    fn check_rewrite_domain_false_skips_domain() {
        let s = Sniffer {
            rewrite_domain: false,
            ..Default::default()
        };
        assert!(s.check(false, "1.1.1.1:80"));
        assert!(!s.check(false, "example.com:443"));
    }

    #[test]
    fn check_ports() {
        let mut s = Sniffer {
            rewrite_domain: true,
            tcp_ports: Some(vec![(80, 80)]),
            udp_ports: Some(vec![(443, 443)]),
            ..Default::default()
        };
        assert!(s.check(false, "google.com:80"));
        assert!(!s.check(false, "google.com:443"));
        assert!(s.check(true, "google.com:443"));
        assert!(!s.check(true, "google.com:80"));
        s.tcp_ports = None;
        assert!(s.check(false, "google.com:443"));
    }

    #[tokio::test]
    async fn http_host_rewrite() {
        let sniffer = Sniffer {
            timeout: Duration::from_secs(1),
            ..Default::default()
        };
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n";
        let mut stream = MockStream::new(req.to_vec());
        let mut addr = "1.1.1.1:80".to_string();
        let putback = sniffer.tcp(&mut stream, &mut addr).await.unwrap();
        assert_eq!(addr, "example.com:80");
        assert!(putback.starts_with(b"GET"));
    }

    #[tokio::test]
    async fn tls_sni_rewrite() {
        let sniffer = Sniffer {
            timeout: Duration::from_secs(1),
            ..Default::default()
        };
        let hello = craft_client_hello_with_sni("example.org");
        let mut stream = MockStream::new(hello);
        let mut addr = "1.1.1.1:443".to_string();
        let putback = sniffer.tcp(&mut stream, &mut addr).await.unwrap();
        assert_eq!(addr, "example.org:443");
        assert!(putback.len() >= 5);
        assert_eq!(putback[0], 0x16);
    }

    #[tokio::test]
    async fn tcp_timeout_returns_empty() {
        let sniffer = Sniffer {
            timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let mut stream = MockStream::blocking(Duration::from_secs(2));
        let mut addr = "66.66.66.66:66".to_string();
        let putback = sniffer.tcp(&mut stream, &mut addr).await.unwrap();
        assert!(putback.is_empty());
        assert_eq!(addr, "66.66.66.66:66");
    }

    #[tokio::test]
    async fn udp_quic_sni() {
        let sniffer = Sniffer::default();
        let pkt = base64_decode(include_str!("quic_test_pkt.b64").trim()).unwrap();
        let mut addr = "2.3.4.5:443".to_string();
        sniffer.udp(&pkt, &mut addr).await.unwrap();
        assert_eq!(addr, "www.notion.so:443");
    }

    fn craft_client_hello_with_sni(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        // SNI extension body: list_len(2) + name_type(1) + name_len(2) + name
        let mut sni_ext = Vec::new();
        let name_entry_len = 1 + 2 + sni_bytes.len();
        sni_ext.extend_from_slice(&((name_entry_len) as u16).to_be_bytes());
        sni_ext.push(0); // host_name
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // type server_name
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id empty
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x00, 0x2f]); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.push(1); // compression methods len
        body.push(0); // null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn base64_decode(s: &str) -> Option<Vec<u8>> {
        fn d(c: u8) -> Option<u8> {
            match c {
                b'A'..=b'Z' => Some(c - b'A'),
                b'a'..=b'z' => Some(c - b'a' + 26),
                b'0'..=b'9' => Some(c - b'0' + 52),
                b'+' => Some(62),
                b'/' => Some(63),
                _ => None,
            }
        }
        let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let (a, b, c, e) = (bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
            let x = d(a)? as u32;
            let y = d(b)? as u32;
            out.push(((x << 2) | (y >> 4)) as u8);
            if c != b'=' {
                let z = d(c)? as u32;
                out.push((((y & 0xf) << 4) | (z >> 2)) as u8);
                if e != b'=' {
                    let w = d(e)? as u32;
                    out.push((((z & 0x3) << 6) | w) as u8);
                }
            }
            i += 4;
        }
        Some(out)
    }
}
