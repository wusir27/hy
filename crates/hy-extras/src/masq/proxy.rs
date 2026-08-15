//! `masquerade.type: proxy` — reverse proxy for GET/HEAD (WS tunnel via [`ProxyMasq::dial_raw`]).

use async_trait::async_trait;
use bytes::Bytes;
use hy_core::error::Error;
use hy_core::server::{MasqHandler, MasqResponse};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ProxyMasq {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_prefix: String,
    pub rewrite_host: bool,
    pub x_forwarded: bool,
    pub insecure: bool,
}

impl ProxyMasq {
    pub fn new(
        url: &str,
        rewrite_host: bool,
        x_forwarded: bool,
        insecure: bool,
    ) -> Result<Self, Error> {
        let url = url.trim();
        if url.is_empty() {
            return Err(Error::config("masquerade.proxy.url", "empty proxy url"));
        }
        let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = url.strip_prefix("http://") {
            ("http", r)
        } else {
            let scheme = url.split("://").next().unwrap_or("");
            return Err(Error::config(
                "masquerade.proxy.url",
                format!("unsupported protocol scheme \"{scheme}\""),
            ));
        };
        let (host_port, path_prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
            None => (rest, String::new()),
        };
        if host_port.is_empty() {
            return Err(Error::config("masquerade.proxy.url", "empty proxy url"));
        }
        let (host, port_opt) = split_host_port(host_port)?;
        let port = port_opt.unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Self {
            scheme: scheme.into(),
            host,
            port,
            path_prefix,
            rewrite_host,
            x_forwarded,
            insecure,
        })
    }

    pub fn connect_addr(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn upstream_path(&self, path: &str) -> String {
        let path = if path.is_empty() { "/" } else { path };
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if self.path_prefix.is_empty() {
            path
        } else {
            format!("{}{}", self.path_prefix, path)
        }
    }

    pub fn upstream_host_header(&self) -> String {
        if (self.scheme == "https" && self.port == 443) || (self.scheme == "http" && self.port == 80)
        {
            if self.host.contains(':') && !self.host.starts_with('[') {
                format!("[{}]", self.host)
            } else {
                self.host.clone()
            }
        } else if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Dial upstream for WebSocket TCP tunnel (plain or TLS).
    pub async fn dial_raw(&self) -> Result<Upstream, String> {
        dial_upstream(self).await
    }

    pub async fn forward(
        &self,
        method: &str,
        incoming_host: &str,
        path: &str,
        client_addr: Option<&str>,
    ) -> Result<MasqResponse, String> {
        let up_path = self.upstream_path(path);
        let host_hdr = if self.rewrite_host {
            self.upstream_host_header()
        } else if incoming_host.is_empty() {
            self.upstream_host_header()
        } else {
            incoming_host.to_string()
        };

        let mut req = format!(
            "{method} {up_path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n"
        );
        if self.x_forwarded {
            let proto = if self.scheme == "https" { "https" } else { "http" };
            req.push_str(&format!("X-Forwarded-Proto: {proto}\r\n"));
            if let Some(addr) = client_addr {
                // Prefer IP without port when host:port
                let ip = strip_host_port(addr);
                req.push_str(&format!("X-Forwarded-For: {ip}\r\n"));
            }
        }
        req.push_str("\r\n");

        let mut stream = dial_upstream(self).await?;
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| e.to_string())?;

        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
                .await
                .map_err(|_| "proxy read timeout".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 8 * 1024 * 1024 {
                break;
            }
        }
        parse_http_response(&buf)
    }
}

#[async_trait]
impl MasqHandler for ProxyMasq {
    async fn handle(&self, method: &str, host: &str, path: &str) -> MasqResponse {
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            return MasqResponse {
                status: 405,
                headers: vec![],
                body: Bytes::new(),
            };
        }
        match self.forward(method, host, path, None).await {
            Ok(r) => r,
            Err(_) => MasqResponse {
                status: 502,
                headers: vec![],
                body: Bytes::new(),
            },
        }
    }
}

pub enum Upstream {
    Tcp(TcpStream),
    Tls(UpstreamTls),
}

impl Upstream {
    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf).await,
            Self::Tls(s) => s.read(buf).await,
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf).await,
            Self::Tls(s) => s.write_all(buf).await,
        }
    }
}

async fn dial_upstream(p: &ProxyMasq) -> Result<Upstream, String> {
    let addr = p.connect_addr();
    let tcp = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&addr)).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(e.to_string()),
        Err(_) => return Err("proxy dial timeout".into()),
    };
    if p.scheme == "https" {
        Ok(Upstream::Tls(
            UpstreamTls::connect(tcp, &p.host, p.insecure).await?,
        ))
    } else {
        Ok(Upstream::Tcp(tcp))
    }
}

fn parse_http_response(raw: &[u8]) -> Result<MasqResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "incomplete proxy response".to_string())?;
    let head = std::str::from_utf8(&raw[..header_end]).map_err(|e| e.to_string())?;
    let body = raw[header_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sp = status_line.split_whitespace();
    let _ = sp.next();
    let status: u16 = sp.next().and_then(|s| s.parse().ok()).unwrap_or(502);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            if k.eq_ignore_ascii_case("transfer-encoding")
                || k.eq_ignore_ascii_case("connection")
                || k.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            headers.push((k.to_string(), v.trim().to_string()));
        }
    }
    Ok(MasqResponse {
        status,
        headers,
        body: Bytes::from(body),
    })
}

fn strip_host_port(addr: &str) -> &str {
    if addr.starts_with('[') {
        addr.find(']')
            .map(|i| &addr[1..i])
            .unwrap_or(addr)
    } else {
        addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
    }
}

fn split_host_port(s: &str) -> Result<(String, Option<u16>), Error> {
    if s.starts_with('[') {
        let end = s
            .find(']')
            .ok_or_else(|| Error::config("masquerade.proxy.url", "invalid proxy url host"))?;
        let host = s[1..end].to_string();
        if s[end + 1..].starts_with(':') {
            let port: u16 = s[end + 2..]
                .parse()
                .map_err(|_| Error::config("masquerade.proxy.url", "invalid proxy url port"))?;
            Ok((host, Some(port)))
        } else {
            Ok((host, None))
        }
    } else if let Some((h, p)) = s.rsplit_once(':') {
        if h.contains(':') {
            Ok((s.to_string(), None))
        } else {
            let port: u16 = p
                .parse()
                .map_err(|_| Error::config("masquerade.proxy.url", "invalid proxy url port"))?;
            Ok((h.to_string(), Some(port)))
        }
    } else {
        Ok((s.to_string(), None))
    }
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
        return Ok(ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Skip))
            .with_no_client_auth());
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

pub struct UpstreamTls {
    io: TcpStream,
    sess: ClientConnection,
    plain_buf: Vec<u8>,
}

impl UpstreamTls {
    async fn connect(mut io: TcpStream, sni: &str, insecure: bool) -> Result<Self, String> {
        let cfg = Arc::new(build_tls_config(insecure)?);
        let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
        let mut sess = ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
        loop {
            while sess.wants_write() {
                let mut buf = Vec::new();
                sess.write_tls(&mut buf).map_err(|e| e.to_string())?;
                if buf.is_empty() {
                    break;
                }
                io.write_all(&buf).await.map_err(|e| e.to_string())?;
            }
            if !sess.is_handshaking() {
                break;
            }
            let mut tls_buf = [0u8; 4096];
            let n = io.read(&mut tls_buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("TLS handshake closed".into());
            }
            let mut cur = std::io::Cursor::new(&tls_buf[..n]);
            while cur.position() < n as u64 {
                let before = cur.position();
                sess.read_tls(&mut cur).map_err(|e| e.to_string())?;
                if cur.position() == before {
                    break;
                }
                sess.process_new_packets().map_err(|e| e.to_string())?;
            }
        }
        Ok(Self {
            io,
            sess,
            plain_buf: Vec::new(),
        })
    }

    async fn flush_tls(&mut self) -> std::io::Result<()> {
        while self.sess.wants_write() {
            let mut buf = Vec::new();
            self.sess.write_tls(&mut buf)?;
            if buf.is_empty() {
                break;
            }
            self.io.write_all(&buf).await?;
        }
        Ok(())
    }

    async fn read_tls_more(&mut self) -> std::io::Result<()> {
        let mut tls_buf = [0u8; 4096];
        let n = self.io.read(&mut tls_buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS closed",
            ));
        }
        let mut cur = std::io::Cursor::new(&tls_buf[..n]);
        while (cur.position() as usize) < n {
            let before = cur.position();
            self.sess.read_tls(&mut cur)?;
            if cur.position() == before {
                break;
            }
            self.sess
                .process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        }
        Ok(())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.plain_buf.is_empty() {
                let n = buf.len().min(self.plain_buf.len());
                buf[..n].copy_from_slice(&self.plain_buf[..n]);
                self.plain_buf.drain(..n);
                return Ok(n);
            }
            let mut tmp = [0u8; 4096];
            match self.sess.reader().read(&mut tmp) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    let take = n.min(buf.len());
                    buf[..take].copy_from_slice(&tmp[..take]);
                    if take < n {
                        self.plain_buf.extend_from_slice(&tmp[take..n]);
                    }
                    return Ok(take);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.read_tls_more().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    pub async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.sess.writer().write_all(buf)?;
        self.flush_tls().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_bad_scheme() {
        assert!(ProxyMasq::new("", false, false, false).is_err());
        match ProxyMasq::new("ftp://x", false, false, false) {
            Err(Error::Config { field, .. }) => assert_eq!(field, "masquerade.proxy.url"),
            Err(e) => panic!("expected config, got {e}"),
            Ok(_) => panic!("expected error"),
        }
    }

    #[test]
    fn parses_http_url() {
        let p = ProxyMasq::new("http://example.com:8080/pfx", true, true, false).unwrap();
        assert_eq!(p.scheme, "http");
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 8080);
        assert_eq!(p.path_prefix, "/pfx");
        assert_eq!(p.upstream_path("/a?q=1"), "/pfx/a?q=1");
    }
}
