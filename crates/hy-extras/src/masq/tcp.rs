//! TCP HTTP/1 (+ optional HTTPS) masquerade façade with forced `Alt-Svc`.
//!
//! WebSocket: when `proxy` is set and the request has `Upgrade: websocket`, the
//! raw request is TCP-tunneled to the proxy backend (aligns official Hijacker).

use super::proxy::ProxyMasq;
use hy_core::server::{MasqHandler, MasqResponse};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// TCP masquerade servers (HTTP and/or HTTPS).
pub struct MasqTcpServer {
    pub quic_port: u16,
    pub https_port: u16,
    pub handler: Arc<dyn MasqHandler>,
    pub force_https: bool,
    /// When set, `Upgrade: websocket` is tunneled to this reverse-proxy backend.
    pub proxy: Option<Arc<ProxyMasq>>,
    /// PEM bytes for listenHTTPS (same cert/key as QUIC).
    pub tls_cert_pem: Vec<u8>,
    pub tls_key_pem: Vec<u8>,
}

impl MasqTcpServer {
    pub fn alt_svc(&self) -> String {
        format!("h3=\":{}\"; ma=2592000", self.quic_port)
    }

    pub async fn listen_http(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let ln = TcpListener::bind(addr).await?;
        let local = ln.local_addr()?;
        let me = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let Ok((s, peer)) = ln.accept().await else {
                    break;
                };
                let me = Arc::clone(&me);
                tokio::spawn(async move {
                    let _ = me.serve_tcp(s, peer, false).await;
                });
            }
        });
        Ok(local)
    }

    pub async fn listen_https(self: &Arc<Self>, addr: SocketAddr) -> std::io::Result<SocketAddr> {
        let cfg = build_server_tls(&self.tls_cert_pem, &self.tls_key_pem)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let ln = TcpListener::bind(addr).await?;
        let local = ln.local_addr()?;
        let me = Arc::clone(self);
        let tls_cfg = Arc::new(cfg);
        tokio::spawn(async move {
            loop {
                let Ok((s, peer)) = ln.accept().await else {
                    break;
                };
                let me = Arc::clone(&me);
                let tls_cfg = Arc::clone(&tls_cfg);
                tokio::spawn(async move {
                    let Ok(mut tls) = ServerTls::handshake(s, tls_cfg).await else {
                        return;
                    };
                    let _ = me.serve_tls(&mut tls, peer).await;
                });
            }
        });
        Ok(local)
    }

    async fn serve_tcp(
        self: Arc<Self>,
        mut s: TcpStream,
        peer: SocketAddr,
        is_https: bool,
    ) -> std::io::Result<()> {
        let mut buf = vec![0u8; 16384];
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        self.dispatch(&mut s, &buf[..n], peer, is_https).await
    }

    async fn serve_tls(
        self: Arc<Self>,
        s: &mut ServerTls,
        peer: SocketAddr,
    ) -> std::io::Result<()> {
        let mut buf = vec![0u8; 16384];
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        self.dispatch_tls(s, &buf[..n], peer).await
    }

    async fn dispatch(
        self: &Arc<Self>,
        s: &mut TcpStream,
        raw: &[u8],
        peer: SocketAddr,
        is_https: bool,
    ) -> std::io::Result<()> {
        let parsed = parse_request(raw)?;
        if !is_https && self.force_https {
            return write_force_https(s, &parsed.host, self.https_port, &parsed.target, &self.alt_svc())
                .await;
        }
        if parsed.upgrade_ws && parsed.connection_upgrade {
            if let Some(proxy) = &self.proxy {
                return tunnel_websocket_tcp(s, raw, proxy, &self.alt_svc()).await;
            }
        }
        let resp = self
            .handler
            .handle(&parsed.method, &parsed.host, &parsed.target)
            .await;
        write_masq_response_tcp(
            s,
            &resp,
            &self.alt_svc(),
            parsed.method.eq_ignore_ascii_case("HEAD"),
        )
        .await?;
        let _ = peer;
        Ok(())
    }

    async fn dispatch_tls(
        self: &Arc<Self>,
        s: &mut ServerTls,
        raw: &[u8],
        peer: SocketAddr,
    ) -> std::io::Result<()> {
        let parsed = parse_request(raw)?;
        if parsed.upgrade_ws && parsed.connection_upgrade {
            if let Some(proxy) = &self.proxy {
                return tunnel_websocket_tls(s, raw, proxy, &self.alt_svc()).await;
            }
        }
        let resp = self
            .handler
            .handle(&parsed.method, &parsed.host, &parsed.target)
            .await;
        write_masq_response_tls(
            s,
            &resp,
            &self.alt_svc(),
            parsed.method.eq_ignore_ascii_case("HEAD"),
        )
        .await?;
        let _ = peer;
        Ok(())
    }
}

struct ParsedReq {
    method: String,
    target: String,
    host: String,
    upgrade_ws: bool,
    connection_upgrade: bool,
}

fn parse_request(raw: &[u8]) -> std::io::Result<ParsedReq> {
    let text = String::from_utf8_lossy(raw);
    let Some(header_end) = text.find("\r\n\r\n") else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "incomplete request",
        ));
    };
    let head = &text[..header_end];
    let mut lines = head.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let mut host = String::new();
    let mut upgrade_ws = false;
    let mut connection_upgrade = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            if k.eq_ignore_ascii_case("host") {
                host = v.to_string();
            } else if k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
                upgrade_ws = true;
            } else if k.eq_ignore_ascii_case("connection")
                && v.to_ascii_lowercase().contains("upgrade")
            {
                connection_upgrade = true;
            }
        }
    }
    Ok(ParsedReq {
        method,
        target,
        host,
        upgrade_ws,
        connection_upgrade,
    })
}

async fn write_force_https(
    s: &mut TcpStream,
    host: &str,
    https_port: u16,
    target: &str,
    alt_svc: &str,
) -> std::io::Result<()> {
    let loc = force_https_location(host, https_port, target);
    let body = format!("Redirecting to {loc}\n");
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {loc}\r\nAlt-Svc: {alt_svc}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    s.write_all(resp.as_bytes()).await
}

fn format_masq_head(resp: &MasqResponse, alt_svc: &str) -> String {
    let mut out = format!("HTTP/1.1 {} \r\n", resp.status);
    let mut has_cl = false;
    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("alt-svc") {
            continue;
        }
        if k.eq_ignore_ascii_case("content-length") {
            has_cl = true;
        }
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    out.push_str("Alt-Svc: ");
    out.push_str(alt_svc);
    out.push_str("\r\n");
    if !has_cl {
        out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

async fn write_masq_response_tcp(
    s: &mut TcpStream,
    resp: &MasqResponse,
    alt_svc: &str,
    head_only: bool,
) -> std::io::Result<()> {
    let head = format_masq_head(resp, alt_svc);
    s.write_all(head.as_bytes()).await?;
    if !head_only && !resp.body.is_empty() {
        s.write_all(&resp.body).await?;
    }
    Ok(())
}

async fn write_masq_response_tls(
    s: &mut ServerTls,
    resp: &MasqResponse,
    alt_svc: &str,
    head_only: bool,
) -> std::io::Result<()> {
    let head = format_masq_head(resp, alt_svc);
    s.write_all(head.as_bytes()).await?;
    if !head_only && !resp.body.is_empty() {
        s.write_all(&resp.body).await?;
    }
    Ok(())
}

fn force_https_location(host: &str, https_port: u16, target: &str) -> String {
    let host_only = if host.starts_with('[') {
        host.find(']')
            .map(|i| host[..=i].to_string())
            .unwrap_or_else(|| host.to_string())
    } else {
        host.rsplit_once(':')
            .map(|(h, _)| h.to_string())
            .unwrap_or_else(|| host.to_string())
    };
    let port = if https_port == 0 { 443 } else { https_port };
    if port == 443 {
        format!("https://{host_only}{target}")
    } else {
        format!("https://{host_only}:{port}{target}")
    }
}

async fn tunnel_websocket_tcp(
    client: &mut TcpStream,
    raw_req: &[u8],
    proxy: &ProxyMasq,
    alt_svc: &str,
) -> std::io::Result<()> {
    let mut up = proxy
        .dial_raw()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    let req = if proxy.rewrite_host {
        rewrite_host_header(raw_req, &proxy.upstream_host_header())
    } else {
        raw_req.to_vec()
    };
    up.write_all(&req).await?;
    relay_ws(client, &mut up, alt_svc).await
}

async fn tunnel_websocket_tls(
    client: &mut ServerTls,
    raw_req: &[u8],
    proxy: &ProxyMasq,
    alt_svc: &str,
) -> std::io::Result<()> {
    let mut up = proxy
        .dial_raw()
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e))?;
    let req = if proxy.rewrite_host {
        rewrite_host_header(raw_req, &proxy.upstream_host_header())
    } else {
        raw_req.to_vec()
    };
    up.write_all(&req).await?;
    // Read upstream headers, inject Alt-Svc, then bidirectional copy.
    let (head, rest) = read_http_head(&mut up).await?;
    let out_head = inject_alt_svc(&head, alt_svc);
    client.write_all(out_head.as_bytes()).await?;
    if !rest.is_empty() {
        client.write_all(&rest).await?;
    }
    let mut cbuf = [0u8; 8192];
    let mut ubuf = [0u8; 8192];
    loop {
        tokio::select! {
            n = client.read(&mut cbuf) => {
                let n = n?;
                if n == 0 { break; }
                up.write_all(&cbuf[..n]).await?;
            }
            n = up.read(&mut ubuf) => {
                let n = n?;
                if n == 0 { break; }
                client.write_all(&ubuf[..n]).await?;
            }
        }
    }
    Ok(())
}

async fn relay_ws(
    client: &mut TcpStream,
    up: &mut super::proxy::Upstream,
    alt_svc: &str,
) -> std::io::Result<()> {
    let (head, rest) = read_http_head(up).await?;
    let out_head = inject_alt_svc(&head, alt_svc);
    client.write_all(out_head.as_bytes()).await?;
    if !rest.is_empty() {
        client.write_all(&rest).await?;
    }
    let mut cbuf = [0u8; 8192];
    let mut ubuf = [0u8; 8192];
    loop {
        tokio::select! {
            n = client.read(&mut cbuf) => {
                let n = n?;
                if n == 0 { break; }
                up.write_all(&cbuf[..n]).await?;
            }
            n = up.read(&mut ubuf) => {
                let n = n?;
                if n == 0 { break; }
                client.write_all(&ubuf[..n]).await?;
            }
        }
    }
    Ok(())
}

async fn read_http_head(
    up: &mut super::proxy::Upstream,
) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = up.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "upstream closed",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let he = i + 4;
            let head = String::from_utf8_lossy(&buf[..he]).to_string();
            let rest = buf[he..].to_vec();
            return Ok((head, rest));
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
}

fn inject_alt_svc(head: &str, alt_svc: &str) -> String {
    let mut out = String::new();
    let mut first = true;
    for line in head.split("\r\n") {
        if first {
            out.push_str(line);
            out.push_str("\r\n");
            first = false;
            continue;
        }
        if line.is_empty() {
            break;
        }
        if line.to_ascii_lowercase().starts_with("alt-svc:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Alt-Svc: ");
    out.push_str(alt_svc);
    out.push_str("\r\n\r\n");
    out
}

fn rewrite_host_header(raw: &[u8], new_host: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let Some(he) = text.find("\r\n\r\n") else {
        return raw.to_vec();
    };
    let mut out = String::new();
    let mut replaced = false;
    for (i, line) in text[..he].split("\r\n").enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        if line.to_ascii_lowercase().starts_with("host:") {
            out.push_str("Host: ");
            out.push_str(new_host);
            replaced = true;
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        out.push_str("\r\nHost: ");
        out.push_str(new_host);
    }
    out.push_str("\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&raw[he + 4..]);
    bytes
}

fn build_server_tls(cert_pem: &[u8], key_pem: &[u8]) -> Result<ServerConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut certs = Vec::new();
    let mut reader = std::io::Cursor::new(cert_pem);
    for item in rustls_pemfile::certs(&mut reader) {
        let der = item.map_err(|e| e.to_string())?;
        certs.push(CertificateDer::from(der));
    }
    if certs.is_empty() {
        return Err("no certificates in PEM".into());
    }
    let mut key_reader = std::io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no private key in PEM".to_string())?;
    let key = PrivateKeyDer::try_from(key).map_err(|e| e.to_string())?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())
}

struct ServerTls {
    io: TcpStream,
    sess: rustls::ServerConnection,
    plain_buf: Vec<u8>,
}

impl ServerTls {
    async fn handshake(mut io: TcpStream, cfg: Arc<ServerConfig>) -> std::io::Result<Self> {
        let mut sess = rustls::ServerConnection::new(cfg)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        loop {
            while sess.wants_write() {
                let mut buf = Vec::new();
                sess.write_tls(&mut buf)?;
                if buf.is_empty() {
                    break;
                }
                io.write_all(&buf).await?;
            }
            if !sess.is_handshaking() {
                break;
            }
            let mut tls_buf = [0u8; 4096];
            let n = io.read(&mut tls_buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS handshake closed",
                ));
            }
            let mut cur = std::io::Cursor::new(&tls_buf[..n]);
            while cur.position() < n as u64 {
                let before = cur.position();
                sess.read_tls(&mut cur)?;
                if cur.position() == before {
                    break;
                }
                sess.process_new_packets()
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
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

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.sess.writer().write_all(buf)?;
        self.flush_tls().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::masq::FileMasq;
    use std::fs;

    #[tokio::test]
    async fn listen_http_serves_file_with_alt_svc() {
        let dir = std::env::temp_dir().join(format!("hy-masq-tcp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"hello-masq").unwrap();

        let handler: Arc<dyn MasqHandler> = Arc::new(FileMasq::new(&dir));
        let srv = Arc::new(MasqTcpServer {
            quic_port: 18443,
            https_port: 443,
            handler,
            force_https: false,
            proxy: None,
            tls_cert_pem: Vec::new(),
            tls_key_pem: Vec::new(),
        });
        let addr = srv
            .listen_http("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("hello-masq"), "{text}");
        assert!(text.contains("Alt-Svc:"), "{text}");
        assert!(text.contains("h3=\":"), "{text}");
        assert!(text.contains("ma=2592000"), "{text}");
        assert!(text.contains("h3=\":18443\""), "{text}");

        let _ = fs::remove_dir_all(&dir);
    }
}
