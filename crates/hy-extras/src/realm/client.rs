//! HTTP signaling client (official `client.go` paths — do not invent).

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub use crate::realm::punch::{
    PunchMetadata, PUNCH_NONCE_SIZE, PUNCH_OBFS_KEY_SIZE,
};

const MAX_ERROR_BODY: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub session_id: String,
    pub ttl: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ttl: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeartbeatRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub meta: PunchMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub meta: PunchMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PunchEvent {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub meta: PunchMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ErrorResponse {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct StatusError {
    pub status_code: u16,
    pub response: ErrorResponse,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.response.error.is_empty() || !self.response.message.is_empty() {
            write!(
                f,
                "realm server returned {}: {}: {}",
                self.status_code, self.response.error, self.response.message
            )
        } else {
            write!(f, "realm server returned {}", self.status_code)
        }
    }
}
impl std::error::Error for StatusError {}

#[derive(Clone)]
pub struct RealmClient {
    base_url: String,
    token: String,
    insecure: bool,
}

impl RealmClient {
    pub fn new(base_url: &str, token: &str, insecure: bool) -> Result<Self, String> {
        if token.is_empty() {
            return Err("token is required".into());
        }
        let base = base_url.trim_end_matches('/').to_string();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err("base URL scheme must be http or https".into());
        }
        Ok(Self {
            base_url: base,
            token: token.to_string(),
            insecure,
        })
    }

    pub fn from_addr(addr: &crate::realm::Addr, insecure: bool) -> Result<Self, String> {
        Self::new(&addr.base_url(), &addr.token, insecure)
    }

    pub async fn register(
        &self,
        realm_id: &str,
        addresses: &[String],
    ) -> Result<RegisterResponse, Box<dyn std::error::Error + Send + Sync>> {
        #[derive(Serialize)]
        struct Body<'a> {
            addresses: &'a [String],
        }
        let body = self
            .exchange(
                "POST",
                realm_id,
                "",
                &self.token,
                Some(&Body { addresses }),
                200,
            )
            .await?;
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn deregister(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = self
            .exchange::<()>("DELETE", realm_id, "", session_id, None, 204)
            .await?;
        Ok(())
    }

    pub async fn heartbeat(
        &self,
        realm_id: &str,
        session_id: &str,
        req: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, Box<dyn std::error::Error + Send + Sync>> {
        let body = self
            .exchange("POST", realm_id, "heartbeat", session_id, Some(req), 200)
            .await?;
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn connect(
        &self,
        realm_id: &str,
        req: &ConnectRequest,
    ) -> Result<ConnectResponse, Box<dyn std::error::Error + Send + Sync>> {
        let body = self
            .exchange("POST", realm_id, "connect", &self.token, Some(req), 200)
            .await?;
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn connect_response(
        &self,
        realm_id: &str,
        session_id: &str,
        nonce: &str,
        addresses: &[String],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        #[derive(Serialize)]
        struct Body<'a> {
            addresses: &'a [String],
        }
        let sub = format!("connects/{}", path_escape(nonce));
        let _ = self
            .exchange("POST", realm_id, &sub, session_id, Some(&Body { addresses }), 204)
            .await?;
        Ok(())
    }

    /// One-shot SSE read of buffered events (for tests / short streams).
    pub async fn events_once(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<EventStream, Box<dyn std::error::Error + Send + Sync>> {
        let path = join_url_path(&["v1", &path_escape(realm_id), "events"]);
        let (status, _headers, body) = self.raw_request("GET", &path, session_id, None).await?;
        if status != 200 {
            return Err(Box::new(decode_status_error(status, &body)));
        }
        Ok(EventStream { buf: body, pos: 0 })
    }

    async fn exchange<In: Serialize>(
        &self,
        method: &str,
        realm_id: &str,
        sub_path: &str,
        bearer: &str,
        body: Option<&In>,
        expected: u16,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        if realm_id.is_empty() || realm_id.contains('/') {
            return Err("realm id must be a single path segment".into());
        }
        let path = join_url_path(&["v1", &path_escape(realm_id), sub_path]);
        let payload = match body {
            Some(b) => Some(serde_json::to_vec(b)?),
            None => None,
        };
        let (status, _headers, resp_body) = self
            .raw_request(method, &path, bearer, payload.as_deref())
            .await?;
        if status != expected {
            return Err(Box::new(decode_status_error(status, &resp_body)));
        }
        Ok(resp_body)
    }

    async fn raw_request(
        &self,
        method: &str,
        path: &str,
        bearer: &str,
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>>
    {
        let (scheme, host_port) = split_base(&self.base_url)?;
        let (host, port) =
            split_host_port_default(host_port, if scheme == "https" { 443 } else { 80 })?;
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await?;
        let mut up = if scheme == "https" {
            Upstream::Tls(UpstreamTls::connect(tcp, &host, self.insecure).await?)
        } else {
            Upstream::Tcp(tcp)
        };

        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_port}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n"
        );
        if let Some(b) = body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        up.write_all(req.as_bytes()).await?;
        if let Some(b) = body {
            up.write_all(b).await?;
        }

        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = up.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 4 * 1024 * 1024 {
                break;
            }
        }
        parse_http_response(&buf)
    }
}

pub struct EventStream {
    buf: Vec<u8>,
    pos: usize,
}

impl EventStream {
    pub fn next_event(
        &mut self,
    ) -> Result<Option<PunchEvent>, Box<dyn std::error::Error + Send + Sync>> {
        let text = std::str::from_utf8(&self.buf[self.pos..])?;
        let mut event_name = String::new();
        let mut data = String::new();
        let mut consumed = 0usize;
        for line in text.split_inclusive('\n') {
            consumed += line.len();
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if event_name.is_empty() && data.is_empty() {
                    continue;
                }
                let done = event_name == "punch";
                let payload = std::mem::take(&mut data);
                event_name.clear();
                self.pos += consumed;
                if done {
                    let ev: PunchEvent = serde_json::from_str(&payload)?;
                    return Ok(Some(ev));
                }
                continue;
            }
            if line.starts_with(':') {
                continue;
            }
            if let Some((field, value)) = line.split_once(':') {
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "event" => event_name = value.to_string(),
                    "data" => {
                        if !data.is_empty() {
                            data.push('\n');
                        }
                        data.push_str(value);
                    }
                    _ => {}
                }
            }
        }
        Ok(None)
    }
}

fn decode_status_error(status: u16, body: &[u8]) -> StatusError {
    let limited = if body.len() > MAX_ERROR_BODY {
        &body[..MAX_ERROR_BODY]
    } else {
        body
    };
    let response = serde_json::from_slice(limited).unwrap_or_default();
    StatusError {
        status_code: status,
        response,
    }
}

fn join_url_path(parts: &[&str]) -> String {
    let mut joined = Vec::new();
    for p in parts {
        let t = p.trim_matches('/');
        if !t.is_empty() {
            joined.push(t);
        }
    }
    format!("/{}", joined.join("/"))
}

fn path_escape(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn split_base(base: &str) -> Result<(&str, &str), String> {
    if let Some(r) = base.strip_prefix("https://") {
        Ok(("https", r))
    } else if let Some(r) = base.strip_prefix("http://") {
        Ok(("http", r))
    } else {
        Err("bad base url".into())
    }
}

fn split_host_port_default(host_port: &str, default_port: u16) -> Result<(String, u16), String> {
    if host_port.starts_with('[') {
        let end = host_port.find(']').ok_or("bad host")?;
        let host = host_port[1..end].to_string();
        let rest = &host_port[end + 1..];
        if let Some(p) = rest.strip_prefix(':') {
            Ok((host, p.parse().map_err(|_| "bad port")?))
        } else {
            Ok((host, default_port))
        }
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        if h.contains(':') {
            Ok((host_port.to_string(), default_port))
        } else {
            Ok((h.to_string(), p.parse().map_err(|_| "bad port")?))
        }
    } else {
        Ok((host_port.to_string(), default_port))
    }
}

fn parse_http_response(
    raw: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete http response")?;
    let head = std::str::from_utf8(&raw[..header_end])?;
    let body = raw[header_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sp = status_line.split_whitespace();
    let _ = sp.next();
    let status: u16 = sp.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers, body))
}

enum Upstream {
    Tcp(TcpStream),
    Tls(UpstreamTls),
}

impl Upstream {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf).await,
            Self::Tls(s) => s.read(buf).await,
        }
    }
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(buf).await,
            Self::Tls(s) => s.write_all(buf).await,
        }
    }
}

struct UpstreamTls {
    io: TcpStream,
    conn: ClientConnection,
}

impl UpstreamTls {
    async fn connect(mut io: TcpStream, sni: &str, insecure: bool) -> Result<Self, String> {
        ensure_crypto();
        let config = build_tls_config(insecure)?;
        let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
        let mut conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
        handshake(&mut io, &mut conn).await?;
        Ok(Self { io, conn })
    }

    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            // Drain plaintext without holding Reader across await.
            {
                let mut reader = self.conn.reader();
                match reader.read(buf) {
                    Ok(0) => {}
                    Ok(n) => return Ok(n),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e),
                }
            }
            flush_tls(&mut self.io, &mut self.conn).await?;
            let mut tmp = [0u8; 4096];
            let n = self.io.read(&mut tmp).await?;
            if n == 0 {
                return Ok(0);
            }
            let mut cur = std::io::Cursor::new(&tmp[..n]);
            self.conn.read_tls(&mut cur)?;
            self.conn
                .process_new_packets()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut off = 0;
        while off < buf.len() {
            let n = {
                let mut writer = self.conn.writer();
                match writer.write(&buf[off..]) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                    Err(e) => return Err(e),
                }
            };
            if n == 0 {
                flush_tls(&mut self.io, &mut self.conn).await?;
            } else {
                off += n;
            }
        }
        flush_tls(&mut self.io, &mut self.conn).await
    }
}

async fn handshake(io: &mut TcpStream, conn: &mut ClientConnection) -> Result<(), String> {
    loop {
        while conn.wants_write() {
            let mut buf = Vec::new();
            conn.write_tls(&mut buf).map_err(|e| e.to_string())?;
            if !buf.is_empty() {
                io.write_all(&buf).await.map_err(|e| e.to_string())?;
            }
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        if conn.wants_read() {
            let mut tmp = [0u8; 4096];
            let n = io.read(&mut tmp).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("tls eof".into());
            }
            let mut cur = std::io::Cursor::new(&tmp[..n]);
            conn.read_tls(&mut cur).map_err(|e| e.to_string())?;
            conn.process_new_packets().map_err(|e| e.to_string())?;
        }
    }
}

async fn flush_tls(io: &mut TcpStream, conn: &mut ClientConnection) -> std::io::Result<()> {
    while conn.wants_write() {
        let mut buf = Vec::new();
        conn.write_tls(&mut buf)?;
        if buf.is_empty() {
            break;
        }
        io.write_all(&buf).await?;
    }
    Ok(())
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
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
