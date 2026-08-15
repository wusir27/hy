//! HTTP / HTTPS CONNECT outbound.
//! Always uses AddrEx.host — ignores resolve (same as official Go).
//! UDP → Error::Dial("http outbound is tcp only").

use super::{AddrEx, PluggableOutbound, TokioTcp};
use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::server::{HyTcpStream, HyUdpSocket};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

const ERR_UDP: &str = "http outbound is tcp only";

pub struct HttpOutbound {
    /// host:port of the proxy
    pub addr: String,
    pub https: bool,
    pub insecure: bool,
    pub server_name: String,
    /// Already includes "Basic " prefix, or empty.
    pub basic_auth: String,
}

impl HttpOutbound {
    pub fn new(proxy_url: &str, insecure: bool) -> Result<Self, Error> {
        let url = proxy_url.trim();
        if url.is_empty() {
            return Err(Error::config("outbounds.http.url", "empty http address"));
        }
        let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
            ("https", r)
        } else if let Some(r) = url.strip_prefix("http://") {
            ("http", r)
        } else {
            return Err(Error::Dial(
                "unsupported scheme for HTTP proxy (use http:// or https://)".into(),
            ));
        };
        let (auth_part, host_part) = if let Some(i) = rest.find('@') {
            (Some(&rest[..i]), &rest[i + 1..])
        } else {
            (None, rest)
        };
        let host_part = host_part.split('/').next().unwrap_or(host_part);
        if host_part.is_empty() {
            return Err(Error::Dial("invalid http proxy url".into()));
        }
        let (host, port_explicit) = split_url_host_port(host_part)?;
        let port = port_explicit.unwrap_or(if scheme == "https" { 443 } else { 80 });
        let addr = join_host_port(&host, port);
        let basic_auth = if let Some(ap) = auth_part {
            let (user, pass) = ap.split_once(':').unwrap_or((ap, ""));
            let token = b64_encode(format!("{user}:{pass}").as_bytes());
            format!("Basic {token}")
        } else {
            String::new()
        };
        Ok(Self {
            addr,
            https: scheme == "https",
            insecure,
            server_name: host,
            basic_auth,
        })
    }
}

#[async_trait]
impl PluggableOutbound for HttpOutbound {
    async fn tcp(&self, addr: &mut AddrEx) -> Result<Box<dyn HyTcpStream>, Error> {
        let target = join_host_port(&addr.host, addr.port);
        let mut req = format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n"
        );
        if !self.basic_auth.is_empty() {
            req.push_str("Proxy-Authorization: ");
            req.push_str(&self.basic_auth);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        let tcp = match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(&self.addr)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(Error::Dial(e.to_string())),
            Err(_) => return Err(Error::Dial("http proxy dial timeout".into())),
        };

        let mut stream: Box<dyn HyTcpStream> = if self.https {
            Box::new(TlsStream::connect(tcp, &self.server_name, self.insecure).await?)
        } else {
            Box::new(TokioTcp(tcp))
        };

        let leftover = write_connect_and_read(stream.as_mut(), req.as_bytes()).await?;
        if leftover.is_empty() {
            Ok(stream)
        } else {
            Ok(Box::new(CachedStream {
                cache: leftover,
                pos: 0,
                inner: stream,
            }))
        }
    }

    async fn udp(&self, _addr: &mut AddrEx) -> Result<Box<dyn HyUdpSocket>, Error> {
        Err(Error::Dial(ERR_UDP.into()))
    }

    async fn check_udp(&self, _addr: &mut AddrEx) -> Result<(), Error> {
        Err(Error::Dial(ERR_UDP.into()))
    }
}

async fn write_connect_and_read(stream: &mut dyn HyTcpStream, req: &[u8]) -> Result<Vec<u8>, Error> {
    let fut = async {
        let mut off = 0;
        while off < req.len() {
            let n = stream.write(&req[off..]).await?;
            if n == 0 {
                return Err(Error::Dial("HTTP proxy write zero".into()));
            }
            off += n;
        }
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(Error::Dial("HTTP proxy closed during CONNECT".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(end) = find_headers_end(&buf) {
                let head = std::str::from_utf8(&buf[..end])
                    .map_err(|_| Error::Dial("invalid HTTP CONNECT response".into()))?;
                let status = parse_status_code(head)
                    .ok_or_else(|| Error::Dial("invalid HTTP CONNECT response".into()))?;
                if status != 200 {
                    return Err(Error::Dial(format!("HTTP request failed: {status}")));
                }
                return Ok(buf[end..].to_vec());
            }
            if buf.len() > 64 * 1024 {
                return Err(Error::Dial("HTTP CONNECT response too large".into()));
            }
        }
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(Error::Dial("http CONNECT timeout".into())),
    }
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn parse_status_code(head: &str) -> Option<u16> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    let _ver = parts.next()?;
    parts.next()?.parse().ok()
}

fn split_url_host_port(host_part: &str) -> Result<(String, Option<u16>), Error> {
    if let Some(rest) = host_part.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::Dial("bad v6 host in http proxy url".into()))?;
        if tail.is_empty() {
            return Ok((host.to_string(), None));
        }
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| Error::Dial("bad http proxy url".into()))?
            .parse()
            .map_err(|_| Error::Dial("bad http proxy port".into()))?;
        return Ok((host.to_string(), Some(port)));
    }
    if let Some((h, p)) = host_part.rsplit_once(':') {
        if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            let port: u16 = p
                .parse()
                .map_err(|_| Error::Dial("bad http proxy port".into()))?;
            return Ok((h.to_string(), Some(port)));
        }
    }
    Ok((host_part.to_string(), None))
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= data.len() {
        let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | (data[i + 2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(T[((n >> 6) & 63) as usize] as char);
        out.push(T[(n & 63) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            let n = (data[i] as u32) << 16;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(T[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn ensure_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_tls_config(insecure: bool) -> Result<ClientConfig, Error> {
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

struct TlsStream {
    io: TcpStream,
    sess: ClientConnection,
    plain_buf: Vec<u8>,
}

impl TlsStream {
    async fn connect(mut io: TcpStream, sni: &str, insecure: bool) -> Result<Self, Error> {
        let cfg = Arc::new(build_tls_config(insecure)?);
        let name = ServerName::try_from(sni.to_string())
            .map_err(|e| Error::Dial(format!("bad SNI: {e}")))?;
        let mut sess = ClientConnection::new(cfg, name).map_err(|e| Error::Dial(e.to_string()))?;
        loop {
            while sess.wants_write() {
                let mut buf = Vec::new();
                sess.write_tls(&mut buf)
                    .map_err(|e| Error::Dial(e.to_string()))?;
                if buf.is_empty() {
                    break;
                }
                io.write_all(&buf).await.map_err(Error::Io)?;
            }
            if !sess.is_handshaking() {
                break;
            }
            let mut tls_buf = [0u8; 4096];
            let n = io.read(&mut tls_buf).await.map_err(Error::Io)?;
            if n == 0 {
                return Err(Error::Dial("TLS handshake closed".into()));
            }
            let mut cur = std::io::Cursor::new(&tls_buf[..n]);
            while cur.position() < n as u64 {
                let before = cur.position();
                sess.read_tls(&mut cur)
                    .map_err(|e| Error::Dial(e.to_string()))?;
                if cur.position() == before {
                    break;
                }
                sess.process_new_packets()
                    .map_err(|e| Error::Dial(e.to_string()))?;
            }
        }
        Ok(Self {
            io,
            sess,
            plain_buf: Vec::new(),
        })
    }

    async fn flush_tls(&mut self) -> Result<(), Error> {
        while self.sess.wants_write() {
            let mut buf = Vec::new();
            self.sess
                .write_tls(&mut buf)
                .map_err(|e| Error::Dial(e.to_string()))?;
            if buf.is_empty() {
                break;
            }
            self.io.write_all(&buf).await.map_err(Error::Io)?;
        }
        Ok(())
    }

    async fn read_tls_more(&mut self) -> Result<(), Error> {
        let mut tls_buf = [0u8; 4096];
        let n = self.io.read(&mut tls_buf).await.map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Dial("TLS connection closed".into()));
        }
        let mut cur = std::io::Cursor::new(&tls_buf[..n]);
        while (cur.position() as usize) < n {
            let before = cur.position();
            self.sess
                .read_tls(&mut cur)
                .map_err(|e| Error::Dial(e.to_string()))?;
            if cur.position() == before {
                break;
            }
            self.sess
                .process_new_packets()
                .map_err(|e| Error::Dial(e.to_string()))?;
        }
        Ok(())
    }
}

#[async_trait]
impl HyTcpStream for TlsStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
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
                Err(e) => return Err(Error::Io(e)),
            }
        }
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.sess
            .writer()
            .write_all(buf)
            .map_err(|e| Error::Dial(e.to_string()))?;
        self.flush_tls().await?;
        Ok(buf.len())
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.sess.send_close_notify();
        let _ = self.flush_tls().await;
        let _ = self.io.shutdown().await;
        Ok(())
    }
}

struct CachedStream {
    cache: Vec<u8>,
    pos: usize,
    inner: Box<dyn HyTcpStream>,
}

#[async_trait]
impl HyTcpStream for CachedStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if self.pos < self.cache.len() {
            let n = (self.cache.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.cache[self.pos..self.pos + n]);
            self.pos += n;
            return Ok(n);
        }
        self.inner.read(buf).await
    }
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.inner.write(buf).await
    }
    async fn close(&mut self) -> Result<(), Error> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn tcp_connect_uses_hostname() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let recorded = Arc::new(Mutex::new(String::new()));
        let rec = Arc::clone(&recorded);
        tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = s.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if find_headers_end(&buf).is_some() {
                    break;
                }
            }
            *rec.lock().unwrap() = String::from_utf8_lossy(&buf).into_owned();
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut sink = [0u8; 1];
            let _ = s.read(&mut sink).await;
        });

        let ob = HttpOutbound::new(&format!("http://{addr}"), false).unwrap();
        let mut dest = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: Some(super::super::ResolveInfo {
                v4: Some(std::net::Ipv4Addr::new(9, 9, 9, 9)),
                v6: None,
                err: None,
            }),
        };
        let _ = ob.tcp(&mut dest).await.expect("tcp");
        let req = recorded.lock().unwrap().clone();
        let first = req.lines().next().unwrap();
        assert_eq!(first, "CONNECT example.test:443 HTTP/1.1");
        assert!(req.contains("Host: example.test:443"), "{req}");
        assert!(!req.contains("9.9.9.9"), "{req}");
    }

    #[tokio::test]
    async fn udp_and_check_udp_tcp_only() {
        let ob = HttpOutbound::new("http://127.0.0.1:8080", false).unwrap();
        let mut a = AddrEx {
            host: "example.test".into(),
            port: 443,
            resolve: None,
        };
        match ob.udp(&mut a).await {
            Err(Error::Dial(s)) => assert_eq!(s, "http outbound is tcp only"),
            Ok(_) => panic!("expected Dial"),
            Err(e) => panic!("{e:?}"),
        }
        match ob.check_udp(&mut a).await {
            Err(Error::Dial(s)) => assert_eq!(s, "http outbound is tcp only"),
            Ok(_) => panic!("expected Dial"),
            Err(e) => panic!("{e:?}"),
        }
    }
}
