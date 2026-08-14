//! TrafficStats HTTP API + TrafficLogger.

use hy_core::server::{StreamStats, TrafficLogger};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const INDEX_HTML: &str = r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Hysteria Traffic Stats API Server</title></head><body><div><p>This is a Hysteria Traffic Stats API server.</p><p>Check the documentation for usage.</p></div></body></html>"#;

#[derive(Clone, Default, Serialize)]
struct Entry {
    tx: u64,
    rx: u64,
}

struct Inner {
    stats: HashMap<String, Entry>,
    online: HashMap<String, i32>,
    kick: HashSet<String>,
    streams: HashMap<u64, Arc<StreamStats>>,
}

pub struct TrafficStats {
    inner: Mutex<Inner>,
    secret: String,
}

pub struct HttpReply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl TrafficStats {
    pub fn new(secret: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                stats: HashMap::new(),
                online: HashMap::new(),
                kick: HashSet::new(),
                streams: HashMap::new(),
            }),
            secret: secret.into(),
        })
    }

    pub fn dispatch(
        &self,
        method: &str,
        path: &str,
        query: &str,
        auth: Option<&str>,
        body: &[u8],
    ) -> HttpReply {
        if !self.secret.is_empty() && auth != Some(self.secret.as_str()) {
            return HttpReply {
                status: 401,
                content_type: "text/plain",
                body: b"unauthorized\n".to_vec(),
            };
        }
        let m = method.to_ascii_uppercase();
        if m == "GET" && path == "/" {
            return HttpReply {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: INDEX_HTML.as_bytes().to_vec(),
            };
        }
        if m == "GET" && path == "/traffic" {
            let clear = query.split('&').any(|p| p == "clear=1" || p == "clear=true");
            let mut g = self.inner.lock().unwrap();
            let body = serde_json::to_vec(&g.stats).unwrap_or_else(|_| b"{}".to_vec());
            if clear {
                g.stats.clear();
            }
            return HttpReply {
                status: 200,
                content_type: "application/json; charset=utf-8",
                body,
            };
        }
        if m == "GET" && path == "/online" {
            let g = self.inner.lock().unwrap();
            let body = serde_json::to_vec(&g.online).unwrap_or_else(|_| b"{}".to_vec());
            return HttpReply {
                status: 200,
                content_type: "application/json; charset=utf-8",
                body,
            };
        }
        if m == "POST" && path == "/kick" {
            let ids: Vec<String> = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(e) => {
                    return HttpReply {
                        status: 400,
                        content_type: "text/plain",
                        body: e.to_string().into_bytes(),
                    };
                }
            };
            let mut g = self.inner.lock().unwrap();
            for id in ids {
                g.kick.insert(id);
            }
            return HttpReply {
                status: 200,
                content_type: "text/plain",
                body: Vec::new(),
            };
        }
        if m == "GET" && path == "/dump/streams" {
            let g = self.inner.lock().unwrap();
            #[derive(Serialize)]
            struct Dump {
                streams: Vec<DumpEntry>,
            }
            #[derive(Serialize)]
            struct DumpEntry {
                auth: String,
                connection: u32,
                stream: u64,
                req_addr: String,
                tx: u64,
                rx: u64,
            }
            let streams: Vec<DumpEntry> = g
                .streams
                .iter()
                .map(|(sid, s)| DumpEntry {
                    auth: s.auth_id.clone(),
                    connection: s.conn_id,
                    stream: *sid,
                    req_addr: s.req_addr.clone(),
                    tx: s.tx,
                    rx: s.rx,
                })
                .collect();
            let body = serde_json::to_vec(&Dump { streams }).unwrap_or_else(|_| b"{}".to_vec());
            return HttpReply {
                status: 200,
                content_type: "application/json; charset=utf-8",
                body,
            };
        }
        HttpReply {
            status: 404,
            content_type: "text/plain",
            body: b"not found\n".to_vec(),
        }
    }

    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> std::io::Result<()> {
        let ln = TcpListener::bind(addr).await?;
        loop {
            let (mut s, _) = ln.accept().await?;
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = serve_one(&me, &mut s).await;
            });
        }
    }
}

async fn serve_one(ts: &TrafficStats, s: &mut tokio::net::TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = s.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let raw = &buf[..n];
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut auth = None;
    let mut content_len = 0usize;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case("authorization") {
                auth = Some(v.trim().to_string());
            }
            if k.eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let header_end = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
    let mut body = raw.get(header_end..).unwrap_or(&[]).to_vec();
    while body.len() < content_len {
        let k = s.read(&mut buf).await?;
        if k == 0 {
            break;
        }
        body.extend_from_slice(&buf[..k]);
    }
    body.truncate(content_len);
    let reply = ts.dispatch(&method, &path, &query, auth.as_deref(), &body);
    let head = format!(
        "HTTP/1.1 {} \r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.content_type,
        reply.body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(&reply.body).await?;
    Ok(())
}

impl TrafficLogger for TrafficStats {
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.kick.remove(id) {
            return false;
        }
        let e = g.stats.entry(id.to_string()).or_default();
        e.tx += tx;
        e.rx += rx;
        true
    }

    fn log_online_state(&self, id: &str, online: bool) {
        let mut g = self.inner.lock().unwrap();
        if online {
            *g.online.entry(id.to_string()).or_insert(0) += 1;
        } else if let Some(c) = g.online.get_mut(id) {
            *c -= 1;
            if *c <= 0 {
                g.online.remove(id);
            }
        }
    }

    fn trace_stream(&self, stream_id: u64, stats: Arc<StreamStats>) {
        self.inner.lock().unwrap().streams.insert(stream_id, stats);
    }

    fn untrace_stream(&self, stream_id: u64) {
        self.inner.lock().unwrap().streams.remove(&stream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_and_clear() {
        let t = TrafficStats::new("");
        assert!(t.log_traffic("u1", 10, 20));
        let r = t.dispatch("GET", "/traffic", "", None, b"");
        assert_eq!(r.status, 200);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["u1"]["tx"], 10);
        assert_eq!(v["u1"]["rx"], 20);
        let r = t.dispatch("GET", "/traffic", "clear=1", None, b"");
        assert_eq!(r.status, 200);
        let r = t.dispatch("GET", "/traffic", "", None, b"");
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v, serde_json::json!({}));
    }

    #[test]
    fn online_and_kick() {
        let t = TrafficStats::new("");
        t.log_online_state("u1", true);
        let r = t.dispatch("GET", "/online", "", None, b"");
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["u1"], 1);
        t.log_online_state("u1", false);
        let r = t.dispatch("GET", "/online", "", None, b"");
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v, serde_json::json!({}));
        let r = t.dispatch("POST", "/kick", "", None, br#"["u1"]"#);
        assert_eq!(r.status, 200);
        assert!(!t.log_traffic("u1", 1, 0));
        assert!(t.log_traffic("u1", 1, 0));
    }

    #[test]
    fn auth_secret() {
        let t = TrafficStats::new("s3cret");
        let r = t.dispatch("GET", "/traffic", "", None, b"");
        assert_eq!(r.status, 401);
        let r = t.dispatch("GET", "/traffic", "", Some("wrong"), b"");
        assert_eq!(r.status, 401);
        let r = t.dispatch("GET", "/traffic", "", Some("s3cret"), b"");
        assert_eq!(r.status, 200);
        let r = t.dispatch("GET", "/", "", Some("s3cret"), b"");
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("Traffic Stats"));
    }
}
