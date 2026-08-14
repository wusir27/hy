use async_trait::async_trait;
use hy_core::server::Authenticator;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// POST JSON `{addr,auth,tx}` → 200 + `{ok:true,id}`.
pub struct HttpAuth {
    pub url: String,
    pub insecure: bool,
}

#[derive(Deserialize)]
struct Resp {
    ok: bool,
    #[serde(default)]
    id: String,
}

pub fn eval_response(status: u16, body: &str) -> Option<String> {
    if status != 200 {
        return None;
    }
    let r: Resp = serde_json::from_str(body).ok()?;
    if r.ok {
        Some(r.id)
    } else {
        None
    }
}

#[async_trait]
impl Authenticator for HttpAuth {
    async fn authenticate(&self, addr: SocketAddr, auth: &str, tx: u64) -> (bool, String) {
        let body = serde_json::json!({
            "addr": addr.to_string(),
            "auth": auth,
            "tx": tx,
        })
        .to_string();
        let url = self.url.clone();
        let posted = tokio::task::spawn_blocking(move || post_http(&url, &body)).await;
        match posted {
            Ok(Ok((status, resp))) => match eval_response(status, &resp) {
                Some(id) => (true, id),
                None => (false, String::new()),
            },
            _ => (false, String::new()),
        }
    }
}

/// HTTP/1.1 POST. HTTPS is rejected in v1 (use password/userpass/command).
fn post_http(url: &str, body: &str) -> Result<(u16, String), String> {
    let rest = url.strip_prefix("http://").ok_or("http auth: only http:// in v1")?;
    let (hostport, path) = match rest.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (rest, "/".into()),
    };
    let addr = hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .or_else(|| format!("{hostport}:80").to_socket_addrs().ok()?.next())
        .ok_or("http auth: resolve")?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(10))).ok();
    let host = hostport.split(':').next().unwrap_or(hostport);
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw).map_err(|e| e.to_string())?;
    let (head, payload) = raw.split_once("\r\n\r\n").ok_or("http auth: bad response")?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("http auth: status")?;
    Ok((status, payload.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_true() {
        assert_eq!(
            eval_response(200, r#"{"ok":true,"id":"bob"}"#).as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn ok_false() {
        assert!(eval_response(200, r#"{"ok":false,"id":"bob"}"#).is_none());
    }

    #[test]
    fn not_200() {
        assert!(eval_response(403, r#"{"ok":true,"id":"bob"}"#).is_none());
    }
}
