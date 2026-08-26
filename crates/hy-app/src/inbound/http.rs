use crate::inbound::forward::relay_tcp;
use crate::listen::parse_listen;
use crate::route_glue::{Dest, FlowDial, Proto};
use hy_core::client::HyTcpConn;
use hy_core::Error;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

pub async fn run(cfg: &crate::config::HttpYaml, client: Arc<dyn FlowDial>) -> Result<(), Error> {
    let listen = cfg.listen.as_deref().ok_or_else(|| Error::config("http.listen", "must be set"))?;
    let addr = parse_listen(listen, "http.listen")?;
    let ln = TcpListener::bind(addr).await.map_err(Error::Io)?;
    tracing::info!("http listen {addr}");
    let user = cfg.username.clone().unwrap_or_default();
    let pass = cfg.password.clone().unwrap_or_default();
    let realm = cfg.realm.clone().unwrap_or_else(|| "Hysteria".into());
    loop {
        let (s, _) = ln.accept().await.map_err(Error::Io)?;
        let client = Arc::clone(&client);
        let user = user.clone();
        let pass = pass.clone();
        let realm = realm.clone();
        tokio::spawn(async move {
            let _ = handle(s, client, &user, &pass, &realm).await;
        });
    }
}

async fn handle(
    s: TcpStream,
    client: Arc<dyn FlowDial>,
    user: &str,
    pass: &str,
    realm: &str,
) -> Result<(), Error> {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).await.map_err(Error::Io)?;
    let parts: Vec<String> = line.split_whitespace().map(|s| s.to_string()).collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0].clone();
    let target = parts[1].clone();
    let proto = parts.get(2).cloned().unwrap_or_else(|| "HTTP/1.1".into());
    let mut headers = Vec::new();
    loop {
        line.clear();
        r.read_line(&mut line).await.map_err(Error::Io)?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        headers.push(line.clone());
    }
    if !user.is_empty() && !proxy_auth_ok(&headers, user, pass) {
        let mut s = r.into_inner();
        let body = format!(
            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"{realm}\"\r\n\r\n"
        );
        let _ = s.write_all(body.as_bytes()).await;
        return Ok(());
    }
    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    let dest = if is_connect {
        if target.contains(':') {
            target.clone()
        } else {
            format!("{target}:443")
        }
    } else if let Some(rest) = target.strip_prefix("http://") {
        let hostport = rest.split('/').next().unwrap_or(rest);
        if hostport.contains(':') {
            hostport.to_string()
        } else {
            format!("{hostport}:80")
        }
    } else {
        return Ok(());
    };

    let mut body = Vec::new();
    if !is_connect {
        if let Some(n) = content_length(&headers) {
            body.resize(n, 0);
            r.read_exact(&mut body).await.map_err(Error::Io)?;
        }
    }
    let mut s = r.into_inner();
    let dest = Dest::from_addr_string(&dest, Proto::Tcp);
    match client.tcp(dest).await {
        Ok(mut out) => {
            if is_connect {
                s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .map_err(Error::Io)?;
            } else {
                let req = build_origin_request(&method, &target, &proto, &headers, &body);
                HyTcpConn::write(&*out, &req).await?;
            }
            relay_tcp(s, out).await
        }
        Err(_) => {
            let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            Ok(())
        }
    }
}

fn content_length(headers: &[String]) -> Option<usize> {
    for h in headers {
        let Some((k, v)) = h.split_once(':') else { continue };
        if k.eq_ignore_ascii_case("content-length") {
            return v.trim().parse().ok();
        }
    }
    None
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "proxy-connection"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn origin_form(target: &str) -> String {
    if let Some(rest) = target.strip_prefix("http://") {
        if let Some(slash) = rest.find('/') {
            rest[slash..].to_string()
        } else {
            "/".into()
        }
    } else {
        target.to_string()
    }
}

fn build_origin_request(method: &str, target: &str, proto: &str, headers: &[String], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{method} {} {proto}\r\n", origin_form(target)).into_bytes();
    for h in headers {
        let name = h.split_once(':').map(|(k, _)| k.trim()).unwrap_or("");
        if hop_by_hop(name) {
            continue;
        }
        out.extend_from_slice(h.as_bytes());
        if !h.ends_with('\n') {
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'A' + 26 - (b'a' - b'A')),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let raw: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    if raw.is_empty() || raw.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 4 * 3);
    for chunk in raw.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let v0 = val(chunk[0])?;
        let v1 = val(chunk[1])?;
        let v2 = if chunk[2] == b'=' { 0 } else { val(chunk[2])? };
        let v3 = if chunk[3] == b'=' { 0 } else { val(chunk[3])? };
        let n = (u32::from(v0) << 18) | (u32::from(v1) << 12) | (u32::from(v2) << 6) | u32::from(v3);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn proxy_auth_ok(headers: &[String], user: &str, pass: &str) -> bool {
    for h in headers {
        let Some((k, v)) = h.split_once(':') else { continue };
        if !k.eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let v = v.trim();
        let Some(b64) = v
            .strip_prefix("Basic ")
            .or_else(|| v.strip_prefix("basic "))
            .or_else(|| v.strip_prefix("BASIC "))
        else {
            continue;
        };
        let Some(raw) = b64_decode(b64.trim()) else {
            continue;
        };
        let Ok(s) = String::from_utf8(raw) else { continue };
        let Some((u, p)) = s.split_once(':') else { continue };
        if u.as_bytes() == user.as_bytes() && ct_eq(p.as_bytes(), pass.as_bytes()) {
            return true;
        }
        return false;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_compares_user_pass() {
        let h = vec!["Proxy-Authorization: Basic dXNlcjpwYXNz\r\n".into()];
        assert!(proxy_auth_ok(&h, "user", "pass"));
        assert!(!proxy_auth_ok(&h, "user", "wrong"));
        assert!(!proxy_auth_ok(&h, "other", "pass"));
        assert!(!proxy_auth_ok(&["Proxy-Authorization: Basic dXNlcjpwYXNz\r\n".into()], "user", "passx"));
        assert!(!proxy_auth_ok(&[], "user", "pass"));
        assert!(!proxy_auth_ok(&["Proxy-Authorization: Basic\r\n".into()], "user", "pass"));
    }

    #[test]
    fn get_forwards_origin_form() {
        let req = build_origin_request(
            "GET",
            "http://127.0.0.1:9/echo?q=1",
            "HTTP/1.1",
            &[
                "Host: 127.0.0.1:9\r\n".into(),
                "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n".into(),
                "User-Agent: curl\r\n".into(),
            ],
            b"",
        );
        let s = String::from_utf8(req).unwrap();
        assert!(s.starts_with("GET /echo?q=1 HTTP/1.1\r\n"), "{s}");
        assert!(s.contains("Host: 127.0.0.1:9"));
        assert!(!s.to_ascii_lowercase().contains("proxy-authorization"));
        assert!(!s.contains("Connection Established"));
    }
}
