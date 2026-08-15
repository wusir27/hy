//! Realm rendezvous address parsing (`realm://`, `realm+http://`, design `https://`).

use std::collections::HashMap;

pub const SCHEME_HTTPS: &str = "realm";
pub const SCHEME_HTTP: &str = "realm+http";

const DEFAULT_HTTPS_PORT: &str = "443";
const DEFAULT_HTTP_PORT: &str = "80";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidScheme;

impl std::fmt::Display for ErrInvalidScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid realm address scheme")
    }
}
impl std::error::Error for ErrInvalidScheme {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidAddr(pub String);

impl std::fmt::Display for ErrInvalidAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid realm address: {}", self.0)
    }
}
impl std::error::Error for ErrInvalidAddr {}

/// Parsed Hysteria Realms rendezvous address.
#[derive(Debug, Clone)]
pub struct Addr {
    /// `realm` or `realm+http` (normalized; design `https://` becomes `realm`).
    pub scheme: String,
    /// HTTP scheme used to contact the rendezvous server: `https` or `http`.
    pub rendezvous_scheme: String,
    pub token: String,
    pub host: String,
    pub port: String,
    pub host_port: String,
    pub realm_id: String,
    /// Requested local UDP source port from `lport` (0 = ephemeral).
    pub local_port: u16,
    pub params: HashMap<String, Vec<String>>,
}

impl Addr {
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.rendezvous_scheme, self.host_port)
    }
}

/// True when `s` should enter Realm mode (not parsed as host:port).
pub fn is_realm_url(s: &str) -> bool {
    let t = s.trim();
    t.starts_with("realm://")
        || t.starts_with("realm+http://")
        || t.starts_with("https://")
}

pub fn parse_addr(s: &str) -> Result<Addr, Box<dyn std::error::Error + Send + Sync>> {
    let s = s.trim();
    // Design form: https://host/id (token from query or userinfo).
    if s.starts_with("https://") || (s.starts_with("http://") && !s.starts_with("realm+http://")) {
        return parse_design_https(s);
    }
    parse_official(s)
}

fn parse_official(s: &str) -> Result<Addr, Box<dyn std::error::Error + Send + Sync>> {
    let (scheme, rest) = s
        .split_once("://")
        .ok_or_else(|| ErrInvalidAddr("missing scheme".into()))?;
    let (rendezvous_scheme, default_port) = scheme_info(scheme)?;
    if rest.is_empty() {
        return Err(Box::new(ErrInvalidAddr("rendezvous host is required".into())));
    }
    if s.contains('#') {
        return Err(Box::new(ErrInvalidAddr("fragment is not supported".into())));
    }

    let (auth_host, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => {
            return Err(Box::new(ErrInvalidAddr("realm id is required".into())));
        }
    };
    if !auth_host.contains('@') {
        return Err(Box::new(ErrInvalidAddr("realm token is required".into())));
    }
    let (token_raw, hostport) = auth_host
        .rsplit_once('@')
        .ok_or_else(|| ErrInvalidAddr("realm token is required".into()))?;
    let token = percent_decode(token_raw);
    if token.is_empty() {
        return Err(Box::new(ErrInvalidAddr("realm token is required".into())));
    }
    if hostport.is_empty() {
        return Err(Box::new(ErrInvalidAddr("rendezvous host is required".into())));
    }

    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_query, None),
    };
    let realm_id = parse_realm_id(path)?;
    let (host, port) = split_host_port(hostport, default_port)?;
    validate_port(&port)?;
    let host_port = join_host_port(&host, &port);
    let params = parse_query(query.unwrap_or(""));
    let local_port = parse_local_port(params.get("lport"))?;

    Ok(Addr {
        scheme: scheme.to_string(),
        rendezvous_scheme: rendezvous_scheme.to_string(),
        token,
        host,
        port,
        host_port,
        realm_id,
        local_port,
        params,
    })
}

fn parse_design_https(s: &str) -> Result<Addr, Box<dyn std::error::Error + Send + Sync>> {
    if s.contains('#') {
        return Err(Box::new(ErrInvalidAddr("fragment is not supported".into())));
    }
    let rest = s
        .strip_prefix("https://")
        .ok_or_else(|| Box::new(ErrInvalidScheme) as Box<dyn std::error::Error + Send + Sync>)?;
    let scheme_http = "https";
    let default_port = DEFAULT_HTTPS_PORT;
    let (auth_host, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => {
            return Err(Box::new(ErrInvalidAddr("realm id is required".into())));
        }
    };
    let (token_from_user, hostport) = if let Some((u, h)) = auth_host.rsplit_once('@') {
        (Some(percent_decode(u)), h)
    } else {
        (None, auth_host)
    };
    if hostport.is_empty() {
        return Err(Box::new(ErrInvalidAddr("rendezvous host is required".into())));
    }
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_query, None),
    };
    let realm_id = parse_realm_id(path)?;
    let params = parse_query(query.unwrap_or(""));
    let token = if let Some(t) = token_from_user.filter(|t| !t.is_empty()) {
        t
    } else if let Some(vs) = params.get("token") {
        vs.first()
            .cloned()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| ErrInvalidAddr("realm token is required".into()))?
    } else {
        return Err(Box::new(ErrInvalidAddr("realm token is required".into())));
    };
    let (host, port) = split_host_port(hostport, default_port)?;
    validate_port(&port)?;
    let host_port = join_host_port(&host, &port);
    let local_port = parse_local_port(params.get("lport"))?;
    Ok(Addr {
        scheme: SCHEME_HTTPS.to_string(),
        rendezvous_scheme: scheme_http.to_string(),
        token,
        host,
        port,
        host_port,
        realm_id,
        local_port,
        params,
    })
}

fn scheme_info(scheme: &str) -> Result<(&'static str, &'static str), ErrInvalidScheme> {
    match scheme {
        SCHEME_HTTPS => Ok(("https", DEFAULT_HTTPS_PORT)),
        SCHEME_HTTP => Ok(("http", DEFAULT_HTTP_PORT)),
        _ => Err(ErrInvalidScheme),
    }
}

fn parse_realm_id(path: &str) -> Result<String, ErrInvalidAddr> {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() || trimmed.contains('/') {
        return Err(ErrInvalidAddr(
            "realm id must be a single path segment".into(),
        ));
    }
    let id = percent_decode(trimmed);
    if id.is_empty() || id.contains('/') {
        return Err(ErrInvalidAddr(
            "realm id must be a single path segment".into(),
        ));
    }
    Ok(id)
}

fn parse_local_port(values: Option<&Vec<String>>) -> Result<u16, ErrInvalidAddr> {
    let Some(values) = values else {
        return Ok(0);
    };
    if values.len() > 1 {
        return Err(ErrInvalidAddr(
            "lport must be specified at most once".into(),
        ));
    }
    let p: u16 = values[0]
        .parse()
        .map_err(|_| ErrInvalidAddr("lport must be an integer in 1-65535".into()))?;
    if p == 0 {
        return Err(ErrInvalidAddr(
            "lport must be an integer in 1-65535".into(),
        ));
    }
    Ok(p)
}

fn validate_port(port: &str) -> Result<(), ErrInvalidAddr> {
    let p: u32 = port
        .parse()
        .map_err(|_| ErrInvalidAddr("invalid rendezvous port".into()))?;
    if p == 0 || p > 65535 {
        return Err(ErrInvalidAddr("invalid rendezvous port".into()));
    }
    Ok(())
}

fn split_host_port(hostport: &str, default_port: &str) -> Result<(String, String), ErrInvalidAddr> {
    if hostport.starts_with('[') {
        let end = hostport
            .find(']')
            .ok_or_else(|| ErrInvalidAddr("invalid rendezvous host or port".into()))?;
        let host = hostport[1..end].to_string();
        if host.is_empty() {
            return Err(ErrInvalidAddr("rendezvous host is required".into()));
        }
        let rest = &hostport[end + 1..];
        if rest.is_empty() {
            return Ok((host, default_port.to_string()));
        }
        if let Some(p) = rest.strip_prefix(':') {
            return Ok((host, p.to_string()));
        }
        return Err(ErrInvalidAddr("invalid rendezvous host or port".into()));
    }
    // host:port or bare host (not IPv6 without brackets)
    if let Some((h, p)) = hostport.rsplit_once(':') {
        if h.contains(':') {
            // ambiguous IPv6 without brackets — treat whole as host
            return Ok((hostport.to_string(), default_port.to_string()));
        }
        if h.is_empty() {
            return Err(ErrInvalidAddr("rendezvous host is required".into()));
        }
        Ok((h.to_string(), p.to_string()))
    } else {
        if hostport.is_empty() {
            return Err(ErrInvalidAddr("rendezvous host is required".into()));
        }
        Ok((hostport.to_string(), default_port.to_string()))
    }
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn parse_query(q: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    if q.is_empty() {
        return out;
    }
    for part in q.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(part), String::new()),
        };
        out.entry(k).or_default().push(v);
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_realm_official() {
        let a = parse_addr("realm://tok@127.0.0.1:9/myid").unwrap();
        assert_eq!(a.token, "tok");
        assert_eq!(a.host, "127.0.0.1");
        assert_eq!(a.port, "9");
        assert_eq!(a.realm_id, "myid");
        assert_eq!(a.rendezvous_scheme, "https");
    }

    #[test]
    fn parse_requires_token() {
        assert!(parse_addr("realm://127.0.0.1:9/myid").is_err());
        assert!(parse_addr("https://127.0.0.1/myid").is_err());
    }

    #[test]
    fn parse_https_design_token_query() {
        let a = parse_addr("https://example.com/myid?token=secret").unwrap();
        assert_eq!(a.token, "secret");
        assert_eq!(a.realm_id, "myid");
        assert_eq!(a.rendezvous_scheme, "https");
    }
}
