use hy_core::Error;
use hy_extras::udphop::parse_port_union;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

/// Split `host:port` / `[host]:port` (port may be a hop union).
fn split_host_port(s: &str) -> Option<(&str, &str)> {
    let s = s.trim();
    if s.starts_with('[') {
        let end = s.find(']')?;
        if s.as_bytes().get(end + 1) != Some(&b':') {
            return None;
        }
        Some((&s[1..end], &s[end + 2..]))
    } else {
        let idx = s.find(':')?;
        Some((&s[..idx], &s[idx + 1..]))
    }
}

fn is_port_hopping(port: &str) -> bool {
    port.contains(',') || port.contains('-')
}

/// Host string + main port / hop union from `server:` (no DNS).
#[derive(Debug, Clone)]
pub struct ParsedServerSpec {
    pub host: String,
    pub port: u16,
    pub hop_ports: Option<Vec<u16>>,
}

/// Resolved client `server:` — always a concrete `SocketAddr` (first hop port).
/// `hop_ports` is `Some` when the port string is an official hop union.
/// `host` is the original SplitHostPort host (for SNI), not the resolved A/AAAA.
#[derive(Debug, Clone)]
pub struct ParsedServer {
    pub addr: SocketAddr,
    pub hop_ports: Option<Vec<u16>>,
    pub host: String,
}

pub fn parse_listen(s: &str, field: &'static str) -> Result<SocketAddr, Error> {
    let t = s.trim();
    if let Some((host, port_str)) = split_host_port(t) {
        if is_port_hopping(port_str) {
            let ports = parse_port_union(port_str)
                .ok_or_else(|| Error::config(field, format!("{port_str} is not a valid port number or range")))?;
            let first = ports[0];
            let ip: IpAddr = if host.is_empty() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                host.parse()
                    .map_err(|_| Error::config(field, format!("bad listen {s}")))?
            };
            return Ok(SocketAddr::new(ip, first));
        }
        // Single port host:port
        if host.is_empty() {
            let p: u16 = port_str
                .parse()
                .map_err(|_| Error::config(field, format!("bad listen {s}")))?;
            return Ok(SocketAddr::from(([0, 0, 0, 0], p)));
        }
        let joined = if t.starts_with('[') {
            t.to_string()
        } else {
            format!("{host}:{port_str}")
        };
        if let Ok(sa) = joined.parse::<SocketAddr>() {
            return Ok(sa);
        }
        // host may be hostname — not supported for listen bind
        return Err(Error::config(field, format!("bad listen {s}")));
    }
    if let Ok(sa) = t.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(p) = t.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], p)));
    }
    Err(Error::config(field, format!("bad listen {s}")))
}

/// Parse `server:` into host + ports. Domain hosts are accepted; DNS is fill.
pub fn parse_server_spec(s: &str) -> Result<ParsedServerSpec, Error> {
    let t = s.trim();
    let (host, port_str) = split_host_port(t).ok_or_else(|| {
        Error::config("ServerAddr", format!("bad server {s}"))
    })?;
    if host.is_empty() {
        return Err(Error::config("ServerAddr", format!("bad server {s}")));
    }
    if is_port_hopping(port_str) {
        let ports = parse_port_union(port_str).ok_or_else(|| {
            Error::config(
                "ServerAddr",
                format!("{port_str} is not a valid port number or range"),
            )
        })?;
        let port = ports[0];
        return Ok(ParsedServerSpec {
            host: host.to_string(),
            port,
            hop_ports: Some(ports),
        });
    }
    let port: u16 = port_str
        .parse()
        .map_err(|_| Error::config("ServerAddr", format!("bad server {s}")))?;
    Ok(ParsedServerSpec {
        host: host.to_string(),
        port,
        hop_ports: None,
    })
}

/// One system DNS lookup when `host` is not a literal IP. First A/AAAA only.
pub fn fill_server_addr(spec: ParsedServerSpec, original: &str) -> Result<ParsedServer, Error> {
    let addr = resolve_server_host(&spec.host, spec.port, original)?;
    Ok(ParsedServer {
        addr,
        hop_ports: spec.hop_ports,
        host: spec.host,
    })
}

fn resolve_server_host(host: &str, port: u16, original: &str) -> Result<SocketAddr, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = (host, port).to_socket_addrs().map_err(|_| {
        Error::config("ServerAddr", format!("bad server {original}"))
    })?;
    let sa = addrs.next().ok_or_else(|| {
        Error::config("ServerAddr", format!("bad server {original}"))
    })?;
    Ok(SocketAddr::new(sa.ip(), port))
}

pub fn parse_server(s: &str) -> Result<ParsedServer, Error> {
    fill_server_addr(parse_server_spec(s)?, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colon_port() {
        assert_eq!(parse_listen(":1080", "Listen").unwrap().port(), 1080);
    }

    #[test]
    fn hop_listen_first_port() {
        let a = parse_listen(":443,10000-20000", "listen").unwrap();
        assert_eq!(a, "0.0.0.0:443".parse().unwrap());
        let b = parse_listen("127.0.0.1:443,10000-20000", "listen").unwrap();
        assert_eq!(b.port(), 443);
        let c = parse_listen("127.0.0.1:18530,10000-10002", "listen").unwrap();
        assert_eq!(c.port(), 18530);
    }

    #[test]
    fn parse_listen_rejects_hostname() {
        assert!(parse_listen("localhost:1080", "Listen").is_err());
        assert!(parse_listen("example.com:443", "listen").is_err());
    }

    #[test]
    fn hop_server_ok() {
        let p = parse_server("1.1.1.1:443,10000-20000").unwrap();
        assert_eq!(p.addr.port(), 443);
        assert!(p.hop_ports.as_ref().unwrap().contains(&443));
        assert!(p.hop_ports.as_ref().unwrap().contains(&10000));
        assert!(p.hop_ports.as_ref().unwrap().contains(&20000));
    }

    #[test]
    fn hop_server_list() {
        let p = parse_server("127.0.0.1:443,444,445").unwrap();
        assert_eq!(p.addr.port(), 443);
        let ports = p.hop_ports.unwrap();
        assert!(ports.contains(&443) && ports.contains(&444) && ports.contains(&445));
    }

    #[test]
    fn hop_ipv6() {
        let p = parse_server("[::1]:443,10000-10002").unwrap();
        assert_eq!(p.addr, "[::1]:443".parse().unwrap());
        assert_eq!(p.hop_ports.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn hop_invalid_union_errors() {
        // Official-invalid: second "port" is an address fragment.
        match parse_server("1.1.1.1:443,1.1.1.1:444") {
            Err(Error::Config { field, .. }) => assert_eq!(field, "ServerAddr"),
            other => panic!("expected Config ServerAddr, got {other:?}"),
        }
    }

    #[test]
    fn parse_server_domain_no_hop() {
        let spec = parse_server_spec("localhost:443").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.port, 443);
        assert!(spec.hop_ports.is_none());
        let p = parse_server("localhost:443").unwrap();
        assert_eq!(p.host, "localhost");
        assert_eq!(p.addr.port(), 443);
        assert!(p.hop_ports.is_none());
    }

    #[test]
    fn parse_server_domain_hop() {
        let spec = parse_server_spec("localhost:443,444").unwrap();
        assert_eq!(spec.host, "localhost");
        assert_eq!(spec.port, 443);
        assert!(spec.hop_ports.is_some());
        let p = parse_server("localhost:443,444").unwrap();
        assert!(p.hop_ports.is_some());
        assert_eq!(p.addr.port(), p.hop_ports.as_ref().unwrap()[0]);
        assert_eq!(p.addr.port(), 443);
    }

    #[test]
    fn parse_server_bad_name() {
        match parse_server("no-such-host.invalid:443") {
            Err(Error::Config { field, .. }) => assert_eq!(field, "ServerAddr"),
            other => panic!("expected Config ServerAddr, got {other:?}"),
        }
    }
}
