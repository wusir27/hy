use hy_core::Error;
use hy_extras::udphop::parse_port_union;
use std::net::{IpAddr, SocketAddr};

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

/// Parsed client `server:` — always a concrete `SocketAddr` (first hop port).
/// `hop_ports` is `Some` when the port string is an official hop union.
#[derive(Debug, Clone)]
pub struct ParsedServer {
    pub addr: SocketAddr,
    pub hop_ports: Option<Vec<u16>>,
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

pub fn parse_server(s: &str) -> Result<ParsedServer, Error> {
    let t = s.trim();
    let (host, port_str) = split_host_port(t).ok_or_else(|| {
        Error::config("ServerAddr", format!("bad server {s}"))
    })?;
    if is_port_hopping(port_str) {
        let ports = parse_port_union(port_str).ok_or_else(|| {
            Error::config(
                "Server",
                format!("{port_str} is not a valid port number or range"),
            )
        })?;
        let first = ports[0];
        let ip: IpAddr = host.parse().map_err(|_| {
            Error::config("ServerAddr", format!("bad server {s}"))
        })?;
        return Ok(ParsedServer {
            addr: SocketAddr::new(ip, first),
            hop_ports: Some(ports),
        });
    }
    let joined = if t.starts_with('[') {
        t.to_string()
    } else {
        format!("{host}:{port_str}")
    };
    let addr: SocketAddr = joined
        .parse()
        .map_err(|_| Error::config("ServerAddr", format!("bad server {s}")))?;
    Ok(ParsedServer {
        addr,
        hop_ports: None,
    })
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
        assert!(parse_server("1.1.1.1:443,1.1.1.1:444").is_err());
    }
}
