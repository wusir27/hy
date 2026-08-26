//! Destination identity used by client routing and passthrough dial.

use std::net::{IpAddr, SocketAddr};

/// Transport protocol for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Host/IP + port + protocol. `addr_string` matches today's inbound dest formatting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dest {
    pub host: Option<String>,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub proto: Proto,
}

impl Dest {
    pub fn from_socket_addr(addr: SocketAddr, proto: Proto) -> Self {
        Self {
            host: None,
            ip: Some(addr.ip()),
            port: addr.port(),
            proto,
        }
    }

    /// Parse an inbound dest string (`host:port`, `ip:port`, `[ipv6]:port`).
    pub fn from_addr_string(s: &str, proto: Proto) -> Self {
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Self::from_socket_addr(addr, proto);
        }
        if let Some((host, port_s)) = s.rsplit_once(':') {
            if !host.is_empty() && !host.contains(':') {
                if let Ok(port) = port_s.parse::<u16>() {
                    return Self {
                        host: Some(host.to_string()),
                        ip: None,
                        port,
                        proto,
                    };
                }
            }
        }
        Self {
            host: Some(s.to_string()),
            ip: None,
            port: 0,
            proto,
        }
    }

    /// Format like today's inbound dest: `host:port` / `ip:port`, IPv6 in brackets.
    pub fn addr_string(&self) -> String {
        if let Some(host) = &self.host {
            format!("{host}:{}", self.port)
        } else if let Some(ip) = self.ip {
            match ip {
                IpAddr::V4(_) => format!("{ip}:{}", self.port),
                IpAddr::V6(_) => format!("[{ip}]:{}", self.port),
            }
        } else {
            format!(":{}", self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn addr_string_host_port() {
        let d = Dest {
            host: Some("example.com".into()),
            ip: None,
            port: 443,
            proto: Proto::Tcp,
        };
        assert_eq!(d.addr_string(), "example.com:443");
    }

    #[test]
    fn addr_string_ipv4_matches_socketaddr() {
        let sa: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let d = Dest::from_socket_addr(sa, Proto::Tcp);
        assert_eq!(d.addr_string(), sa.to_string());
        assert_eq!(d.addr_string(), "1.2.3.4:80");
        assert_eq!(d.ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(d.host.is_none());
    }

    #[test]
    fn addr_string_ipv6_brackets_match_socketaddr() {
        let sa: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let d = Dest::from_socket_addr(sa, Proto::Tcp);
        assert_eq!(d.addr_string(), sa.to_string());
        assert_eq!(d.addr_string(), "[2001:db8::1]:443");
        assert_eq!(d.ip, Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())));
        assert!(d.host.is_none());
    }

    #[test]
    fn from_addr_string_roundtrip_socks_http_styles() {
        for s in ["example.com:443", "127.0.0.1:8080", "[::1]:443", "[2001:db8::1]:53"] {
            let d = Dest::from_addr_string(s, Proto::Tcp);
            assert_eq!(d.addr_string(), s, "roundtrip {s}");
        }
    }
}
