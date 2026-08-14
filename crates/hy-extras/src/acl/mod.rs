//! First-match ACL. GeoIP/GeoSite fail compile in v1.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError {
    pub line: usize,
    pub msg: String,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
    Any,
}

#[derive(Debug, Clone)]
enum AddrPat {
    All,
    Suffix(String),
    Exact(String),
    Wildcard(String),
    Ip(IpAddr),
    Cidr { ip: IpAddr, prefix: u8 },
}

#[derive(Debug, Clone)]
struct PortPat {
    proto: Proto,
    /// None = any port.
    ports: Option<(u16, u16)>,
}

#[derive(Debug, Clone)]
struct Rule {
    outbound: String,
    addr: AddrPat,
    port: PortPat,
    hijack: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct MatchHit {
    pub outbound: String,
    pub hijack: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct CompiledRuleSet {
    rules: Vec<Rule>,
    default: String,
}

impl CompiledRuleSet {
    pub fn compile(text: &str) -> Result<Self, CompileError> {
        let mut rules = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let s = raw.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            rules.push(parse_rule(s, line)?);
        }
        Ok(Self {
            rules,
            default: "default".into(),
        })
    }

    pub fn match_host(&self, host: &str, proto: Proto, port: u16) -> MatchHit {
        self.match_info(host, None, None, proto, port)
    }

    /// §10.4 HostInfo: name + resolved A/AAAA used for CIDR / IP rules.
    pub fn match_info(
        &self,
        host: &str,
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        proto: Proto,
        port: u16,
    ) -> MatchHit {
        let host_l = normalize_host(host);
        let mut ips = Vec::new();
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
        }
        if let Some(v) = v4 {
            ips.push(IpAddr::V4(v));
        }
        if let Some(v) = v6 {
            ips.push(IpAddr::V6(v));
        }
        for r in &self.rules {
            if !port_ok(&r.port, proto, port) {
                continue;
            }
            if addr_ok(&r.addr, &host_l, &ips) {
                return MatchHit {
                    outbound: r.outbound.clone(),
                    hijack: r.hijack,
                };
            }
        }
        MatchHit {
            outbound: self.default.clone(),
            hijack: None,
        }
    }
}

fn parse_rule(s: &str, line: usize) -> Result<Rule, CompileError> {
    let open = s.find('(').ok_or_else(|| CompileError {
        line,
        msg: "expected outbound(args)".into(),
    })?;
    let close = s.rfind(')').ok_or_else(|| CompileError {
        line,
        msg: "missing )".into(),
    })?;
    if close < open {
        return Err(CompileError {
            line,
            msg: "bad parens".into(),
        });
    }
    let name = s[..open].trim().to_ascii_lowercase();
    if name.is_empty() {
        return Err(CompileError {
            line,
            msg: "empty outbound".into(),
        });
    }
    let args: Vec<&str> = s[open + 1..close]
        .split(',')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .collect();
    if args.is_empty() {
        return Err(CompileError {
            line,
            msg: "empty args".into(),
        });
    }
    let addr = parse_addr(args[0], line)?;
    let port = if args.len() >= 2 {
        parse_port(args[1], line)?
    } else {
        PortPat {
            proto: Proto::Any,
            ports: None,
        }
    };
    let hijack = if args.len() >= 3 {
        Some(args[2].parse::<IpAddr>().map_err(|_| CompileError {
            line,
            msg: format!("bad hijack IP {}", args[2]),
        })?)
    } else {
        None
    };
    Ok(Rule {
        outbound: name,
        addr,
        port,
        hijack,
    })
}

fn parse_addr(s: &str, line: usize) -> Result<AddrPat, CompileError> {
    let t = s.trim();
    if t == "*" || t.eq_ignore_ascii_case("all") {
        return Ok(AddrPat::All);
    }
    if let Some(rest) = t.strip_prefix("geoip:").or_else(|| t.strip_prefix("geosite:")) {
        let _ = rest;
        return Err(CompileError {
            line,
            msg: format!("{t} not loaded"),
        });
    }
    if let Some(suf) = t.strip_prefix("suffix:") {
        return Ok(AddrPat::Suffix(normalize_host(suf)));
    }
    if let Some((ip, pref)) = t.split_once('/') {
        if let Ok(ip) = ip.parse::<IpAddr>() {
            let prefix: u8 = pref.parse().map_err(|_| CompileError {
                line,
                msg: format!("bad prefix {pref}"),
            })?;
            return Ok(AddrPat::Cidr { ip, prefix });
        }
    }
    if let Ok(ip) = t.parse::<IpAddr>() {
        return Ok(AddrPat::Ip(ip));
    }
    if t.contains('*') {
        return Ok(AddrPat::Wildcard(normalize_host(t)));
    }
    Ok(AddrPat::Exact(normalize_host(t)))
}

fn parse_port(s: &str, line: usize) -> Result<PortPat, CompileError> {
    let t = s.trim();
    if t.is_empty() || t == "*" || t == "*/*" {
        return Ok(PortPat {
            proto: Proto::Any,
            ports: None,
        });
    }
    let (proto_s, port_s) = match t.split_once('/') {
        Some((p, rest)) => (p, Some(rest)),
        None => (t, None),
    };
    let proto = match proto_s {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "*" => Proto::Any,
        _ => {
            return Err(CompileError {
                line,
                msg: format!("bad proto {proto_s}"),
            })
        }
    };
    let ports = match port_s {
        None | Some("*") => None,
        Some(p) => {
            if let Some((a, b)) = p.split_once('-') {
                let lo: u16 = a.parse().map_err(|_| CompileError {
                    line,
                    msg: format!("bad port {a}"),
                })?;
                let hi: u16 = b.parse().map_err(|_| CompileError {
                    line,
                    msg: format!("bad port {b}"),
                })?;
                Some((lo, hi))
            } else {
                let n: u16 = p.parse().map_err(|_| CompileError {
                    line,
                    msg: format!("bad port {p}"),
                })?;
                Some((n, n))
            }
        }
    };
    Ok(PortPat { proto, ports })
}

fn port_ok(p: &PortPat, proto: Proto, port: u16) -> bool {
    if p.proto != Proto::Any && p.proto != proto {
        return false;
    }
    match p.ports {
        None => true,
        Some((lo, hi)) => port >= lo && port <= hi,
    }
}

fn addr_ok(pat: &AddrPat, host: &str, ips: &[IpAddr]) -> bool {
    match pat {
        AddrPat::All => true,
        AddrPat::Exact(h) => host == h,
        AddrPat::Suffix(s) => host == s || host.ends_with(&format!(".{s}")),
        AddrPat::Wildcard(w) => glob_match(w, host),
        AddrPat::Ip(ip) => ips.contains(ip),
        AddrPat::Cidr { ip, prefix } => ips.iter().any(|h| ip_in_cidr(*h, *ip, *prefix)),
    }
}

fn normalize_host(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn glob_match(pat: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match (p.first(), t.first()) {
            (None, None) => true,
            (Some(b'*'), _) => rec(&p[1..], t) || (!t.is_empty() && rec(p, &t[1..])),
            (Some(a), Some(b)) if a == b => rec(&p[1..], &t[1..]),
            _ => false,
        }
    }
    rec(pat.as_bytes(), text.as_bytes())
}

fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let shift = 32u32.saturating_sub(prefix as u32);
            let mask = if prefix == 0 { 0 } else { !0u32 << shift };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let shift = 128u32.saturating_sub(prefix as u32);
            let mask = if prefix == 0 { 0 } else { !0u128 << shift };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

#[allow(dead_code)]
fn _keep_ip_types(_: Ipv4Addr, _: Ipv6Addr) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(s: &str) -> CompiledRuleSet {
        CompiledRuleSet::compile(s).unwrap()
    }

    #[test]
    fn first_match_cidr_udp() {
        let rs = set("reject(10.0.0.0/8, udp)\ndirect(*)\n");
        let h = rs.match_host("10.1.2.3", Proto::Udp, 53);
        assert_eq!(h.outbound, "reject");
        let h = rs.match_host("10.1.2.3", Proto::Tcp, 53);
        assert_eq!(h.outbound, "direct");
    }

    #[test]
    fn suffix_and_port() {
        let rs = set("proxy(suffix:example.com, tcp/443)\nreject(*)\n");
        assert_eq!(
            rs.match_host("foo.example.com", Proto::Tcp, 443).outbound,
            "proxy"
        );
        assert_eq!(
            rs.match_host("example.com", Proto::Tcp, 80).outbound,
            "reject"
        );
    }

    #[test]
    fn hijack_ip() {
        let rs = set("hijack_ob(1.2.3.4, *, 9.9.9.9)\n");
        let h = rs.match_host("1.2.3.4", Proto::Tcp, 1);
        assert_eq!(h.outbound, "hijack_ob");
        assert_eq!(h.hijack, Some("9.9.9.9".parse().unwrap()));
    }

    #[test]
    fn geo_fails_with_line() {
        let e = CompiledRuleSet::compile("direct(*)\nreject(geoip:cn)\n").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.msg.contains("not loaded"));
    }

    #[test]
    fn comments_and_default() {
        let rs = set("# x\n\ndirect(suffix:ok.test)\n");
        assert_eq!(rs.match_host("nope", Proto::Tcp, 1).outbound, "default");
    }

    #[test]
    fn wildcard_domain() {
        let rs = set("direct(*.example.com)\nreject(*)\n");
        assert_eq!(
            rs.match_host("a.example.com", Proto::Tcp, 1).outbound,
            "direct"
        );
    }

    #[test]
    fn port_range() {
        let rs = set("direct(*, udp/1000-2000)\nreject(*)\n");
        assert_eq!(rs.match_host("x", Proto::Udp, 1500).outbound, "direct");
        assert_eq!(rs.match_host("x", Proto::Udp, 9).outbound, "reject");
    }

    #[test]
    fn resolve_a_hits_cidr() {
        let rs = set("reject(10.0.0.0/8)\ndirect(*)\n");
        let h = rs.match_info(
            "intranet.test",
            Some("10.1.2.3".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "reject");
        let h = rs.match_info(
            "intranet.test",
            Some("1.2.3.4".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "direct");
    }
}
