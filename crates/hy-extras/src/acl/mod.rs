//! First-match ACL with official geoip: / geosite: (V2Ray proto).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use regex::Regex;

pub mod v2geo;
pub use v2geo::{
    encode_geoip_list, encode_geosite_list, load_geoip_bytes, load_geoip_file, load_geosite_bytes,
    load_geosite_file, FileGeoLoader, GeoIpMap, GeoSiteMap, MemoryGeoLoader,
};

use v2geo::{
    DOMAIN_TYPE_FULL, DOMAIN_TYPE_PLAIN, DOMAIN_TYPE_REGEX, DOMAIN_TYPE_ROOT_DOMAIN, GeoIp, GeoSite,
};

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

/// On-demand GeoIP/GeoSite database, matching official `acl.GeoLoader`.
pub trait GeoLoader {
    fn load_geoip(&self) -> Result<GeoIpMap, String>;
    fn load_geosite(&self) -> Result<GeoSiteMap, String>;
}

#[derive(Clone, Debug)]
enum AddrPat {
    All,
    Suffix(String),
    Exact(String),
    Wildcard(String),
    Ip(IpAddr),
    Cidr { ip: IpAddr, prefix: u8 },
    GeoIp(GeoIpMatcher),
    GeoSite(GeoSiteMatcher),
}

#[derive(Clone, Debug)]
struct GeoIpMatcher {
    n4: Vec<(Ipv4Addr, u8)>,
    n6: Vec<(Ipv6Addr, u8)>,
    inverse: bool,
}

impl GeoIpMatcher {
    fn new(list: &GeoIp) -> Result<Self, String> {
        let mut n4 = Vec::new();
        let mut n6 = Vec::new();
        for cidr in &list.cidr {
            if cidr.ip.len() == 4 {
                let ip = Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
                n4.push((ip, cidr.prefix as u8));
            } else if cidr.ip.len() == 16 {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&cidr.ip);
                n6.push((Ipv6Addr::from(oct), cidr.prefix as u8));
            } else {
                return Err("invalid IP length".into());
            }
        }
        n4.sort_by(|a, b| a.0.octets().cmp(&b.0.octets()));
        n6.sort_by(|a, b| a.0.octets().cmp(&b.0.octets()));
        Ok(Self {
            n4,
            n6,
            inverse: list.inverse_match,
        })
    }

    fn match_ip4(&self, ip: Ipv4Addr) -> bool {
        let ipb = ip.octets();
        let n = &self.n4;
        let mut left: isize = 0;
        let mut right: isize = n.len() as isize - 1;
        while left <= right {
            let mid = ((left + right) / 2) as usize;
            if ip_in_cidr(IpAddr::V4(ip), IpAddr::V4(n[mid].0), n[mid].1) {
                return true;
            } else if n[mid].0.octets() < ipb {
                left = mid as isize + 1;
            } else {
                right = mid as isize - 1;
            }
        }
        false
    }

    fn match_ip6(&self, ip: Ipv6Addr) -> bool {
        let ipb = ip.octets();
        let n = &self.n6;
        let mut left: isize = 0;
        let mut right: isize = n.len() as isize - 1;
        while left <= right {
            let mid = ((left + right) / 2) as usize;
            if ip_in_cidr(IpAddr::V6(ip), IpAddr::V6(n[mid].0), n[mid].1) {
                return true;
            } else if n[mid].0.octets() < ipb {
                left = mid as isize + 1;
            } else {
                right = mid as isize - 1;
            }
        }
        false
    }

    fn matches(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> bool {
        if let Some(ip) = v4 {
            if self.match_ip4(ip) {
                return !self.inverse;
            }
        }
        if let Some(ip) = v6 {
            if self.match_ip6(ip) {
                return !self.inverse;
            }
        }
        self.inverse
    }
}

#[derive(Clone, Debug)]
struct GeoSiteDomain {
    kind: i32,
    value: String,
    regex: Option<Regex>,
    attrs: HashMap<String, bool>,
}

#[derive(Clone, Debug)]
struct GeoSiteMatcher {
    domains: Vec<GeoSiteDomain>,
    attrs: Vec<String>,
}

impl GeoSiteMatcher {
    fn new(list: &GeoSite, attrs: Vec<String>) -> Result<Self, String> {
        let mut domains = Vec::with_capacity(list.domain.len());
        for d in &list.domain {
            let attrs_map = domain_attribute_to_map(&d.attribute);
            match d.r#type {
                DOMAIN_TYPE_PLAIN => domains.push(GeoSiteDomain {
                    kind: DOMAIN_TYPE_PLAIN,
                    value: d.value.clone(),
                    regex: None,
                    attrs: attrs_map,
                }),
                DOMAIN_TYPE_REGEX => {
                    let re = Regex::new(&d.value).map_err(|e| e.to_string())?;
                    domains.push(GeoSiteDomain {
                        kind: DOMAIN_TYPE_REGEX,
                        value: d.value.clone(),
                        regex: Some(re),
                        attrs: attrs_map,
                    });
                }
                DOMAIN_TYPE_ROOT_DOMAIN => domains.push(GeoSiteDomain {
                    kind: DOMAIN_TYPE_ROOT_DOMAIN,
                    value: d.value.clone(),
                    regex: None,
                    attrs: attrs_map,
                }),
                DOMAIN_TYPE_FULL => domains.push(GeoSiteDomain {
                    kind: DOMAIN_TYPE_FULL,
                    value: d.value.clone(),
                    regex: None,
                    attrs: attrs_map,
                }),
                _ => return Err("unsupported domain type".into()),
            }
        }
        Ok(Self { domains, attrs })
    }

    fn match_domain(&self, domain: &GeoSiteDomain, name: &str) -> bool {
        if !self.attrs.is_empty() {
            if domain.attrs.is_empty() {
                return false;
            }
            for a in &self.attrs {
                if !domain.attrs.get(a).copied().unwrap_or(false) {
                    return false;
                }
            }
        }
        match domain.kind {
            DOMAIN_TYPE_PLAIN => name.contains(&domain.value),
            DOMAIN_TYPE_REGEX => domain
                .regex
                .as_ref()
                .map(|r| r.is_match(name))
                .unwrap_or(false),
            DOMAIN_TYPE_FULL => name == domain.value,
            DOMAIN_TYPE_ROOT_DOMAIN => name == domain.value || name.ends_with(&format!(".{}", domain.value)),
            _ => false,
        }
    }

    fn matches(&self, name: &str) -> bool {
        self.domains.iter().any(|d| self.match_domain(d, name))
    }
}

fn domain_attribute_to_map(attrs: &[v2geo::domain::Attribute]) -> HashMap<String, bool> {
    let mut m = HashMap::new();
    for a in attrs {
        // Official: int attributes count as present = true.
        m.insert(a.key.clone(), true);
    }
    m
}

#[derive(Debug, Clone)]
struct PortPat {
    proto: Proto,
    /// None = any port.
    ports: Option<(u16, u16)>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct CompiledRuleSet {
    rules: Vec<Rule>,
    default: String,
}

impl CompiledRuleSet {
    pub fn compile(text: &str) -> Result<Self, CompileError> {
        Self::compile_with(text, None)
    }

    pub fn compile_with(text: &str, loader: Option<&dyn GeoLoader>) -> Result<Self, CompileError> {
        let mut rules = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = i + 1;
            let s = raw.trim();
            if s.is_empty() || s.starts_with('#') {
                continue;
            }
            rules.push(parse_rule(s, line, loader)?);
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
    /// GeoIP uses only the Resolver v4/v6 parameters, not a host-parsed IP.
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
            if addr_ok(&r.addr, &host_l, &ips, v4, v6) {
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

fn parse_rule(s: &str, line: usize, loader: Option<&dyn GeoLoader>) -> Result<Rule, CompileError> {
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
    let addr = parse_addr(args[0], line, loader)?;
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

fn parse_addr(s: &str, line: usize, loader: Option<&dyn GeoLoader>) -> Result<AddrPat, CompileError> {
    // Official: ToLower + TrimRight dots on the whole address (args are already trimmed).
    let t = s.trim().to_ascii_lowercase();
    let t = t.trim_end_matches('.');
    if t == "*" || t == "all" {
        return Ok(AddrPat::All);
    }
    if let Some(country) = t.strip_prefix("geoip:") {
        if country.is_empty() {
            return Err(CompileError {
                line,
                msg: "empty GeoIP country code".into(),
            });
        }
        let Some(loader) = loader else {
            return Err(CompileError {
                line,
                msg: format!("{t} not loaded"),
            });
        };
        let gmap = loader
            .load_geoip()
            .map_err(|e| CompileError { line, msg: e })?;
        let list = gmap.get(country).ok_or_else(|| CompileError {
            line,
            msg: format!("GeoIP country code {country} not found"),
        })?;
        let m = GeoIpMatcher::new(list).map_err(|e| CompileError { line, msg: e })?;
        return Ok(AddrPat::GeoIp(m));
    }
    if let Some(rest) = t.strip_prefix("geosite:") {
        let (name, attrs) = parse_geosite_name(rest);
        if name.is_empty() {
            return Err(CompileError {
                line,
                msg: "empty GeoSite name".into(),
            });
        }
        let Some(loader) = loader else {
            return Err(CompileError {
                line,
                msg: format!("{t} not loaded"),
            });
        };
        let gmap = loader
            .load_geosite()
            .map_err(|e| CompileError { line, msg: e })?;
        let list = gmap.get(&name).ok_or_else(|| CompileError {
            line,
            msg: format!("GeoSite name {name} not found"),
        })?;
        let m = GeoSiteMatcher::new(list, attrs).map_err(|e| CompileError { line, msg: e })?;
        return Ok(AddrPat::GeoSite(m));
    }
    if let Some(suf) = t.strip_prefix("suffix:") {
        return Ok(AddrPat::Suffix(suf.to_string()));
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
        return Ok(AddrPat::Wildcard(t.to_string()));
    }
    Ok(AddrPat::Exact(t.to_string()))
}

/// Official `parseGeoSiteName`: split `@`, trim name and each attr.
fn parse_geosite_name(s: &str) -> (String, Vec<String>) {
    let mut parts = s.split('@');
    let base = parts.next().unwrap_or("").trim().to_string();
    let attrs = parts.map(|p| p.trim().to_string()).collect();
    (base, attrs)
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

fn addr_ok(
    pat: &AddrPat,
    host: &str,
    ips: &[IpAddr],
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
) -> bool {
    match pat {
        AddrPat::All => true,
        AddrPat::Exact(h) => host == h,
        AddrPat::Suffix(s) => host == s || host.ends_with(&format!(".{s}")),
        AddrPat::Wildcard(w) => glob_match(w, host),
        AddrPat::Ip(ip) => ips.contains(ip),
        AddrPat::Cidr { ip, prefix } => ips.iter().any(|h| ip_in_cidr(*h, *ip, *prefix)),
        AddrPat::GeoIp(m) => m.matches(v4, v6),
        AddrPat::GeoSite(m) => m.matches(host),
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
    use prost::Message;
    use std::sync::atomic::{AtomicBool, Ordering};
    use v2geo::{
        domain, Cidr, Domain, GeoIp, GeoIpList, GeoSite, GeoSiteList, DOMAIN_TYPE_FULL,
        DOMAIN_TYPE_PLAIN, DOMAIN_TYPE_ROOT_DOMAIN,
    };

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

    fn fixture_geoip() -> GeoIpMap {
        let list = GeoIpList {
            entry: vec![
                GeoIp {
                    country_code: "CN".into(),
                    cidr: vec![
                        Cidr {
                            ip: vec![1, 2, 3, 0],
                            prefix: 24,
                        },
                        Cidr {
                            ip: b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                .to_vec(),
                            prefix: 32,
                        },
                    ],
                    inverse_match: false,
                },
                GeoIp {
                    country_code: "JP".into(),
                    cidr: vec![Cidr {
                        ip: vec![203, 0, 113, 0],
                        prefix: 24,
                    }],
                    inverse_match: false,
                },
                GeoIp {
                    country_code: "INV".into(),
                    cidr: vec![Cidr {
                        ip: vec![10, 0, 0, 0],
                        prefix: 8,
                    }],
                    inverse_match: true,
                },
            ],
        };
        load_geoip_bytes(&list.encode_to_vec()).unwrap()
    }

    fn attr_cn() -> domain::Attribute {
        domain::Attribute {
            key: "cn".into(),
            typed_value: Some(domain::attribute::TypedValue::BoolValue(true)),
        }
    }

    fn fixture_geosite() -> GeoSiteMap {
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "GOOGLE".into(),
                domain: vec![
                    Domain {
                        r#type: DOMAIN_TYPE_FULL,
                        value: "accounts.google.com".into(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: DOMAIN_TYPE_ROOT_DOMAIN,
                        value: "youtube.com".into(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: DOMAIN_TYPE_PLAIN,
                        value: "gstatic".into(),
                        attribute: vec![],
                    },
                    Domain {
                        r#type: DOMAIN_TYPE_FULL,
                        value: "gstatic-cn.com".into(),
                        attribute: vec![attr_cn()],
                    },
                    Domain {
                        r#type: DOMAIN_TYPE_ROOT_DOMAIN,
                        value: "google.cn".into(),
                        attribute: vec![attr_cn()],
                    },
                ],
            }],
        };
        load_geosite_bytes(&list.encode_to_vec()).unwrap()
    }

    fn geo_loader() -> MemoryGeoLoader {
        MemoryGeoLoader {
            geoip: fixture_geoip(),
            geosite: fixture_geosite(),
        }
    }

    fn compile_geo(text: &str) -> CompiledRuleSet {
        CompiledRuleSet::compile_with(text, Some(&geo_loader())).unwrap()
    }

    #[test]
    fn geoip_cn_and_jp_case_via_match_info() {
        let rs = compile_geo("reject(geoip:cn)\ndirect(geoip:JP)\nproxy(*)\n");
        let h = rs.match_info(
            "x.test",
            Some("1.2.3.4".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "reject");
        let h = rs.match_info(
            "x.test",
            Some("203.0.113.9".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "direct");
        let h = rs.match_info(
            "x.test",
            None,
            Some("2001:db8::1".parse().unwrap()),
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "reject");
        let h = rs.match_info(
            "x.test",
            Some("8.8.8.8".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "proxy");
        // Host-parsed IP is not HostInfo v4/v6 for geoip.
        let h = rs.match_host("1.2.3.4", Proto::Tcp, 80);
        assert_eq!(h.outbound, "proxy");
    }

    #[test]
    fn geoip_unknown_and_empty_fail_with_line() {
        let e = CompiledRuleSet::compile_with("direct(*)\nreject(geoip:zz)\n", Some(&geo_loader()))
            .unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.msg.contains("GeoIP country code zz not found"), "{}", e.msg);

        let e = CompiledRuleSet::compile_with("reject(geoip:)\n", Some(&geo_loader())).unwrap_err();
        assert_eq!(e.line, 1);
        assert_eq!(e.msg, "empty GeoIP country code");

        let e = CompiledRuleSet::compile("reject(geoip:)\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert_eq!(e.msg, "empty GeoIP country code");
    }

    #[test]
    fn geoip_space_after_colon_not_trimmed() {
        let e = CompiledRuleSet::compile_with("reject(geoip: cn)\n", Some(&geo_loader())).unwrap_err();
        assert_eq!(e.line, 1);
        assert!(
            e.msg.contains("GeoIP country code  cn not found")
                || e.msg.contains("not found"),
            "{}",
            e.msg
        );
        assert!(!e.msg.contains("empty"));
    }

    #[test]
    fn geoip_inverse_match() {
        let rs = compile_geo("reject(geoip:inv)\ndirect(*)\n");
        // listed CIDR + inverse → miss
        let h = rs.match_info(
            "x",
            Some("10.1.2.3".parse().unwrap()),
            None,
            Proto::Tcp,
            1,
        );
        assert_eq!(h.outbound, "direct");
        // not listed → inverse hit
        let h = rs.match_info(
            "x",
            Some("1.2.3.4".parse().unwrap()),
            None,
            Proto::Tcp,
            1,
        );
        assert_eq!(h.outbound, "reject");
        // unresolved name: inverse hit
        let h = rs.match_info("unresolved.test", None, None, Proto::Tcp, 1);
        assert_eq!(h.outbound, "reject");
        // unresolved non-inverse: miss
        let rs = compile_geo("reject(geoip:cn)\ndirect(*)\n");
        let h = rs.match_info("unresolved.test", None, None, Proto::Tcp, 1);
        assert_eq!(h.outbound, "direct");
    }

    #[test]
    fn geosite_full_root_plain_and_attrs() {
        let rs = compile_geo("direct(geosite:google)\nreject(*)\n");
        assert_eq!(
            rs.match_host("accounts.google.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        assert_eq!(
            rs.match_host("www.youtube.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        assert_eq!(
            rs.match_host("youtube.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        assert_eq!(
            rs.match_host("fonts.gstatic.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        assert_eq!(
            rs.match_host("notgoogle.com", Proto::Tcp, 443).outbound,
            "reject"
        );

        let rs = compile_geo("direct(geosite:google@cn)\nreject(*)\n");
        assert_eq!(
            rs.match_host("gstatic-cn.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        assert_eq!(
            rs.match_host("www.google.cn", Proto::Tcp, 443).outbound,
            "direct"
        );
        // Full google.com has no @cn
        assert_eq!(
            rs.match_host("accounts.google.com", Proto::Tcp, 443).outbound,
            "reject"
        );

        // official parseGeoSiteName trims name and attr: `google @cn`
        let rs = compile_geo("direct(geosite:google @cn)\nreject(*)\n");
        assert_eq!(
            rs.match_host("gstatic-cn.com", Proto::Tcp, 443).outbound,
            "direct"
        );
    }

    #[test]
    fn geosite_unknown_and_empty_fail_with_line() {
        let e =
            CompiledRuleSet::compile_with("reject(geosite:nope)\n", Some(&geo_loader())).unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.msg.contains("GeoSite name nope not found"), "{}", e.msg);

        let e = CompiledRuleSet::compile_with("reject(geosite:)\n", Some(&geo_loader())).unwrap_err();
        assert_eq!(e.line, 1);
        assert_eq!(e.msg, "empty GeoSite name");
    }

    struct FlagLoader {
        geoip: AtomicBool,
        geosite: AtomicBool,
        inner: MemoryGeoLoader,
    }

    impl GeoLoader for FlagLoader {
        fn load_geoip(&self) -> Result<GeoIpMap, String> {
            self.geoip.store(true, Ordering::SeqCst);
            self.inner.load_geoip()
        }
        fn load_geosite(&self) -> Result<GeoSiteMap, String> {
            self.geosite.store(true, Ordering::SeqCst);
            self.inner.load_geosite()
        }
    }

    #[test]
    fn no_geo_rules_does_not_call_loader() {
        let l = FlagLoader {
            geoip: AtomicBool::new(false),
            geosite: AtomicBool::new(false),
            inner: geo_loader(),
        };
        let rs = CompiledRuleSet::compile_with("direct(*)\nreject(suffix:evil.test)\n", Some(&l))
            .unwrap();
        assert!(!l.geoip.load(Ordering::SeqCst));
        assert!(!l.geosite.load(Ordering::SeqCst));
        assert_eq!(rs.match_host("x", Proto::Tcp, 1).outbound, "direct");
    }

    #[test]
    fn only_geoip_does_not_load_geosite() {
        let l = FlagLoader {
            geoip: AtomicBool::new(false),
            geosite: AtomicBool::new(false),
            inner: geo_loader(),
        };
        CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&l)).unwrap();
        assert!(l.geoip.load(Ordering::SeqCst));
        assert!(!l.geosite.load(Ordering::SeqCst));
    }

    struct PanicLoader;
    impl GeoLoader for PanicLoader {
        fn load_geoip(&self) -> Result<GeoIpMap, String> {
            panic!("load_geoip should not be called");
        }
        fn load_geosite(&self) -> Result<GeoSiteMap, String> {
            panic!("load_geosite should not be called");
        }
    }

    #[test]
    fn no_geo_rules_panic_loader_ok() {
        CompiledRuleSet::compile_with("direct(*)\n", Some(&PanicLoader)).unwrap();
    }

    #[test]
    fn file_loader_bad_path_fails_compile() {
        let l = FileGeoLoader {
            geoip: Some("/no/such/hy-geoip-missing.dat".into()),
            geosite: None,
        };
        let e = CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&l)).unwrap_err();
        assert_eq!(e.line, 1);
        assert!(!e.msg.is_empty());
    }

    #[test]
    fn file_loader_temp_dat() {
        let dir = std::env::temp_dir().join(format!(
            "hy-geo-extras-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("geoip.dat");
        let bytes = GeoIpList {
            entry: vec![GeoIp {
                country_code: "CN".into(),
                cidr: vec![Cidr {
                    ip: vec![1, 2, 3, 0],
                    prefix: 24,
                }],
                inverse_match: false,
            }],
        }
        .encode_to_vec();
        std::fs::write(&path, &bytes).unwrap();
        let l = FileGeoLoader {
            geoip: Some(path.clone()),
            geosite: None,
        };
        let rs = CompiledRuleSet::compile_with("reject(geoip:cn)\ndirect(*)\n", Some(&l)).unwrap();
        let h = rs.match_info(
            "x",
            Some("1.2.3.9".parse().unwrap()),
            None,
            Proto::Tcp,
            1,
        );
        assert_eq!(h.outbound, "reject");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_geosite_name_official() {
        assert_eq!(parse_geosite_name("google@cn"), ("google".into(), vec!["cn".into()]));
        assert_eq!(
            parse_geosite_name(" google @cn "),
            ("google".into(), vec!["cn".into()])
        );
        assert_eq!(
            parse_geosite_name("netflix @xixi    @haha "),
            ("netflix".into(), vec!["xixi".into(), "haha".into()])
        );
        assert_eq!(parse_geosite_name(""), ("".into(), Vec::<String>::new()));
    }

    #[test]
    fn invalid_ip_length_fails_compile() {
        let mut m = GeoIpMap::new();
        m.insert(
            "xx".into(),
            GeoIp {
                country_code: "xx".into(),
                cidr: vec![Cidr {
                    ip: vec![1, 2, 3],
                    prefix: 24,
                }],
                inverse_match: false,
            },
        );
        let l = MemoryGeoLoader {
            geoip: m,
            geosite: GeoSiteMap::new(),
        };
        let e = CompiledRuleSet::compile_with("reject(geoip:xx)\n", Some(&l)).unwrap_err();
        assert_eq!(e.msg, "invalid IP length");
    }
}
