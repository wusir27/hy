//! Compile a local Shadowrocket-style `.conf` and match destinations.

use crate::action::Action;
use crate::dest::Dest;
use crate::error::Error;
use crate::suffix::SuffixTrie;
use hy_extras::acl::v2geo::GeoIp;
use hy_extras::acl::GeoIpMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

/// Compiled client router.
#[derive(Debug)]
pub struct Router {
    skip_domains: Vec<String>,
    skip_cidrs: Vec<(IpAddr, u8)>,
    bypass_cidrs: Vec<(IpAddr, u8)>,
    dns_servers: Vec<String>,
    exact: HashMap<String, (usize, Action)>,
    suffixes: SuffixTrie,
    keywords: Vec<(usize, String, Action)>,
    cidrs: Vec<(usize, IpAddr, u8, Action)>,
    geoips: Vec<(usize, GeoIpMatcher, Action)>,
    final_action: Action,
    rule_set_skipped: usize,
}

impl Router {
    /// Highest-priority Direct CIDRs from `bypass-tun` / `tun-excluded-routes`.
    /// Stored this step; system exclude is not installed.
    pub fn bypass_cidrs(&self) -> &[(IpAddr, u8)] {
        &self.bypass_cidrs
    }

    /// `[General] dns-server` values (store only).
    pub fn dns_servers(&self) -> &[String] {
        &self.dns_servers
    }

    pub fn rule_set_skipped(&self) -> usize {
        self.rule_set_skipped
    }

    pub fn decide(&self, dest: &Dest) -> Action {
        let action = self.decide_inner(dest);
        tracing::debug!(
            dest = %dest.addr_string(),
            action = %action,
            "route decide"
        );
        action
    }

    fn decide_inner(&self, dest: &Dest) -> Action {
        let host = dest
            .host
            .as_deref()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty());

        if let Some(h) = host.as_deref() {
            if self.skip_domains.iter().any(|s| host_matches_suffix(h, s)) {
                return Action::Direct;
            }
        }
        if let Some(ip) = dest.ip {
            if self
                .skip_cidrs
                .iter()
                .chain(self.bypass_cidrs.iter())
                .any(|(net, pfx)| ip_in_cidr(ip, *net, *pfx))
            {
                return Action::Direct;
            }
        }

        if let Some(h) = host.as_deref() {
            if let Some((_, a)) = self.best_domain(h) {
                return a;
            }
            if let Some(ip) = dest.ip {
                if let Some((_, a)) = self.best_ip(ip) {
                    return a;
                }
            }
            return self.final_action;
        }

        if let Some(ip) = dest.ip {
            if let Some((_, a)) = self.best_ip(ip) {
                return a;
            }
        }
        self.final_action
    }

    fn best_domain(&self, host: &str) -> Option<(usize, Action)> {
        let mut best: Option<(usize, Action)> = None;
        if let Some(&hit) = self.exact.get(host) {
            best = min_hit(best, hit);
        }
        for hit in self.suffixes.lookup(host) {
            best = min_hit(best, hit);
        }
        for (idx, kw, act) in &self.keywords {
            if host.contains(kw.as_str()) {
                best = min_hit(best, (*idx, *act));
            }
        }
        best
    }

    fn best_ip(&self, ip: IpAddr) -> Option<(usize, Action)> {
        let mut best: Option<(usize, Action)> = None;
        for (idx, net, pfx, act) in &self.cidrs {
            if ip_in_cidr(ip, *net, *pfx) {
                best = min_hit(best, (*idx, *act));
            }
        }
        for (idx, geo, act) in &self.geoips {
            if geo.matches(ip) {
                best = min_hit(best, (*idx, *act));
            }
        }
        best
    }
}

fn min_hit(cur: Option<(usize, Action)>, hit: (usize, Action)) -> Option<(usize, Action)> {
    Some(match cur {
        None => hit,
        Some(c) if hit.0 < c.0 => hit,
        Some(c) => c,
    })
}

pub fn compile(text: &str, geoip: Option<&GeoIpMap>) -> Result<Router, Error> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut skip_domains = Vec::new();
    let mut skip_cidrs = Vec::new();
    let mut bypass_cidrs = Vec::new();
    let mut dns_servers = Vec::new();
    let mut exact = HashMap::new();
    let mut suffixes = SuffixTrie::default();
    let mut keywords = Vec::new();
    let mut cidrs = Vec::new();
    let mut geoips = Vec::new();
    let mut final_action = Action::Proxy;
    let mut rule_set_skipped = 0usize;
    let mut n_domain = 0usize;
    let mut n_suffix = 0usize;
    let mut n_keyword = 0usize;
    let mut n_cidr = 0usize;
    let mut n_geoip = 0usize;
    let mut next_idx = 0usize;
    let mut section = Section::None;

    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        let mut line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if matches!(section, Section::Rule | Section::General | Section::None) {
            if let Some(stripped) = strip_hash_comment(line) {
                line = stripped;
            } else {
                continue;
            }
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = parse_section(&line[1..line.len() - 1]);
            continue;
        }
        match section {
            Section::None | Section::Ignore => {}
            Section::General => parse_general(
                line,
                &mut skip_domains,
                &mut skip_cidrs,
                &mut bypass_cidrs,
                &mut dns_servers,
            ),
            Section::Rule => {
                let parts: Vec<&str> = line.split(',').map(str::trim).collect();
                if parts.is_empty() {
                    continue;
                }
                let kind = parts[0].to_ascii_uppercase();
                if kind == "RULE-SET" {
                    rule_set_skipped += 1;
                    tracing::debug!(line = line_no, "skipping RULE-SET (not downloaded)");
                    continue;
                }
                if kind == "FINAL" {
                    let pol = parts.get(1).copied().unwrap_or("");
                    match parse_pol(pol) {
                        Some(a) => final_action = a,
                        None => {
                            return Err(Error::compile(
                                line_no,
                                format!(
                                    "FINAL policy '{pol}' is not DIRECT, REJECT, or PROXY"
                                ),
                            ));
                        }
                    }
                    continue;
                }
                let supported = matches!(
                    kind.as_str(),
                    "DOMAIN"
                        | "DOMAIN-SUFFIX"
                        | "DOMAIN-KEYWORD"
                        | "IP-CIDR"
                        | "IP-CIDR6"
                        | "GEOIP"
                );
                if !supported {
                    continue;
                }
                let arg = parts.get(1).copied().unwrap_or("");
                let pol_s = parts.get(2).copied().unwrap_or("");
                let Some(action) = parse_pol(pol_s) else {
                    tracing::warn!(
                        line = line_no,
                        pol = pol_s,
                        "skipping rule with unknown policy"
                    );
                    continue;
                };
                if arg.is_empty() {
                    tracing::warn!(line = line_no, "skipping rule with empty value");
                    continue;
                }
                match kind.as_str() {
                    "DOMAIN" => {
                        let d = normalize_domain(arg);
                        exact.entry(d).or_insert((next_idx, action));
                        n_domain += 1;
                        next_idx += 1;
                    }
                    "DOMAIN-SUFFIX" => {
                        let d = normalize_domain(arg);
                        suffixes.insert(&d, next_idx, action);
                        n_suffix += 1;
                        next_idx += 1;
                    }
                    "DOMAIN-KEYWORD" => {
                        keywords.push((next_idx, arg.to_ascii_lowercase(), action));
                        n_keyword += 1;
                        next_idx += 1;
                    }
                    "IP-CIDR" | "IP-CIDR6" => {
                        let (ip, pfx) = parse_cidr(arg).ok_or_else(|| {
                            Error::compile(line_no, format!("invalid CIDR {arg}"))
                        })?;
                        cidrs.push((next_idx, ip, pfx, action));
                        n_cidr += 1;
                        next_idx += 1;
                    }
                    "GEOIP" => {
                        let country = arg.trim().to_ascii_lowercase();
                        if country.is_empty() {
                            return Err(Error::compile(line_no, "empty GeoIP country code"));
                        }
                        let list = geoip.and_then(|m| m.get(&country)).ok_or_else(|| {
                            Error::compile(
                                line_no,
                                format!("GeoIP country code {country} not found"),
                            )
                        })?;
                        let matcher = GeoIpMatcher::new(list).map_err(|e| {
                            Error::compile(line_no, e)
                        })?;
                        geoips.push((next_idx, matcher, action));
                        n_geoip += 1;
                        next_idx += 1;
                    }
                    _ => {}
                }
            }
        }
    }

    tracing::info!(
        domain = n_domain,
        suffix = n_suffix,
        keyword = n_keyword,
        cidr = n_cidr,
        geoip = n_geoip,
        rule_set_skipped,
        "client-route compiled"
    );

    Ok(Router {
        skip_domains,
        skip_cidrs,
        bypass_cidrs,
        dns_servers,
        exact,
        suffixes,
        keywords,
        cidrs,
        geoips,
        final_action,
        rule_set_skipped,
    })
}

pub fn compile_file(path: impl AsRef<Path>, geoip: Option<&GeoIpMap>) -> Result<Router, Error> {
    let path = path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    compile(&text, geoip)
}

#[derive(Clone, Copy)]
enum Section {
    None,
    General,
    Rule,
    Ignore,
}

fn parse_section(name: &str) -> Section {
    match name.trim().to_ascii_lowercase().as_str() {
        "general" => Section::General,
        "rule" => Section::Rule,
        "proxy" | "proxy group" | "host" | "mitm" | "url rewrite" => Section::Ignore,
        _ => Section::Ignore,
    }
}

fn strip_hash_comment(line: &str) -> Option<&str> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    Some(t.split('#').next().unwrap_or(t).trim())
}

fn parse_general(
    line: &str,
    skip_domains: &mut Vec<String>,
    skip_cidrs: &mut Vec<(IpAddr, u8)>,
    bypass_cidrs: &mut Vec<(IpAddr, u8)>,
    dns_servers: &mut Vec<String>,
) {
    let Some((k, v)) = line.split_once('=') else {
        return;
    };
    let key = k.trim().to_ascii_lowercase();
    let val = v.trim();
    match key.as_str() {
        "skip-proxy" => {
            for item in split_csv(val) {
                if let Some(c) = parse_cidr(&item) {
                    skip_cidrs.push(c);
                } else if !item.is_empty() {
                    skip_domains.push(normalize_skip_domain(&item));
                }
            }
        }
        "bypass-tun" | "tun-excluded-routes" => {
            for item in split_csv(val) {
                if let Some(c) = parse_cidr(&item) {
                    bypass_cidrs.push(c);
                }
            }
        }
        "dns-server" => {
            for item in split_csv(val) {
                if !item.is_empty() {
                    dns_servers.push(item);
                }
            }
        }
        _ => {}
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_pol(s: &str) -> Option<Action> {
    match s.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Some(Action::Direct),
        "REJECT" | "REJECT-DROP" => Some(Action::Reject),
        "PROXY" => Some(Action::Proxy),
        _ => None,
    }
}

fn normalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_skip_domain(s: &str) -> String {
    let mut d = normalize_domain(s);
    if let Some(rest) = d.strip_prefix("*.") {
        d = rest.to_string();
    } else if let Some(rest) = d.strip_prefix('.') {
        d = rest.to_string();
    }
    d
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.len() > suffix.len()
        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.')
        && host.ends_with(suffix)
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    if let Some((ip, pfx)) = s.split_once('/') {
        let ip: IpAddr = ip.trim().parse().ok()?;
        let pfx: u8 = pfx.trim().parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if pfx > max {
            return None;
        }
        Some((ip, pfx))
    } else {
        let ip: IpAddr = s.parse().ok()?;
        let pfx = if ip.is_ipv4() { 32 } else { 128 };
        Some((ip, pfx))
    }
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

#[derive(Debug, Clone)]
struct GeoIpMatcher {
    cidrs: Vec<(IpAddr, u8)>,
    inverse: bool,
}

impl GeoIpMatcher {
    fn new(list: &GeoIp) -> Result<Self, String> {
        let mut cidrs = Vec::with_capacity(list.cidr.len());
        for c in &list.cidr {
            let ip = match c.ip.len() {
                4 => IpAddr::from([c.ip[0], c.ip[1], c.ip[2], c.ip[3]]),
                16 => {
                    let mut oct = [0u8; 16];
                    oct.copy_from_slice(&c.ip);
                    IpAddr::from(oct)
                }
                _ => return Err("invalid IP length".into()),
            };
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if c.prefix > max {
                return Err("invalid CIDR prefix".into());
            }
            cidrs.push((ip, c.prefix as u8));
        }
        Ok(Self {
            cidrs,
            inverse: list.inverse_match,
        })
    }

    fn matches(&self, ip: IpAddr) -> bool {
        let hit = self.cidrs.iter().any(|(net, pfx)| ip_in_cidr(ip, *net, *pfx));
        if self.inverse {
            !hit
        } else {
            hit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dest::Proto;
    use hy_extras::acl::v2geo::{Cidr, GeoIp, GeoIpList};
    use hy_extras::acl::{encode_geoip_list, load_geoip_bytes};
    use std::net::{Ipv4Addr, SocketAddr};

    fn fixture_geoip() -> GeoIpMap {
        let bytes = encode_geoip_list(&GeoIpList {
            entry: vec![GeoIp {
                country_code: "CN".into(),
                cidr: vec![
                    Cidr {
                        ip: vec![1, 2, 3, 0],
                        prefix: 24,
                    },
                    Cidr {
                        ip: vec![114, 114, 114, 0],
                        prefix: 24,
                    },
                ],
                inverse_match: false,
            }],
        });
        load_geoip_bytes(&bytes).unwrap()
    }

    fn mini_sr_cnip() -> &'static str {
        r#"
[General]
skip-proxy = localhost, *.local, 10.0.0.0/8
bypass-tun = 192.168.0.0/16
dns-server = 8.8.8.8, https://dns.example/dns-query
ipv6 = false

[Proxy]
PROXY = shadowsocks, 1.2.3.4, 443

[Rule]
# comment ignored
DOMAIN-SUFFIX,baidu.com,DIRECT
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN-KEYWORD,ads,REJECT
IP-CIDR,10.20.30.0/24,DIRECT
GEOIP,CN,DIRECT
DOMAIN-SUFFIX,blocked.example,REJECT
FINAL,PROXY

[URL Rewrite]
^https://x.example https://y.example 302
"#
    }

    fn dest_host(host: &str) -> Dest {
        Dest {
            host: Some(host.into()),
            ip: None,
            port: 443,
            proto: Proto::Tcp,
        }
    }

    fn dest_ip(ip: Ipv4Addr) -> Dest {
        Dest::from_socket_addr(SocketAddr::from((ip, 443)), Proto::Tcp)
    }

    #[test]
    fn sr_cnip_like_fixture_decide() {
        let geo = fixture_geoip();
        let r = compile(mini_sr_cnip(), Some(&geo)).unwrap();
        assert_eq!(r.decide(&dest_host("www.baidu.com")), Action::Direct);
        assert_eq!(r.decide(&dest_host("foo.local")), Action::Direct);
        assert_eq!(r.decide(&dest_host("localhost")), Action::Direct);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(1, 2, 3, 4))), Action::Direct);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(8, 8, 8, 8))), Action::Proxy);
        assert_eq!(r.decide(&dest_host("tracker.ads.cdn")), Action::Reject);
        assert_eq!(r.decide(&dest_host("blocked.example")), Action::Reject);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(10, 20, 30, 9))), Action::Direct);
        assert_eq!(r.dns_servers(), ["8.8.8.8", "https://dns.example/dns-query"]);
        assert!(r.bypass_cidrs().iter().any(|(ip, p)| {
            *ip == IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)) && *p == 16
        }));
    }

    #[test]
    fn many_suffixes_use_trie() {
        let mut conf = String::from("[Rule]\n");
        for i in 0..4000 {
            conf.push_str(&format!("DOMAIN-SUFFIX,n{i}.example.test,DIRECT\n"));
        }
        conf.push_str("FINAL,PROXY\n");
        let r = compile(&conf, None).unwrap();
        assert_eq!(
            r.decide(&dest_host("www.n42.example.test")),
            Action::Direct
        );
        assert_eq!(r.decide(&dest_host("other.com")), Action::Proxy);
        // Must not match a prefix that is not a suffix.
        assert_eq!(
            r.decide(&dest_host("n42.example.test.evil.com")),
            Action::Proxy
        );
    }

    #[test]
    fn domain_keyword() {
        let r = compile(
            "[Rule]\nDOMAIN-KEYWORD,tracker,REJECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        assert_eq!(r.decide(&dest_host("foo.tracker.net")), Action::Reject);
        assert_eq!(r.decide(&dest_host("example.com")), Action::Proxy);
    }

    #[test]
    fn rule_set_lines_skipped_never_match() {
        let text = r#"
[Rule]
RULE-SET,https://example.invalid/cn.list,DIRECT
RULE-SET,https://example.invalid/ads.list,REJECT
DOMAIN,real.example,DIRECT
FINAL,PROXY
"#;
        let r = compile(text, None).unwrap();
        assert_eq!(r.rule_set_skipped(), 2);
        assert_eq!(r.decide(&dest_host("real.example")), Action::Direct);
        // Would have been DIRECT/REJECT if RULE-SET were fetched.
        assert_eq!(r.decide(&dest_host("cn.example")), Action::Proxy);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(1, 2, 3, 4))), Action::Proxy);
    }

    #[test]
    fn missing_geoip_country_fails_naming_line() {
        let geo = fixture_geoip();
        let text = "[Rule]\nGEOIP,zz,DIRECT\nFINAL,PROXY\n";
        let e = compile(text, Some(&geo)).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("line 2"), "{s}");
        assert!(s.contains("GeoIP country code zz not found"), "{s}");
    }

    #[test]
    fn skip_proxy_beats_later_proxy() {
        let text = r#"
[General]
skip-proxy = example.com, 8.8.8.8/32
[Rule]
DOMAIN,example.com,PROXY
IP-CIDR,8.8.8.8/32,PROXY
FINAL,PROXY
"#;
        let r = compile(text, None).unwrap();
        assert_eq!(r.decide(&dest_host("example.com")), Action::Direct);
        assert_eq!(r.decide(&dest_host("www.example.com")), Action::Direct);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(8, 8, 8, 8))), Action::Direct);
        assert_eq!(r.decide(&dest_host("other.com")), Action::Proxy);
    }

    #[test]
    fn host_matches_domain_before_ip() {
        let text = r#"
[Rule]
DOMAIN-SUFFIX,google.com,REJECT
IP-CIDR,8.8.8.8/32,DIRECT
FINAL,PROXY
"#;
        let r = compile(text, None).unwrap();
        let both = Dest {
            host: Some("dns.google.com".into()),
            ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            port: 443,
            proto: Proto::Tcp,
        };
        assert_eq!(r.decide(&both), Action::Reject);
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(8, 8, 8, 8))), Action::Direct);
    }

    #[test]
    fn ip_only_ignores_domain_rules() {
        let text = r#"
[Rule]
DOMAIN-SUFFIX,google.com,REJECT
FINAL,PROXY
"#;
        let r = compile(text, None).unwrap();
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(8, 8, 8, 8))), Action::Proxy);
    }

    #[test]
    fn unknown_pol_skipped_unknown_final_fails() {
        let ok = compile(
            "[Rule]\nDOMAIN,a.example,YOUTUBE\nDOMAIN,b.example,DIRECT\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        assert_eq!(ok.decide(&dest_host("a.example")), Action::Proxy);
        assert_eq!(ok.decide(&dest_host("b.example")), Action::Direct);

        let e = compile("[Rule]\nFINAL,YOUTUBE\n", None).unwrap_err();
        let s = e.to_string();
        assert!(s.contains("FINAL"), "{s}");
        assert!(s.contains("YOUTUBE"), "{s}");
    }

    #[test]
    fn case_insensitive_and_inline_comment() {
        let text = "[rule]\ndomain-suffix,Example.COM,direct # note\nfinal,proxy\n";
        let r = compile(text, None).unwrap();
        assert_eq!(r.decide(&dest_host("WWW.EXAMPLE.COM")), Action::Direct);
    }

    #[test]
    fn compile_file_and_missing_final_defaults_proxy() {
        let dir = std::env::temp_dir().join(format!("hy-route-cf-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("r.conf");
        std::fs::write(&p, "[Rule]\nDOMAIN,only.example,DIRECT\n").unwrap();
        let r = compile_file(&p, None).unwrap();
        assert_eq!(r.decide(&dest_host("only.example")), Action::Direct);
        assert_eq!(r.decide(&dest_host("other.example")), Action::Proxy);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bypass_cidr_is_direct() {
        let r = compile(
            "[General]\nbypass-tun = 172.16.0.0/12\n[Rule]\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        assert_eq!(r.decide(&dest_ip(Ipv4Addr::new(172, 16, 5, 1))), Action::Direct);
    }

    #[test]
    fn reject_drop_is_reject() {
        let r = compile("[Rule]\nDOMAIN,x.example,REJECT-DROP\nFINAL,PROXY\n", None).unwrap();
        assert_eq!(r.decide(&dest_host("x.example")), Action::Reject);
    }
}
