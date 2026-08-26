//! Linux policy routing for DIRECT / marked QUIC (`fwmark` → table 162).
//!
//! Command construction and "already exists" skip are unit-tested without
//! `CAP_NET_ADMIN`. The real `ip` runner is injected.

pub const DEFAULT_FWMARK: u32 = 0x162;
pub const POLICY_TABLE: u32 = 162;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRoutingError {
    pub commands: Vec<String>,
    pub cause: String,
}

impl std::fmt::Display for PolicyRoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "policy routing failed: {}; commands: {}",
            self.cause,
            self.commands.join(" ; ")
        )
    }
}

impl std::error::Error for PolicyRoutingError {}

pub fn parse_fwmark(s: Option<&str>) -> Result<u32, String> {
    let Some(raw) = s.map(str::trim).filter(|t| !t.is_empty()) else {
        return Ok(DEFAULT_FWMARK);
    };
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    u32::from_str_radix(hex, 16).map_err(|e| format!("bad --route-fwmark {raw}: {e}"))
}

pub fn format_fwmark(mark: u32) -> String {
    format!("0x{mark:x}")
}

pub fn rule_args(mark: u32, table: u32) -> Vec<String> {
    vec![
        "rule".into(),
        "add".into(),
        "fwmark".into(),
        format_fwmark(mark),
        "lookup".into(),
        table.to_string(),
    ]
}

pub fn route_args(via: Option<&str>, dev: &str, table: u32) -> Vec<String> {
    let mut v = vec!["route".into(), "add".into(), "default".into()];
    if let Some(gw) = via {
        v.push("via".into());
        v.push(gw.to_string());
    }
    v.push("dev".into());
    v.push(dev.to_string());
    v.push("table".into());
    v.push(table.to_string());
    v
}

pub fn format_ip_command(args: &[String]) -> String {
    format!("ip {}", args.join(" "))
}

pub fn is_already_exists(stderr: &str) -> bool {
    stderr.to_ascii_lowercase().contains("file exists")
}

/// Parse `ip -4 route show default` (first default line).
pub fn parse_ip_default_route(stdout: &str) -> Option<(Option<String>, String)> {
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("default") {
            continue;
        }
        let mut via = None;
        let mut dev = None;
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            match tok {
                "via" => via = it.next().map(|s| s.to_string()),
                "dev" => dev = it.next().map(|s| s.to_string()),
                _ => {}
            }
        }
        if let Some(d) = dev {
            return Some((via, d));
        }
    }
    None
}

pub fn is_tunnel_nic(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("tun") || n.starts_with("utun")
}

/// `run(args)`: Ok on success; Err(stderr) on failure.
pub fn apply_policy_routing(
    mark: u32,
    table: u32,
    via: Option<&str>,
    dev: &str,
    mut run: impl FnMut(&[&str]) -> Result<(), String>,
) -> Result<(), PolicyRoutingError> {
    let rule = rule_args(mark, table);
    let route = route_args(via, dev, table);
    let commands = vec![format_ip_command(&rule), format_ip_command(&route)];
    let fail = |cause: String| PolicyRoutingError {
        commands: commands.clone(),
        cause,
    };

    let rule_ref: Vec<&str> = rule.iter().map(|s| s.as_str()).collect();
    match run(&rule_ref) {
        Ok(()) => {}
        Err(e) if is_already_exists(&e) => {}
        Err(e) => return Err(fail(e)),
    }
    let route_ref: Vec<&str> = route.iter().map(|s| s.as_str()).collect();
    match run(&route_ref) {
        Ok(()) => {}
        Err(e) if is_already_exists(&e) => {}
        Err(e) => return Err(fail(e)),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg_attr(not(feature = "client-route"), allow(dead_code))]
pub fn install_linux_policy_routing(mark: u32) -> Result<(), PolicyRoutingError> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            let rule = rule_args(mark, POLICY_TABLE);
            return Err(PolicyRoutingError {
                commands: vec![format_ip_command(&rule)],
                cause: format!("ip route show default: {e}"),
            });
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (via, dev) = parse_ip_default_route(&stdout).ok_or_else(|| PolicyRoutingError {
        commands: vec![
            format_ip_command(&rule_args(mark, POLICY_TABLE)),
            format_ip_command(&route_args(None, "<physical-nic>", POLICY_TABLE)),
        ],
        cause: format!("no default route in: {stdout}"),
    })?;
    if is_tunnel_nic(&dev) {
        return Err(PolicyRoutingError {
            commands: vec![format_ip_command(&route_args(
                via.as_deref(),
                &dev,
                POLICY_TABLE,
            ))],
            cause: format!("default route is tunnel {dev}, need a physical NIC"),
        });
    }
    let run = |args: &[&str]| {
        let o = std::process::Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        if o.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&o.stderr).trim().to_string())
        }
    };
    apply_policy_routing(mark, POLICY_TABLE, via.as_deref(), &dev, run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[test]
    fn parse_fwmark_default_and_hex() {
        assert_eq!(parse_fwmark(None).unwrap(), 0x162);
        assert_eq!(parse_fwmark(Some("")).unwrap(), 0x162);
        assert_eq!(parse_fwmark(Some("0x162")).unwrap(), 0x162);
        assert_eq!(parse_fwmark(Some("0X162")).unwrap(), 0x162);
        assert_eq!(parse_fwmark(Some("162")).unwrap(), 0x162);
        assert_eq!(parse_fwmark(Some("ff")).unwrap(), 0xff);
        assert!(parse_fwmark(Some("zzz")).is_err());
    }

    #[test]
    fn command_construction() {
        assert_eq!(POLICY_TABLE, 162);
        let r = rule_args(0x162, POLICY_TABLE);
        assert_eq!(
            r.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            ["rule", "add", "fwmark", "0x162", "lookup", "162"]
        );
        assert_eq!(
            format_ip_command(&r),
            "ip rule add fwmark 0x162 lookup 162"
        );
        let rt = route_args(Some("192.168.1.1"), "eth0", 162);
        assert_eq!(
            format_ip_command(&rt),
            "ip route add default via 192.168.1.1 dev eth0 table 162"
        );
        let onlink = route_args(None, "enp1s0", 162);
        assert_eq!(
            format_ip_command(&onlink),
            "ip route add default dev enp1s0 table 162"
        );
    }

    #[test]
    fn parse_default_route_via_dev() {
        let s = "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100\n";
        let (via, dev) = parse_ip_default_route(s).unwrap();
        assert_eq!(via.as_deref(), Some("192.0.2.1"));
        assert_eq!(dev, "eth0");
        let s = "default dev wlan0 scope link\n";
        let (via, dev) = parse_ip_default_route(s).unwrap();
        assert!(via.is_none());
        assert_eq!(dev, "wlan0");
        assert!(is_tunnel_nic("tun0"));
        assert!(is_tunnel_nic("utun3"));
        assert!(!is_tunnel_nic("eth0"));
    }

    #[test]
    fn skip_if_already_exists() {
        let n = AtomicUsize::new(0);
        let calls: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let run = |args: &[&str]| {
            n.fetch_add(1, Ordering::SeqCst);
            calls.lock().unwrap().push(args.join(" "));
            Err("RTNETLINK answers: File exists".into())
        };
        apply_policy_routing(0x162, 162, Some("10.0.0.1"), "eth0", run).unwrap();
        assert_eq!(n.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn failure_surfaces_exact_commands() {
        let run = |args: &[&str]| {
            if args.first() == Some(&"rule") {
                Ok(())
            } else {
                Err("Nexthop has invalid gateway".into())
            }
        };
        let e = apply_policy_routing(0x162, 162, Some("192.168.0.1"), "eth0", run).unwrap_err();
        assert!(e.cause.contains("invalid gateway"), "{e}");
        assert!(
            e.commands
                .iter()
                .any(|c| c == "ip rule add fwmark 0x162 lookup 162"),
            "{:?}",
            e.commands
        );
        assert!(
            e.commands.iter().any(|c| c.contains("ip route add default via 192.168.0.1 dev eth0 table 162")),
            "{:?}",
            e.commands
        );
        let s = e.to_string();
        assert!(s.contains("ip rule add fwmark 0x162 lookup 162"), "{s}");
        assert!(s.contains("ip route add default via 192.168.0.1 dev eth0 table 162"), "{s}");
    }

    #[test]
    fn already_exists_helper() {
        assert!(is_already_exists("RTNETLINK answers: File exists\n"));
        assert!(is_already_exists("Error: File exists"));
        assert!(!is_already_exists("Network is unreachable"));
    }
}
