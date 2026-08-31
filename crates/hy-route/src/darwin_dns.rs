//! Darwin system DNS magnet: `networksetup` parsers and argv (no live call on Linux).
//!
//! After utun is up, set the DirectDialer physical NIC's service DNS to `1.1.1.1`
//! so `1.1.1.1:53` follows `0.0.0.0/0` into the TUN hijack. Restore to DHCP
//! (`empty`) on Drop / TUN stop. Never target `utun*`.

use crate::direct::is_utun_name;
use crate::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};

/// Magnet address only (not `8.8.8.8`).
pub const MAGNET_DNS: &str = "1.1.1.1";

/// Parse `networksetup -listallhardwareports` into Device → Hardware Port.
/// Skips `utun*` devices.
pub fn parse_hardware_ports(stdout: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut port: Option<String> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Hardware Port:") {
            port = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = line.strip_prefix("Device:") {
            let dev = rest.trim().to_string();
            if let Some(p) = port.take() {
                if p.is_empty() || dev.is_empty() || is_utun_name(&dev) {
                    continue;
                }
                out.push((dev, p));
            }
        }
    }
    out
}

/// Hardware Port (networksetup service) for a Device name. Rejects `utun*`.
pub fn service_for_device(ports: &[(String, String)], device: &str) -> Result<String, Error> {
    if is_utun_name(device) {
        return Err(Error::dns(format!(
            "refusing networksetup on utun {device}"
        )));
    }
    ports
        .iter()
        .find(|(dev, _)| dev == device)
        .map(|(_, port)| port.clone())
        .ok_or_else(|| Error::dns(format!("no Hardware Port for Device {device}")))
}

/// `networksetup -setdnsservers <service> 1.1.1.1`
pub fn set_dnsservers_argv(service: &str) -> Vec<String> {
    vec![
        "networksetup".into(),
        "-setdnsservers".into(),
        service.into(),
        MAGNET_DNS.into(),
    ]
}

/// `networksetup -setdnsservers <service> empty` (DHCP).
pub fn restore_dnsservers_argv(service: &str) -> Vec<String> {
    vec![
        "networksetup".into(),
        "-setdnsservers".into(),
        service.into(),
        "empty".into(),
    ]
}

/// Restores the service DNS to DHCP on Drop. Actual `networksetup` only on macOS.
pub struct DarwinDnsRestore {
    service: String,
    done: AtomicBool,
}

impl DarwinDnsRestore {
    pub fn new(service: String) -> Self {
        Self {
            service,
            done: AtomicBool::new(false),
        }
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn restore(&self) {
        if self.done.swap(true, Ordering::SeqCst) {
            return;
        }
        #[cfg(target_os = "macos")]
        {
            let argv = restore_dnsservers_argv(&self.service);
            if let Err(e) = run_networksetup(&argv) {
                tracing::error!(error = %e, service = %self.service, "restore Darwin DNS failed");
            }
        }
    }
}

impl Drop for DarwinDnsRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Map Device → Hardware Port and set magnet DNS. Caller must not pass `utun*`.
#[cfg(target_os = "macos")]
pub fn hijack_system_dns(device: &str) -> Result<DarwinDnsRestore, Error> {
    if is_utun_name(device) {
        return Err(Error::dns(format!(
            "refusing networksetup on utun {device}"
        )));
    }
    let out = std::process::Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
        .map_err(|e| Error::dns(format!("networksetup -listallhardwareports: {e}")))?;
    if !out.status.success() {
        return Err(Error::dns(format!(
            "networksetup -listallhardwareports failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let ports = parse_hardware_ports(&String::from_utf8_lossy(&out.stdout));
    let service = service_for_device(&ports, device)?;
    let argv = set_dnsservers_argv(&service);
    run_networksetup(&argv)?;
    tracing::info!(device, service = %service, dns = MAGNET_DNS, "darwin system DNS magnet");
    Ok(DarwinDnsRestore::new(service))
}

#[cfg(target_os = "macos")]
fn run_networksetup(argv: &[String]) -> Result<(), Error> {
    if argv.is_empty() {
        return Err(Error::dns("empty networksetup argv"));
    }
    let out = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| Error::dns(format!("networksetup: {e}")))?;
    if !out.status.success() {
        return Err(Error::dns(format!(
            "{} failed: {}",
            argv.join(" "),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\n\
Hardware Port: Ethernet\n\
Device: en0\n\
Ethernet Address: 00:11:22:33:44:55\n\
\n\
Hardware Port: Wi-Fi\n\
Device: en1\n\
Ethernet Address: aa:bb:cc:dd:ee:ff\n\
\n\
Hardware Port: iPhone USB\n\
Device: en6\n\
Ethernet Address: bb:bb:bb:bb:bb:bb\n\
\n\
Hardware Port: utun leftover\n\
Device: utun2\n\
Ethernet Address: N/A\n\
\n\
VLAN Configurations\n\
===================\n\
";

    #[test]
    fn parse_listallhardwareports_device_to_hardware_port() {
        let ports = parse_hardware_ports(FIXTURE);
        assert_eq!(
            ports,
            vec![
                ("en0".into(), "Ethernet".into()),
                ("en1".into(), "Wi-Fi".into()),
                ("en6".into(), "iPhone USB".into()),
            ]
        );
        assert!(
            !ports.iter().any(|(d, _)| is_utun_name(d)),
            "utun must not appear"
        );
        assert_eq!(service_for_device(&ports, "en1").unwrap(), "Wi-Fi");
        assert_eq!(service_for_device(&ports, "en0").unwrap(), "Ethernet");
        let e = service_for_device(&ports, "utun0").unwrap_err();
        assert!(e.to_string().contains("utun"), "{e}");
        let e = service_for_device(&ports, "en99").unwrap_err();
        assert!(e.to_string().contains("en99"), "{e}");
    }

    #[test]
    fn set_and_restore_dnsservers_argv() {
        let set = set_dnsservers_argv("Wi-Fi");
        assert_eq!(set, ["networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1"]);
        assert!(!set.iter().any(|a| a.contains("8.8.8.8")));
        let restore = restore_dnsservers_argv("Wi-Fi");
        assert_eq!(
            restore,
            ["networksetup", "-setdnsservers", "Wi-Fi", "empty"]
        );
        assert_eq!(restore.last().map(String::as_str), Some("empty"));
        let set_eth = set_dnsservers_argv("Ethernet");
        assert_eq!(set_eth[2], "Ethernet");
        assert_eq!(set_eth[3], MAGNET_DNS);
    }
}
