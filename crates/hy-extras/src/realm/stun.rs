//! Minimal STUN Binding discovery (RFC 5389), no external STUN crate.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hy_core::io::DatagramIo;
use rand::RngCore;

pub const DEFAULT_STUN_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_STUN_PORT: u16 = 3478;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidSTUNConfig(pub String);

impl std::fmt::Display for ErrInvalidSTUNConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid STUN config: {}", self.0)
    }
}
impl std::error::Error for ErrInvalidSTUNConfig {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrFamily {
    #[default]
    Any,
    V4,
    V6,
}

impl AddrFamily {
    pub fn allows(self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::V4 => ip.is_ipv4(),
            Self::V6 => ip.is_ipv6(),
        }
    }

    pub fn from_ip_mode(mode: &str) -> Result<Self, String> {
        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "dual" => Ok(Self::Any),
            "v4" => Ok(Self::V4),
            "v6" => Ok(Self::V6),
            other => Err(format!(
                "invalid ipMode {other:?} (expected v4, v6, or dual)"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct STUNConfig {
    pub servers: Vec<String>,
    pub timeout: Duration,
    pub family: AddrFamily,
}

/// Fast check: STUN messages have top two bits clear and magic cookie.
pub fn is_stun_message(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }
    if packet[0] & 0xc0 != 0 {
        return false;
    }
    let cookie = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    cookie == MAGIC_COOKIE
}

pub fn parse_stun_binding_response(packet: &[u8]) -> Result<([u8; 12], SocketAddr), String> {
    if !is_stun_message(packet) {
        return Err("not stun".into());
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != BINDING_SUCCESS {
        return Err("not binding success".into());
    }
    let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if packet.len() < 20 + len {
        return Err("truncated".into());
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&packet[8..20]);
    let mut i = 20;
    let end = 20 + len;
    let mut mapped: Option<SocketAddr> = None;
    let mut xor_mapped: Option<SocketAddr> = None;
    while i + 4 <= end {
        let atype = u16::from_be_bytes([packet[i], packet[i + 1]]);
        let alen = u16::from_be_bytes([packet[i + 2], packet[i + 3]]) as usize;
        i += 4;
        if i + alen > end {
            break;
        }
        let val = &packet[i..i + alen];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Ok(a) = parse_xor_mapped(val, &txid) {
                    xor_mapped = Some(a);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if let Ok(a) = parse_mapped(val) {
                    mapped = Some(a);
                }
            }
            _ => {}
        }
        i += alen;
        // 32-bit padding
        let pad = (4 - (alen % 4)) % 4;
        i += pad;
    }
    let addr = xor_mapped.or(mapped).ok_or_else(|| "no mapped address".to_string())?;
    Ok((txid, addr))
}

fn parse_mapped(val: &[u8]) -> Result<SocketAddr, ()> {
    if val.len() < 4 {
        return Err(());
    }
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);
    match family {
        0x01 if val.len() >= 8 => {
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 if val.len() >= 20 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&val[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(a)), port))
        }
        _ => Err(()),
    }
}

fn parse_xor_mapped(val: &[u8], txid: &[u8; 12]) -> Result<SocketAddr, ()> {
    if val.len() < 4 {
        return Err(());
    }
    let family = val[1];
    let xport = u16::from_be_bytes([val[2], val[3]]);
    let port = xport ^ ((MAGIC_COOKIE >> 16) as u16);
    match family {
        0x01 if val.len() >= 8 => {
            let mut ipb = [val[4], val[5], val[6], val[7]];
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                ipb[i] ^= cookie[i];
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ipb)), port))
        }
        0x02 if val.len() >= 20 => {
            let mut ipb = [0u8; 16];
            ipb.copy_from_slice(&val[4..20]);
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                ipb[i] ^= cookie[i];
            }
            for i in 0..12 {
                ipb[4 + i] ^= txid[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ipb)), port))
        }
        _ => Err(()),
    }
}

fn build_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut msg = vec![0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg[2..4].copy_from_slice(&0u16.to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(txid);
    msg
}

/// Encode a Binding Success with XOR-MAPPED-ADDRESS (RFC 5389).
#[cfg(test)]
pub(crate) fn encode_binding_success(txid: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let (family, mut xor_addr, port): (u8, Vec<u8>, u16) = match mapped {
        SocketAddr::V4(sa) => (0x01, sa.ip().octets().to_vec(), sa.port()),
        SocketAddr::V6(sa) => (0x02, sa.ip().octets().to_vec(), sa.port()),
    };
    let xport = port ^ ((MAGIC_COOKIE >> 16) as u16);
    let cookie = MAGIC_COOKIE.to_be_bytes();
    for i in 0..xor_addr.len().min(4) {
        xor_addr[i] ^= cookie[i];
    }
    if xor_addr.len() == 16 {
        for i in 0..12 {
            xor_addr[4 + i] ^= txid[i];
        }
    }
    let val_len = 4 + xor_addr.len();
    let mut attr = Vec::with_capacity(4 + val_len);
    attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    attr.extend_from_slice(&(val_len as u16).to_be_bytes());
    attr.push(0);
    attr.push(family);
    attr.extend_from_slice(&xport.to_be_bytes());
    attr.extend_from_slice(&xor_addr);
    let pad = (4 - (attr.len() % 4)) % 4;
    attr.extend(std::iter::repeat(0u8).take(pad));

    let mut msg = vec![0u8; 20];
    msg[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg[2..4].copy_from_slice(&(attr.len() as u16).to_be_bytes());
    msg[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg[8..20].copy_from_slice(txid);
    msg.extend_from_slice(&attr);
    msg
}

#[cfg(test)]
pub(crate) fn parse_binding_request_txid(packet: &[u8]) -> Option<[u8; 12]> {
    if !is_stun_message(packet) {
        return None;
    }
    let msg_type = u16::from_be_bytes([packet[0], packet[1]]);
    if msg_type != BINDING_REQUEST {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&packet[8..20]);
    Some(txid)
}

pub(crate) async fn send_discover_requests(
    conn: &dyn DatagramIo,
    config: STUNConfig,
) -> Result<(HashMap<[u8; 12], SocketAddr>, Duration), ErrInvalidSTUNConfig> {
    if config.servers.is_empty() {
        return Err(ErrInvalidSTUNConfig(
            "at least one STUN server is required".into(),
        ));
    }
    let timeout = if config.timeout.is_zero() {
        DEFAULT_STUN_TIMEOUT
    } else {
        config.timeout
    };
    let family = effective_family(config.family, conn.local_addr().ok());
    let stun_addrs = resolve_stun_servers(&config.servers, family).await?;
    if stun_addrs.is_empty() {
        return Err(ErrInvalidSTUNConfig(
            "no STUN server addresses match the local socket family".into(),
        ));
    }

    let mut transactions: HashMap<[u8; 12], SocketAddr> = HashMap::new();
    for addr in &stun_addrs {
        let mut txid = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut txid);
        let msg = build_binding_request(&txid);
        if conn.send_to(&msg, *addr).await.is_ok() {
            transactions.insert(txid, *addr);
        }
    }
    if transactions.is_empty() {
        return Err(ErrInvalidSTUNConfig(
            "failed to send STUN binding requests".into(),
        ));
    }
    Ok((transactions, timeout))
}

pub(crate) fn mapped_addrs_from_results(
    results: HashMap<SocketAddr, ()>,
) -> Result<Vec<SocketAddr>, ErrInvalidSTUNConfig> {
    if results.is_empty() {
        return Err(ErrInvalidSTUNConfig(
            "no STUN responses received".into(),
        ));
    }
    let mut addrs: Vec<SocketAddr> = results.into_keys().collect();
    addrs.sort_by_key(|a| a.to_string());
    Ok(addrs)
}

/// Discover reflexive addresses via STUN using `conn.recv_from`.
///
/// Do **not** call this on a [`crate::realm::punch_conn::PunchPacketConn`]: that
/// type siphons Binding Success onto its STUN event channel, so `recv_from`
/// never returns those packets. Use [`crate::realm::punch_conn::discover_on_punch`].
pub async fn discover(
    conn: &dyn DatagramIo,
    config: STUNConfig,
) -> Result<Vec<SocketAddr>, ErrInvalidSTUNConfig> {
    let (mut transactions, timeout) = send_discover_requests(conn, config).await?;
    let mut results: HashMap<SocketAddr, ()> = HashMap::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = vec![0u8; 1500];
    while !transactions.is_empty() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, conn.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                if let Ok((txid, mapped)) = parse_stun_binding_response(&buf[..n]) {
                    if transactions.remove(&txid).is_some() {
                        results.insert(mapped, ());
                    }
                }
            }
            Ok(Err(e)) => return Err(ErrInvalidSTUNConfig(e.to_string())),
            Err(_) => break,
        }
    }
    mapped_addrs_from_results(results)
}

fn effective_family(family: AddrFamily, local: Option<SocketAddr>) -> AddrFamily {
    if family != AddrFamily::Any {
        return family;
    }
    match local {
        Some(a) if !a.ip().is_unspecified() => {
            if a.ip().is_ipv4() {
                AddrFamily::V4
            } else {
                AddrFamily::V6
            }
        }
        _ => AddrFamily::Any,
    }
}

async fn resolve_stun_servers(
    servers: &[String],
    family: AddrFamily,
) -> Result<Vec<SocketAddr>, ErrInvalidSTUNConfig> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for server in servers {
        let (host, port) = split_stun_server(server)?;
        let lookup = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| ErrInvalidSTUNConfig(e.to_string()))?;
        for sa in lookup {
            if !family.allows(sa.ip()) {
                continue;
            }
            let key = sa.to_string();
            if seen.insert(key) {
                out.push(sa);
            }
        }
    }
    Ok(out)
}

fn split_stun_server(server: &str) -> Result<(String, u16), ErrInvalidSTUNConfig> {
    if server.is_empty() {
        return Err(ErrInvalidSTUNConfig("STUN server is empty".into()));
    }
    if let Ok(sa) = server.parse::<SocketAddr>() {
        return Ok((sa.ip().to_string(), sa.port()));
    }
    if let Some((h, p)) = server.rsplit_once(':') {
        if !h.contains(':') {
            let port: u16 = p
                .parse()
                .map_err(|_| ErrInvalidSTUNConfig("invalid STUN server address".into()))?;
            if h.is_empty() || port == 0 {
                return Err(ErrInvalidSTUNConfig("invalid STUN server address".into()));
            }
            return Ok((h.to_string(), port));
        }
    }
    // bare host or IPv6 without port
    if server.parse::<IpAddr>().is_ok() || !server.contains(':') {
        return Ok((server.to_string(), DEFAULT_STUN_PORT));
    }
    Err(ErrInvalidSTUNConfig(
        "invalid STUN server address".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mapped_binding_success_roundtrip() {
        let txid = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];
        let mapped: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let pkt = encode_binding_success(&txid, mapped);
        let (got_txid, got_addr) = parse_stun_binding_response(&pkt).unwrap();
        assert_eq!(got_txid, txid);
        assert_eq!(got_addr, mapped);
    }

    #[test]
    fn parse_binding_request_txid_matches_builder() {
        let txid = [9u8; 12];
        let req = build_binding_request(&txid);
        assert_eq!(parse_binding_request_txid(&req), Some(txid));
        assert!(parse_binding_request_txid(&encode_binding_success(&txid, "1.2.3.4:1".parse().unwrap())).is_none());
    }
}
