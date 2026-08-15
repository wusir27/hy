//! Pre-QUIC UDP hole punching (official `punch_engine.go`).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hy_core::io::DatagramIo;
use tokio::sync::mpsc;

use crate::realm::punch::{
    decode_punch_packet, decode_punch_metadata, encode_punch_packet, PunchMetadata, PunchPacket,
    PunchPacketType, PUNCH_MAX_WIRE_LEN,
};
use crate::realm::punch_conn::PunchPacketEvent;
use crate::realm::stun::AddrFamily;

pub const DEFAULT_PUNCH_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_PUNCH_INTERVAL: Duration = Duration::from_millis(100);
const SYMMETRIC_NAT_PORT_GAP: u16 = 4;
const SYMMETRIC_NAT_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_NAT_MAX_PORTS_PER_HOST: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidPunchConfig(pub String);

impl std::fmt::Display for ErrInvalidPunchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid punch config: {}", self.0)
    }
}
impl std::error::Error for ErrInvalidPunchConfig {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrPunchTimeout;

impl std::fmt::Display for ErrPunchTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "punch timed out")
    }
}
impl std::error::Error for ErrPunchTimeout {}

#[derive(Debug, Clone)]
pub struct PunchConfig {
    pub timeout: Duration,
    pub interval: Duration,
    pub family: AddrFamily,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PUNCH_TIMEOUT,
            interval: DEFAULT_PUNCH_INTERVAL,
            family: AddrFamily::Any,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PunchResult {
    pub peer_addr: SocketAddr,
    pub packet: PunchPacket,
}

/// Punch owning `conn` reads until success/timeout (client-style).
pub async fn punch(
    conn: &dyn DatagramIo,
    local_addrs: &[SocketAddr],
    peer_addrs: &[SocketAddr],
    meta: &PunchMetadata,
    config: PunchConfig,
) -> Result<PunchResult, Box<dyn std::error::Error + Send + Sync>> {
    decode_punch_metadata(meta)?;
    let candidates = candidate_punch_addrs(local_addrs, peer_addrs, config.family);
    if candidates.is_empty() {
        return Err(Box::new(ErrInvalidPunchConfig(
            "no compatible peer addresses".into(),
        )));
    }
    let timeout = if config.timeout.is_zero() {
        DEFAULT_PUNCH_TIMEOUT
    } else {
        config.timeout
    };
    let interval = if config.interval.is_zero() {
        DEFAULT_PUNCH_INTERVAL
    } else {
        config.interval
    };
    if interval.is_zero() {
        return Err(Box::new(ErrInvalidPunchConfig(
            "interval must be positive".into(),
        )));
    }

    let deadline = tokio::time::Instant::now() + timeout;
    let mut next_send = tokio::time::Instant::now();
    let mut buf = vec![0u8; PUNCH_MAX_WIRE_LEN];
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(Box::new(ErrPunchTimeout));
        }
        let now = tokio::time::Instant::now();
        if now >= next_send {
            send_punch_packets(conn, &candidates, meta, PunchPacketType::Hello).await;
            next_send = now + interval;
        }
        let wait = next_send.min(deadline).saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(wait, conn.recv_from(&mut buf)).await {
            Ok(Ok((n, addr))) => {
                if let Ok(packet) = decode_punch_packet(&buf[..n], meta) {
                    if packet.ty == PunchPacketType::Hello {
                        let _ = send_punch_packet(conn, addr, meta, PunchPacketType::Ack).await;
                    }
                    return Ok(PunchResult {
                        peer_addr: addr,
                        packet,
                    });
                }
            }
            Ok(Err(e)) => return Err(Box::new(e)),
            Err(_) => continue,
        }
    }
}

/// Server-style punch using demuxed events from `PunchPacketConn`.
pub async fn punch_via_events(
    conn: &dyn DatagramIo,
    mut events: mpsc::Receiver<PunchPacketEvent>,
    attempt_id: &str,
    local_addrs: &[SocketAddr],
    peer_addrs: &[SocketAddr],
    meta: &PunchMetadata,
    config: PunchConfig,
) -> Result<PunchResult, Box<dyn std::error::Error + Send + Sync>> {
    decode_punch_metadata(meta)?;
    let candidates = candidate_punch_addrs(local_addrs, peer_addrs, config.family);
    if candidates.is_empty() {
        return Err(Box::new(ErrInvalidPunchConfig(
            "no compatible peer addresses".into(),
        )));
    }
    let timeout = if config.timeout.is_zero() {
        DEFAULT_PUNCH_TIMEOUT
    } else {
        config.timeout
    };
    let interval = if config.interval.is_zero() {
        DEFAULT_PUNCH_INTERVAL
    } else {
        config.interval
    };

    send_punch_packets(conn, &candidates, meta, PunchPacketType::Hello).await;
    let mut ticker = tokio::time::interval(interval);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err(Box::new(ErrPunchTimeout)),
            _ = ticker.tick() => {
                send_punch_packets(conn, &candidates, meta, PunchPacketType::Hello).await;
            }
            ev = events.recv() => {
                let Some(ev) = ev else {
                    return Err(Box::new(ErrPunchTimeout));
                };
                if ev.attempt_id != attempt_id {
                    continue;
                }
                if ev.packet.ty == PunchPacketType::Hello {
                    let _ = send_punch_packet(conn, ev.from, meta, PunchPacketType::Ack).await;
                }
                return Ok(PunchResult {
                    peer_addr: ev.from,
                    packet: ev.packet,
                });
            }
        }
    }
}

async fn send_punch_packets(
    conn: &dyn DatagramIo,
    addrs: &[SocketAddr],
    meta: &PunchMetadata,
    packet_type: PunchPacketType,
) {
    for addr in addrs {
        let _ = send_punch_packet(conn, *addr, meta, packet_type).await;
    }
}

async fn send_punch_packet(
    conn: &dyn DatagramIo,
    addr: SocketAddr,
    meta: &PunchMetadata,
    packet_type: PunchPacketType,
) -> std::io::Result<usize> {
    let packet = encode_punch_packet(packet_type, meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    conn.send_to(&packet, addr).await
}

pub fn candidate_punch_addrs(
    local_addrs: &[SocketAddr],
    peer_addrs: &[SocketAddr],
    family: AddrFamily,
) -> Vec<SocketAddr> {
    let allowed = punch_families(local_addrs, family);
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for addr in peer_addrs {
        if addr.port() == 0 {
            continue;
        }
        if !allowed.allows(addr.ip()) {
            continue;
        }
        if seen.insert(*addr) {
            candidates.push(*addr);
        }
    }
    candidates = expand_symmetric_nat_candidates(candidates, &mut seen);
    candidates.sort_by_key(|a| a.to_string());
    candidates
}

pub fn expand_symmetric_nat_candidates(
    mut candidates: Vec<SocketAddr>,
    seen: &mut HashSet<SocketAddr>,
) -> Vec<SocketAddr> {
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for addr in &candidates {
        if let IpAddr::V4(_) = addr.ip() {
            ports_by_ip.entry(addr.ip()).or_default().push(addr.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if !predictable_port_group(&ports) {
            continue;
        }
        let start = ports[0] as u32;
        let mut end = ports[ports.len() - 1] as u32 + SYMMETRIC_NAT_EXTRA_PORTS as u32;
        if end > 65535 {
            end = 65535;
        }
        let mut added = 0usize;
        let mut port = start;
        while port <= end && added < SYMMETRIC_NAT_MAX_PORTS_PER_HOST {
            let addr = SocketAddr::new(ip, port as u16);
            if seen.insert(addr) {
                candidates.push(addr);
                added += 1;
            }
            port += 1;
        }
    }
    candidates
}

fn predictable_port_group(ports: &[u16]) -> bool {
    if ports.len() < 2 {
        return false;
    }
    for i in 1..ports.len() {
        if ports[i].saturating_sub(ports[i - 1]) > SYMMETRIC_NAT_PORT_GAP {
            return false;
        }
    }
    true
}

struct PunchFamilySet {
    v4: bool,
    v6: bool,
}

impl PunchFamilySet {
    fn allows(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

fn punch_families(local_addrs: &[SocketAddr], family: AddrFamily) -> PunchFamilySet {
    match family {
        AddrFamily::V4 => return PunchFamilySet { v4: true, v6: false },
        AddrFamily::V6 => return PunchFamilySet { v4: false, v6: true },
        AddrFamily::Any => {}
    }
    let mut families = PunchFamilySet {
        v4: false,
        v6: false,
    };
    for addr in local_addrs {
        match addr.ip() {
            IpAddr::V4(_) => families.v4 = true,
            IpAddr::V6(_) => families.v6 = true,
        }
    }
    if !families.v4 && !families.v6 {
        families.v4 = true;
        families.v6 = true;
    }
    families
}
