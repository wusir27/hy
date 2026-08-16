//! Linux TUN inbound (`tun`).
//!
//! Opens `/dev/net/tun` (IFF_TUN|IFF_NO_PI), configures address/MTU/routes, then
//! runs a userspace IPv4 TCP/UDP stack that dials via `client.tcp` / `client.udp`.
//! ICMP is ignored (official does not proxy ICMP). Privilege failures are logged
//! and returned — never swallowed.

use crate::config::TunConfig;
use crate::inbound::tun_plan::{prepend_family, strip_family};
pub use crate::inbound::tun_plan::parse_utun_unit;
use hy_core::client::{Client, HyTcpConn};
use hy_core::Error;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// Parsed IPv4 header fields used by the dataplane and unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub header_len: usize,
    pub total_len: usize,
}

/// Parse an IPv4 header (no options required beyond IHL).
pub fn parse_ipv4(pkt: &[u8]) -> Option<Ipv4Info> {
    if pkt.len() < 20 {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl || total_len > pkt.len() {
        return None;
    }
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some(Ipv4Info {
        src,
        dst,
        proto,
        header_len: ihl,
        total_len,
    })
}

/// UDP header: src port, dst port, payload offset within the IP packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_off: usize,
    pub payload_len: usize,
}

pub fn parse_udp(pkt: &[u8], ip: &Ipv4Info) -> Option<UdpInfo> {
    let off = ip.header_len;
    if ip.total_len < off + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    let dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
    let ulen = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]) as usize;
    if ulen < 8 || off + ulen > ip.total_len {
        return None;
    }
    Some(UdpInfo {
        src_port,
        dst_port,
        payload_off: off + 8,
        payload_len: ulen - 8,
    })
}

/// TCP header (ports + flags + seq/ack + data offset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub header_len: usize,
    pub payload_off: usize,
    pub payload_len: usize,
}

pub fn parse_tcp(pkt: &[u8], ip: &Ipv4Info) -> Option<TcpInfo> {
    let off = ip.header_len;
    if ip.total_len < off + 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    let dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
    let seq = u32::from_be_bytes([pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]]);
    let ack = u32::from_be_bytes([pkt[off + 8], pkt[off + 9], pkt[off + 10], pkt[off + 11]]);
    let data_off = ((pkt[off + 12] >> 4) as usize) * 4;
    if data_off < 20 || off + data_off > ip.total_len {
        return None;
    }
    let flags = pkt[off + 13];
    Some(TcpInfo {
        src_port,
        dst_port,
        seq,
        ack,
        flags,
        header_len: data_off,
        payload_off: off + data_off,
        payload_len: ip.total_len - off - data_off,
    })
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in chunks.by_ref() {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_header_checksum(hdr: &mut [u8]) {
    hdr[10] = 0;
    hdr[11] = 0;
    let c = internet_checksum(hdr);
    hdr[10] = (c >> 8) as u8;
    hdr[11] = c as u8;
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_and_payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp_and_payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IP_PROTO_UDP);
    let len = udp_and_payload.len() as u16;
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(udp_and_payload);
    let c = internet_checksum(&pseudo);
    if c == 0 {
        0xffff
    } else {
        c
    }
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_and_payload: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp_and_payload.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IP_PROTO_TCP);
    let len = tcp_and_payload.len() as u16;
    pseudo.extend_from_slice(&len.to_be_bytes());
    pseudo.extend_from_slice(tcp_and_payload);
    internet_checksum(&pseudo)
}

fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // id
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/frag
    pkt[8] = 64; // TTL
    pkt[9] = proto;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    ipv4_header_checksum(&mut pkt[..20]);
    pkt[20..].copy_from_slice(payload);
    pkt
}

fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => build_udp_v4(s, d, payload),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => build_udp_v6(s, d, payload),
        _ => Vec::new(),
    }
}

fn build_udp_v4(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = vec![0u8; 8 + payload.len()];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    udp[4..6].copy_from_slice(&ulen.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let csum = udp_checksum(*src.ip(), *dst.ip(), &udp);
    udp[6..8].copy_from_slice(&csum.to_be_bytes());
    build_ipv4(*src.ip(), *dst.ip(), IP_PROTO_UDP, &udp)
}

fn build_tcp_segment(
    src: SocketAddr,
    dst: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => build_tcp_v4(s, d, seq, ack, flags, payload),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => build_tcp_v6(s, d, seq, ack, flags, payload),
        _ => Vec::new(),
    }
}

fn build_tcp_v4(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = vec![0u8; 20 + payload.len()];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50; // data offset = 5 (20 bytes)
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    tcp[20..].copy_from_slice(payload);
    let csum = tcp_checksum(*src.ip(), *dst.ip(), &tcp);
    tcp[16..18].copy_from_slice(&csum.to_be_bytes());
    build_ipv4(*src.ip(), *dst.ip(), IP_PROTO_TCP, &tcp)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Info {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub next: u8,
    pub header_len: usize,
    pub total_len: usize,
}

pub fn parse_ipv6(pkt: &[u8]) -> Option<Ipv6Info> {
    if pkt.len() < 40 || pkt[0] >> 4 != 6 {
        return None;
    }
    let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let total = 40 + plen;
    if pkt.len() < total {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
    Some(Ipv6Info {
        src,
        dst,
        next: pkt[6],
        header_len: 40,
        total_len: total,
    })
}

pub fn parse_udp6(pkt: &[u8], ip: &Ipv6Info) -> Option<UdpInfo> {
    parse_udp(
        pkt,
        &Ipv4Info {
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            proto: IP_PROTO_UDP,
            header_len: ip.header_len,
            total_len: ip.total_len,
        },
    )
}

pub fn parse_tcp6(pkt: &[u8], ip: &Ipv6Info) -> Option<TcpInfo> {
    parse_tcp(
        pkt,
        &Ipv4Info {
            src: Ipv4Addr::UNSPECIFIED,
            dst: Ipv4Addr::UNSPECIFIED,
            proto: IP_PROTO_TCP,
            header_len: ip.header_len,
            total_len: ip.total_len,
        },
    )
}

fn ip6_pseudo(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> u16 {
    let mut p = Vec::with_capacity(40 + payload.len());
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, next]);
    p.extend_from_slice(payload);
    internet_checksum(&p)
}

fn build_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + payload.len()];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt[6] = next;
    pkt[7] = 64;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..].copy_from_slice(payload);
    pkt
}

fn build_udp_v6(src: SocketAddrV6, dst: SocketAddrV6, payload: &[u8]) -> Vec<u8> {
    let mut udp = vec![0u8; 8 + payload.len()];
    udp[0..2].copy_from_slice(&src.port().to_be_bytes());
    udp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    udp[4..6].copy_from_slice(&ulen.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let c = ip6_pseudo(*src.ip(), *dst.ip(), IP_PROTO_UDP, &udp);
    let c = if c == 0 { 0xffff } else { c };
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    build_ipv6(*src.ip(), *dst.ip(), IP_PROTO_UDP, &udp)
}

fn build_tcp_v6(
    src: SocketAddrV6,
    dst: SocketAddrV6,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = vec![0u8; 20 + payload.len()];
    tcp[0..2].copy_from_slice(&src.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&dst.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
    tcp[20..].copy_from_slice(payload);
    let c = ip6_pseudo(*src.ip(), *dst.ip(), IP_PROTO_TCP, &tcp);
    tcp[16..18].copy_from_slice(&c.to_be_bytes());
    build_ipv6(*src.ip(), *dst.ip(), IP_PROTO_TCP, &tcp)
}

type PacketTx = mpsc::Sender<Vec<u8>>;

#[cfg(target_os = "linux")]
pub async fn run(cfg: TunConfig, client: Arc<dyn Client>) -> Result<(), Error> {
    let fd = match open_tun_fd(&cfg.name) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!(error = %e, "failed to create tun interface");
            return Err(Error::config(
                "tun",
                format!("failed to create tun interface: {e}"),
            ));
        }
    };
    if let Err(e) = configure_device(&cfg) {
        let _ = unsafe { libc::close(fd) };
        tracing::error!(error = %e, "failed to create tun interface");
        return Err(Error::config(
            "tun",
            format!("failed to create tun interface: {e}"),
        ));
    }

    tracing::info!(iface = %cfg.name, "TUN listening");
    run_dataplane(fd, cfg, client, false, false).await
}

#[cfg(target_os = "macos")]
pub async fn run(cfg: TunConfig, client: Arc<dyn Client>) -> Result<(), Error> {
    let fd = match crate::inbound::tun_darwin::open_and_configure(&cfg) {
        Ok(fd) => fd,
        Err(e) => {
            tracing::error!(error = %e, "failed to create tun interface");
            return Err(Error::config(
                "tun",
                format!("failed to create tun interface: {e}"),
            ));
        }
    };
    tracing::info!(iface = %cfg.name, "TUN listening");
    run_dataplane(fd, cfg, client, true, true).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn run(_cfg: TunConfig, _client: Arc<dyn Client>) -> Result<(), Error> {
    Err(Error::config("tun", "not supported"))
}

#[cfg(target_os = "linux")]
fn open_tun_fd(name: &str) -> std::io::Result<RawFd> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // Copy name (must fit IFNAMSIZ including NUL).
    let nb = name.as_bytes();
    if nb.len() >= libc::IFNAMSIZ {
        unsafe { libc::close(fd) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for (i, b) in nb.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

    let r = unsafe { libc::ioctl(fd, libc::TUNSETIFF, &mut ifr as *mut _) };
    if r < 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

#[cfg(target_os = "linux")]
fn configure_device(cfg: &TunConfig) -> std::io::Result<()> {
    run_ip(&["link", "set", "dev", &cfg.name, "mtu", &cfg.mtu.to_string()])?;
    // Replace any existing address then add.
    let _ = run_ip(&["addr", "flush", "dev", &cfg.name]);
    run_ip(&["addr", "add", &cfg.ipv4, "dev", &cfg.name])?;
    if let Some(ref v6) = cfg.ipv6 {
        match run_ip(&["addr", "add", v6, "dev", &cfg.name]) {
            Ok(()) => {}
            Err(e) => {
                tracing::warn!(error = %e, "tun IPv6 address not applied; IPv4 only");
            }
        }
    }
    run_ip(&["link", "set", "dev", &cfg.name, "up"])?;

    if let Some(ref route) = cfg.route {
        if route.strict {
            tracing::info!("tun route.strict requested (best-effort)");
        }
        let mut prefixes = route.ipv4.clone();
        if prefixes.is_empty() {
            prefixes.push("0.0.0.0/0".into());
        }
        for p in &prefixes {
            if let Err(e) = run_ip(&["route", "replace", p, "dev", &cfg.name]) {
                tracing::error!(prefix = %p, error = %e, "tun auto-route failed");
            }
        }
        for p in &route.ipv6 {
            if let Err(e) = run_ip(&["route", "replace", p, "dev", &cfg.name]) {
                tracing::error!(prefix = %p, error = %e, "tun auto-route (ipv6) failed");
            }
        }
        for p in &route.ipv4_exclude {
            // Best-effort: unreachable / higher-prio local exclude is OS-specific; log only.
            tracing::warn!(prefix = %p, "tun route ipv4Exclude ignored (no sing-tun)");
        }
        for p in &route.ipv6_exclude {
            tracing::warn!(prefix = %p, "tun route ipv6Exclude ignored (no sing-tun)");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_ip(args: &[&str]) -> std::io::Result<()> {
    let out = std::process::Command::new("ip").args(args).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(std::io::Error::other(format!(
            "ip {} failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}


#[cfg(target_os = "macos")]
struct TunDev {
    fd: tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
}

#[cfg(target_os = "macos")]
impl TunDev {
    fn new(fd: RawFd) -> std::io::Result<Self> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            fd: tokio::io::unix::AsyncFd::new(owned)?,
        })
    }

    async fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::os::fd::AsRawFd;
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write_all(&self, mut data: &[u8]) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        while !data.is_empty() {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                let n = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        data.as_ptr() as *const libc::c_void,
                        data.len(),
                    )
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "tun write zero",
                    ));
                }
                Ok(Ok(n)) => data = &data[n..],
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn run_dataplane(
    fd: RawFd,
    cfg: TunConfig,
    client: Arc<dyn Client>,
    family_hdr: bool,
    enable_v6: bool,
) -> Result<(), Error> {
    // Split into owned read/write via dup so concurrent writer task works.
    let write_fd = unsafe { libc::dup(fd) };
    if write_fd < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(Error::Io(e));
    }
    #[cfg(target_os = "linux")]
    let (mut reader, writer) = {
        (
            unsafe { tokio::fs::File::from_raw_fd(fd) },
            Arc::new(Mutex::new(unsafe { tokio::fs::File::from_raw_fd(write_fd) })),
        )
    };
    #[cfg(target_os = "macos")]
    let (reader, writer) = {
        (
            TunDev::new(fd).map_err(Error::Io)?,
            Arc::new(Mutex::new(TunDev::new(write_fd).map_err(Error::Io)?)),
        )
    };

    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(512);
    let writer_task = Arc::clone(&writer);
    tokio::spawn(async move {
        while let Some(pkt) = pkt_rx.recv().await {
            let wire = if family_hdr { prepend_family(&pkt) } else { pkt };
            let mut w = writer_task.lock().await;
            let _ = w.write_all(&wire).await;
        }
    });
    // Keep writer alive for the read loop lifetime (channel closes on drop of pkt_tx at end).
    let _keep_writer = writer;

    let idle = if cfg.timeout.is_zero() {
        Duration::from_secs(300)
    } else {
        cfg.timeout
    };

    let mut udp_txs: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut tcp_txs: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; 65535];

    loop {
        let n = reader.read(&mut buf).await.map_err(Error::Io)?;
        if n == 0 {
            return Err(Error::Io(std::io::Error::other("tun device closed")));
        }
        let raw = &buf[..n];
        let pkt = if family_hdr {
            match strip_family(raw) {
                Some(p) => p,
                None => continue,
            }
        } else {
            raw
        };
        if let Some(ip) = parse_ipv4(pkt) {
        match ip.proto {
            IP_PROTO_ICMP => {
                // Official does not proxy ICMP.
            }
            IP_PROTO_UDP => {
                let Some(udp) = parse_udp(pkt, &ip) else {
                    continue;
                };
                let src = SocketAddr::V4(SocketAddrV4::new(ip.src, udp.src_port));
                let dst = SocketAddr::V4(SocketAddrV4::new(ip.dst, udp.dst_port));
                let payload = pkt[udp.payload_off..udp.payload_off + udp.payload_len].to_vec();
                let key = (src, dst);
                udp_txs.retain(|_, tx| !tx.is_closed());
                if let Some(tx) = udp_txs.get(&key) {
                    let _ = tx.try_send(payload);
                    continue;
                }
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                let _ = tx.try_send(payload);
                udp_txs.insert(key, tx);
                let client = Arc::clone(&client);
                let pkt_tx = pkt_tx.clone();
                tokio::spawn(async move {
                    let _ = udp_session(client, rx, pkt_tx, src, dst, idle).await;
                });
            }
            IP_PROTO_TCP => {
                let Some(tcp) = parse_tcp(pkt, &ip) else {
                    continue;
                };
                let src = SocketAddr::V4(SocketAddrV4::new(ip.src, tcp.src_port));
                let dst = SocketAddr::V4(SocketAddrV4::new(ip.dst, tcp.dst_port));
                let key = (src, dst);
                tcp_txs.retain(|_, tx| !tx.is_closed());
                if let Some(tx) = tcp_txs.get(&key) {
                    let frame = pkt[ip.header_len..ip.total_len].to_vec();
                    let _ = tx.try_send(frame);
                    continue;
                }
                // New flow: only start on SYN (not SYN+ACK from us).
                if tcp.flags & TCP_SYN == 0 || tcp.flags & TCP_ACK != 0 {
                    continue;
                }
                let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
                // First segment includes the TCP header+payload for the session task.
                let frame = pkt[ip.header_len..ip.total_len].to_vec();
                let _ = tx.try_send(frame);
                tcp_txs.insert(key, tx);
                let client = Arc::clone(&client);
                let pkt_tx = pkt_tx.clone();
                tokio::spawn(async move {
                    let _ = tcp_session(client, rx, pkt_tx, src, dst, idle).await;
                });
            }
            _ => {}
        }
        continue;
        }
        if enable_v6 {
            if let Some(ip6) = parse_ipv6(pkt) {
                match ip6.next {
                    IP_PROTO_ICMP | 58 => {}
                    IP_PROTO_UDP => {
                        let Some(udp) = parse_udp6(pkt, &ip6) else { continue };
                        let src = SocketAddr::V6(SocketAddrV6::new(ip6.src, udp.src_port, 0, 0));
                        let dst = SocketAddr::V6(SocketAddrV6::new(ip6.dst, udp.dst_port, 0, 0));
                        let payload = pkt[udp.payload_off..udp.payload_off + udp.payload_len].to_vec();
                        let key = (src, dst);
                        udp_txs.retain(|_, tx| !tx.is_closed());
                        if let Some(tx) = udp_txs.get(&key) {
                            let _ = tx.try_send(payload);
                            continue;
                        }
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                        let _ = tx.try_send(payload);
                        udp_txs.insert(key, tx);
                        let client = Arc::clone(&client);
                        let pkt_tx = pkt_tx.clone();
                        tokio::spawn(async move {
                            let _ = udp_session(client, rx, pkt_tx, src, dst, idle).await;
                        });
                    }
                    IP_PROTO_TCP => {
                        let Some(tcp) = parse_tcp6(pkt, &ip6) else { continue };
                        let src = SocketAddr::V6(SocketAddrV6::new(ip6.src, tcp.src_port, 0, 0));
                        let dst = SocketAddr::V6(SocketAddrV6::new(ip6.dst, tcp.dst_port, 0, 0));
                        let key = (src, dst);
                        tcp_txs.retain(|_, tx| !tx.is_closed());
                        if let Some(tx) = tcp_txs.get(&key) {
                            let frame = pkt[ip6.header_len..ip6.total_len].to_vec();
                            let _ = tx.try_send(frame);
                            continue;
                        }
                        if tcp.flags & TCP_SYN == 0 || tcp.flags & TCP_ACK != 0 {
                            continue;
                        }
                        let (tx, rx) = mpsc::channel::<Vec<u8>>(128);
                        let frame = pkt[ip6.header_len..ip6.total_len].to_vec();
                        let _ = tx.try_send(frame);
                        tcp_txs.insert(key, tx);
                        let client = Arc::clone(&client);
                        let pkt_tx = pkt_tx.clone();
                        tokio::spawn(async move {
                            let _ = tcp_session(client, rx, pkt_tx, src, dst, idle).await;
                        });
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn udp_session(
    client: Arc<dyn Client>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    pkt_tx: PacketTx,
    src: SocketAddr,
    dst: SocketAddr,
    idle: Duration,
) -> Result<(), Error> {
    let mut hy = client.udp().await?;
    let dst_s = dst.to_string();
    while let Some(payload) = rx.recv().await {
        hy.send(&payload, &dst_s).await?;
        loop {
            tokio::select! {
                biased;
                Some(more) = rx.recv() => {
                    hy.send(&more, &dst_s).await?;
                }
                r = tokio::time::timeout(idle, hy.receive()) => {
                    match r {
                        Ok(Ok((payload, _))) => {
                            // Reply: swap src/dst so it looks like it came from remote.
                            let pkt = build_udp_packet(dst, src, &payload);
                            let _ = pkt_tx.send(pkt).await;
                        }
                        Ok(Err(_)) => {
                            let _ = hy.close().await;
                            return Ok(());
                        }
                        Err(_) => {
                            if rx.is_empty() {
                                let _ = hy.close().await;
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = hy.close().await;
    Ok(())
}

async fn tcp_session(
    client: Arc<dyn Client>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    pkt_tx: PacketTx,
    client_addr: SocketAddr,
    remote_addr: SocketAddr,
    idle: Duration,
) -> Result<(), Error> {
    // Consume initial SYN.
    let Some(first) = rx.recv().await else {
        return Ok(());
    };
    let syn_seq = if first.len() >= 8 {
        u32::from_be_bytes([first[4], first[5], first[6], first[7]])
    } else {
        return Ok(());
    };

    static ISS: AtomicU32 = AtomicU32::new(1_000_000);
    let mut snd_nxt = ISS.fetch_add(100_000, Ordering::Relaxed);
    let isn = snd_nxt;
    let mut rcv_nxt = syn_seq.wrapping_add(1);

    // SYN-ACK
    let synack = build_tcp_segment(
        remote_addr,
        client_addr,
        isn,
        rcv_nxt,
        TCP_SYN | TCP_ACK,
        &[],
    );
    pkt_tx.send(synack).await.map_err(|_| Error::Closed(None))?;
    snd_nxt = snd_nxt.wrapping_add(1);

    // Wait for ACK (and optional early data).
    let handshake_deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(handshake_deadline);
    loop {
        tokio::select! {
            _ = &mut handshake_deadline => {
                let rst = build_tcp_segment(remote_addr, client_addr, snd_nxt, 0, TCP_RST, &[]);
                let _ = pkt_tx.send(rst).await;
                return Ok(());
            }
            frame = rx.recv() => {
                let Some(frame) = frame else { return Ok(()); };
                if frame.len() < 20 { continue; }
                let flags = frame[13];
                if flags & TCP_RST != 0 { return Ok(()); }
                if flags & TCP_ACK == 0 { continue; }
                // Established (optionally with payload).
                let data_off = ((frame[12] >> 4) as usize) * 4;
                let early = if frame.len() > data_off {
                    frame[data_off..].to_vec()
                } else {
                    Vec::new()
                };
                if !early.is_empty() {
                    let seq = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
                    if seq == rcv_nxt {
                        // Will send after hy dial.
                    }
                }
                return tcp_established(
                    client, rx, pkt_tx, client_addr, remote_addr,
                    snd_nxt, rcv_nxt, early, idle,
                ).await;
            }
        }
    }
}

async fn tcp_established(
    client: Arc<dyn Client>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    pkt_tx: PacketTx,
    client_addr: SocketAddr,
    remote_addr: SocketAddr,
    mut snd_nxt: u32,
    mut rcv_nxt: u32,
    early: Vec<u8>,
    idle: Duration,
) -> Result<(), Error> {
    let hy = match client.tcp(&remote_addr.to_string()).await {
        Ok(c) => c,
        Err(_) => {
            let rst = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_RST | TCP_ACK, &[]);
            let _ = pkt_tx.send(rst).await;
            return Ok(());
        }
    };
    let hy: Arc<dyn HyTcpConn> = Arc::from(hy);

    if !early.is_empty() {
        let _ = hy.write(&early).await;
        rcv_nxt = rcv_nxt.wrapping_add(early.len() as u32);
        let ack = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_ACK, &[]);
        let _ = pkt_tx.send(ack).await;
    }

    let mut fin_seen = false;
    loop {
        let mut rbuf = vec![0u8; 16384];
        tokio::select! {
            frame = rx.recv() => {
                let Some(frame) = frame else {
                    let _ = hy.close().await;
                    return Ok(());
                };
                if frame.len() < 20 { continue; }
                let flags = frame[13];
                if flags & TCP_RST != 0 {
                    let _ = hy.close().await;
                    return Ok(());
                }
                let seq = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
                let data_off = ((frame[12] >> 4) as usize) * 4;
                let payload = if frame.len() > data_off { &frame[data_off..] } else { &[][..] };
                if !payload.is_empty() && seq == rcv_nxt {
                    let _ = hy.write(payload).await;
                    rcv_nxt = rcv_nxt.wrapping_add(payload.len() as u32);
                    let ack = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_ACK, &[]);
                    let _ = pkt_tx.send(ack).await;
                }
                if flags & TCP_FIN != 0 {
                    // FIN sequence is after any payload already counted into rcv_nxt.
                    let fin_seq = seq.wrapping_add(payload.len() as u32);
                    if fin_seq == rcv_nxt {
                        rcv_nxt = rcv_nxt.wrapping_add(1);
                    }
                    let finack = build_tcp_segment(
                        remote_addr,
                        client_addr,
                        snd_nxt,
                        rcv_nxt,
                        TCP_ACK | TCP_FIN,
                        &[],
                    );
                    let _ = pkt_tx.send(finack).await;
                    snd_nxt = snd_nxt.wrapping_add(1);
                    fin_seen = true;
                    let _ = hy.close().await;
                    return Ok(());
                }
            }
            r = tokio::time::timeout(idle, hy.read(&mut rbuf)) => {
                match r {
                    Ok(Ok(0)) | Err(_) if fin_seen => {
                        return Ok(());
                    }
                    Ok(Ok(0)) => {
                        let fin = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_FIN | TCP_ACK, &[]);
                        let _ = pkt_tx.send(fin).await;
                        snd_nxt = snd_nxt.wrapping_add(1);
                        let _ = hy.close().await;
                        return Ok(());
                    }
                    Ok(Ok(n)) => {
                        let chunk = &rbuf[..n];
                        // Segmentize to ~1200 to stay under typical MTU with headers.
                        for piece in chunk.chunks(1200) {
                            let seg = build_tcp_segment(
                                remote_addr, client_addr, snd_nxt, rcv_nxt,
                                TCP_ACK | TCP_PSH, piece,
                            );
                            let _ = pkt_tx.send(seg).await;
                            snd_nxt = snd_nxt.wrapping_add(piece.len() as u32);
                        }
                    }
                    Ok(Err(_)) => {
                        let rst = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_RST | TCP_ACK, &[]);
                        let _ = pkt_tx.send(rst).await;
                        return Ok(());
                    }
                    Err(_) => {
                        // Idle timeout with no uplink pending.
                        if rx.is_empty() {
                            let rst = build_tcp_segment(remote_addr, client_addr, snd_nxt, rcv_nxt, TCP_RST | TCP_ACK, &[]);
                            let _ = pkt_tx.send(rst).await;
                            let _ = hy.close().await;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hy_core::client::{HyTcpConn, HyUdpConn};

    #[test]
    fn parse_ipv4_udp_headers() {
        // Minimal IPv4 + UDP: 1.2.3.4:12345 -> 5.6.7.8:53, payload "hi"
        let mut pkt = vec![0u8; 20 + 8 + 2];
        pkt[0] = 0x45;
        let total = (20 + 8 + 2) as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IP_PROTO_UDP;
        pkt[12..16].copy_from_slice(&[1, 2, 3, 4]);
        pkt[16..20].copy_from_slice(&[5, 6, 7, 8]);
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&10u16.to_be_bytes());
        pkt[28] = b'h';
        pkt[29] = b'i';

        let ip = parse_ipv4(&pkt).expect("ipv4");
        assert_eq!(ip.src, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(ip.dst, Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(ip.proto, IP_PROTO_UDP);
        let udp = parse_udp(&pkt, &ip).expect("udp");
        assert_eq!(udp.src_port, 12345);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(&pkt[udp.payload_off..udp.payload_off + udp.payload_len], b"hi");
    }

    #[test]
    fn parse_ipv4_tcp_headers() {
        let mut pkt = vec![0u8; 20 + 20];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = IP_PROTO_TCP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[24..28].copy_from_slice(&0xabcdu32.to_be_bytes());
        pkt[28..32].copy_from_slice(&0u32.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = TCP_SYN;

        let ip = parse_ipv4(&pkt).expect("ipv4");
        assert_eq!(ip.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ip.dst, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(ip.proto, IP_PROTO_TCP);
        let tcp = parse_tcp(&pkt, &ip).expect("tcp");
        assert_eq!(tcp.src_port, 40000);
        assert_eq!(tcp.dst_port, 443);
        assert_eq!(tcp.seq, 0xabcd);
        assert_eq!(tcp.flags & TCP_SYN, TCP_SYN);
    }

    #[test]
    fn utun_name_scan() {
        assert_eq!(crate::inbound::tun_plan::parse_utun_unit("utun123").unwrap(), 123);
        assert_eq!(crate::inbound::tun_plan::parse_utun_unit("utun0").unwrap(), 0);
        assert!(crate::inbound::tun_plan::parse_utun_unit("utun").is_err());
        assert!(crate::inbound::tun_plan::parse_utun_unit("hy0").is_err());
        assert!(crate::inbound::tun_plan::parse_utun_unit("utunX").is_err());
        assert!(crate::inbound::tun_plan::parse_utun_unit("hytun").is_err());
    }

    #[test]
    fn darwin_default_v4_is_eight_subranges() {
        let p = crate::inbound::tun_plan::darwin_default_ipv4();
        assert_eq!(p.len(), 8);
        assert_eq!(p[0], (Ipv4Addr::new(1, 0, 0, 0), 8));
        assert_eq!(p[7], (Ipv4Addr::new(128, 0, 0, 0), 1));
        assert!(!p.iter().any(|(a, b)| *a == Ipv4Addr::UNSPECIFIED && *b == 0));
    }

    #[test]
    fn exclude_diff_default_route_minus_host() {
        let got = crate::inbound::tun_plan::darwin_ipv4_install_list(
            &["0.0.0.0/0".into()],
            &["1.2.3.4/32".into()],
        )
        .unwrap();
        assert!(!got.is_empty());
        let host = Ipv4Addr::new(1, 2, 3, 4);
        for (a, bits) in &got {
            let mask = if *bits == 0 { 0 } else { !0u32 << (32 - bits) };
            let net = u32::from(*a) & mask;
            assert_ne!(net, u32::from(host) & mask, "exclude leaked {a}/{bits}");
        }
        // 1.2.3.4 itself must not be covered
        let covers = got.iter().any(|(a, bits)| {
            let mask = if *bits == 0 { 0 } else { !0u32 << (32 - bits) };
            (u32::from(*a) & mask) == (u32::from(host) & mask)
        });
        assert!(!covers);
    }

    #[test]
    fn darwin_default_v6_and_exclude() {
        let p = crate::inbound::tun_plan::darwin_default_ipv6();
        assert_eq!(p.len(), 8);
        let got = crate::inbound::tun_plan::darwin_ipv6_install_list(
            &[],
            &["2001:db8::1/128".into()],
        )
        .unwrap();
        assert!(!got.is_empty());
    }

    #[test]
    fn darwin_v6_p2p_dst_official() {
        let a: Ipv6Addr = "2001::ffff:ffff:ffff:fff1".parse().unwrap();
        assert!(crate::inbound::tun_plan::darwin_v6_p2p_dst(a, 126).is_none());
        let p = crate::inbound::tun_plan::darwin_v6_p2p_dst(a, 128).unwrap();
        assert_eq!(p, Ipv6Addr::from(u128::from(a).wrapping_add(1)));
    }

    #[test]
    fn family_header_roundtrip_ipv4() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&20u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = IP_PROTO_UDP;
        ip[12..16].copy_from_slice(&[1, 2, 3, 4]);
        ip[16..20].copy_from_slice(&[5, 6, 7, 8]);
        let wire = prepend_family(&ip);
        assert_eq!(&wire[..4], &[0, 0, 0, 2]);
        let body = strip_family(&wire).expect("strip");
        let parsed = parse_ipv4(body).expect("ipv4 after strip");
        assert_eq!(parsed.src, Ipv4Addr::new(1, 2, 3, 4));
    }

    struct DummyClient;

    #[async_trait]
    impl Client for DummyClient {
        async fn tcp(&self, _addr: &str) -> Result<Box<dyn HyTcpConn>, Error> {
            Err(Error::Dial("dummy".into()))
        }
        async fn udp(&self) -> Result<Box<dyn HyUdpConn>, Error> {
            Err(Error::Dial("dummy".into()))
        }
        async fn close(&self) -> Result<(), Error> {
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_without_usable_tun_returns_err() {
        let cfg = TunConfig {
            name: "hy-p5d3-nopriv".into(),
            mtu: 1500,
            timeout: Duration::from_secs(300),
            ipv4: "100.100.100.101/30".into(),
            ipv6: None,
            route: None,
        };
        let r = run(cfg, Arc::new(DummyClient)).await;
        assert!(r.is_err(), "expected Err without NET_ADMIN, got Ok(())");
        match r {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "tun");
                assert!(
                    reason.contains("failed to create tun interface"),
                    "reason={reason}"
                );
            }
            Err(Error::Io(_)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
