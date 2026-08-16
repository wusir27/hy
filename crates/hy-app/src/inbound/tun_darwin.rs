//! Darwin utun device: official syscall sequence (no sing-tun).

use crate::config::TunConfig;
use crate::inbound::tun_plan::{
    darwin_ipv4_install_list, darwin_ipv6_install_list, parse_utun_unit, parse_v4_prefix,
    parse_v6_prefix,
};
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::process::Command;

const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control\0";
const SIOCAIFADDR_IN6: libc::c_ulong = 2_155_899_162;
const IN6_IFF_NODAD: u32 = 0x0020;
const IN6_IFF_SECURED: u32 = 0x0400;
const ND6_INFINITE: u32 = 0xFFFF_FFFF;

#[repr(C)]
struct IfAliasReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    addr: libc::sockaddr_in,
    dstaddr: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

#[repr(C)]
struct AddrLifetime6 {
    expire: f64,
    preferred: f64,
    vltime: u32,
    pltime: u32,
}

#[repr(C)]
struct IfAliasReq6 {
    name: [u8; 16],
    addr: libc::sockaddr_in6,
    dstaddr: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: u32,
    lifetime: AddrLifetime6,
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

fn name_bytes(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    let mut buf = [0 as libc::c_char; libc::IFNAMSIZ];
    let nb = name.as_bytes();
    if nb.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name too long"));
    }
    for (i, b) in nb.iter().enumerate() {
        buf[i] = *b as libc::c_char;
    }
    Ok(buf)
}

fn sockaddr_in4(addr: Ipv4Addr) -> libc::sockaddr_in {
    let mut s: libc::sockaddr_in = unsafe { mem::zeroed() };
    s.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
    s.sin_family = libc::AF_INET as u8;
    s.sin_addr = libc::in_addr {
        s_addr: u32::from(addr).to_be(),
    };
    s
}

fn sockaddr_in6(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    let mut s: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    s.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
    s.sin6_family = libc::AF_INET6 as u8;
    s.sin6_addr = libc::in6_addr { s6_addr: addr.octets() };
    s
}

fn v4_mask(bits: u8) -> Ipv4Addr {
    Ipv4Addr::from(if bits == 0 { 0 } else { !0u32 << (32 - bits) })
}

fn v6_mask(bits: u8) -> Ipv6Addr {
    Ipv6Addr::from(if bits == 0 { 0u128 } else { !0u128 << (128 - bits) })
}

fn use_socket(domain: libc::c_int, typ: libc::c_int, proto: libc::c_int, f: impl FnOnce(RawFd) -> io::Result<()>) -> io::Result<()> {
    let fd = unsafe { libc::socket(domain, typ, proto) };
    if fd < 0 {
        return Err(last_err());
    }
    let r = f(fd);
    unsafe { libc::close(fd) };
    r
}

/// Open `utunN`, set MTU/addrs, optional routes. On any configure/route error the fd is closed.
pub fn open_and_configure(cfg: &TunConfig) -> io::Result<RawFd> {
    let unit = parse_utun_unit(&cfg.name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "bad tun name")
    })?;
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
    if fd < 0 {
        return Err(last_err());
    }
    if let Err(e) = create_utun(fd, unit, cfg) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if let Err(e) = set_nonblock(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if let Err(e) = maybe_routes(cfg) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn set_nonblock(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(last_err());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(last_err());
    }
    Ok(())
}

fn create_utun(fd: RawFd, unit: u32, cfg: &TunConfig) -> io::Result<()> {
    let mut info: libc::ctl_info = unsafe { mem::zeroed() };
    for (i, b) in UTUN_CONTROL.iter().enumerate() {
        if i >= info.ctl_name.len() {
            break;
        }
        info.ctl_name[i] = *b as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("CTLIOCGINFO: {}", last_err())));
    }

    let mut addr: libc::sockaddr_ctl = unsafe { mem::zeroed() };
    addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
    addr.sc_family = libc::AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit + 1;
    let cr = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
        )
    };
    if cr < 0 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("connect utun: {}", last_err())));
    }

    set_mtu(&cfg.name, cfg.mtu)?;
    let (v4, v4bits) = parse_v4_prefix(&cfg.ipv4).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    add_v4(&cfg.name, v4, v4bits)?;
    if let Some(ref v6s) = cfg.ipv6 {
        match parse_v6_prefix(v6s) {
            Ok((v6, bits)) => {
                if let Err(e) = add_v6(&cfg.name, v6, bits) {
                    tracing::error!(error = %e, "failed to create tun interface");
                    return Err(e);
                }
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e)),
        }
    }
    Ok(())
}

fn set_mtu(name: &str, mtu: u32) -> io::Result<()> {
    use_socket(libc::AF_INET, libc::SOCK_DGRAM, 0, |s| {
        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        ifr.ifr_name = name_bytes(name)?;
        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        if unsafe { libc::ioctl(s, libc::SIOCSIFMTU, &mut ifr) } < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("SIOCSIFMTU: {}", last_err())));
        }
        Ok(())
    })
}

fn add_v4(name: &str, addr: Ipv4Addr, bits: u8) -> io::Result<()> {
    use_socket(libc::AF_INET, libc::SOCK_DGRAM, 0, |s| {
        let mut req = IfAliasReq {
            name: name_bytes(name)?,
            addr: sockaddr_in4(addr),
            dstaddr: sockaddr_in4(addr),
            mask: sockaddr_in4(v4_mask(bits)),
        };
        if unsafe { libc::ioctl(s, libc::SIOCAIFADDR, &mut req) } < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("SIOCAIFADDR: {}", last_err())));
        }
        Ok(())
    })
}

fn add_v6(name: &str, addr: Ipv6Addr, bits: u8) -> io::Result<()> {
    use_socket(libc::AF_INET6, libc::SOCK_DGRAM, 0, |s| {
        let mut nb = [0u8; 16];
        let raw = name.as_bytes();
        nb[..raw.len()].copy_from_slice(raw);
        let mut dst = sockaddr_in6(addr);
        if bits == 128 {
            let next = Ipv6Addr::from(u128::from(addr).wrapping_add(1));
            dst = sockaddr_in6(next);
        }
        let mut req = IfAliasReq6 {
            name: nb,
            addr: sockaddr_in6(addr),
            dstaddr: dst,
            mask: sockaddr_in6(v6_mask(bits)),
            flags: IN6_IFF_NODAD | IN6_IFF_SECURED,
            lifetime: AddrLifetime6 {
                expire: 0.0,
                preferred: 0.0,
                vltime: ND6_INFINITE,
                pltime: ND6_INFINITE,
            },
        };
        if unsafe { libc::ioctl(s, SIOCAIFADDR_IN6, &mut req) } < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("SIOCAIFADDR_IN6: {}", last_err())));
        }
        Ok(())
    })
}

fn maybe_routes(cfg: &TunConfig) -> io::Result<()> {
    let Some(ref route) = cfg.route else {
        return Ok(());
    };
    if route.strict {
        tracing::info!("tun route.strict requested (best-effort)");
    }
    let v4 = darwin_ipv4_install_list(&route.ipv4, &route.ipv4_exclude)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let v6 = darwin_ipv6_install_list(&route.ipv6, &route.ipv6_exclude)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let (gw4, _) = parse_v4_prefix(&cfg.ipv4).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let gw6 = cfg
        .ipv6
        .as_ref()
        .and_then(|s| parse_v6_prefix(s).ok())
        .map(|(a, _)| a);
    for (addr, bits) in v4 {
        add_route_v4(addr, bits, gw4)?;
    }
    if let Some(g6) = gw6 {
        for (addr, bits) in v6 {
            add_route_v6(addr, bits, g6)?;
        }
    }
    let _ = Command::new("dscacheutil").arg("-flushcache").status();
    Ok(())
}

const RTM_VERSION: u8 = 5;
const RTM_ADD: u8 = 1;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_STATIC: i32 = 0x800;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;

fn roundup(n: usize) -> usize {
    if n == 0 {
        4
    } else {
        (n + 3) & !3
    }
}

fn add_route_v4(dst: Ipv4Addr, bits: u8, gw: Ipv4Addr) -> io::Result<()> {
    let sa_dst = sockaddr_in4(Ipv4Addr::from(u32::from(dst) & (if bits == 0 { 0 } else { !0u32 << (32 - bits) })));
    let sa_gw = sockaddr_in4(gw);
    let sa_mask = sockaddr_in4(v4_mask(bits));
    write_rtm(sa_dst, sa_gw, sa_mask)
}

fn add_route_v6(dst: Ipv6Addr, bits: u8, gw: Ipv6Addr) -> io::Result<()> {
    let net = Ipv6Addr::from(u128::from(dst) & (if bits == 0 { 0 } else { !0u128 << (128 - bits) }));
    write_rtm6(sockaddr_in6(net), sockaddr_in6(gw), sockaddr_in6(v6_mask(bits)))
}

fn write_rtm(dst: libc::sockaddr_in, gw: libc::sockaddr_in, mask: libc::sockaddr_in) -> io::Result<()> {
    let hdr_len = mem::size_of::<libc::rt_msghdr>();
    let dlen = roundup(dst.sin_len as usize);
    let glen = roundup(gw.sin_len as usize);
    let mlen = roundup(mask.sin_len as usize);
    let total = hdr_len + dlen + glen + mlen;
    let mut buf = vec![0u8; total];
    let hdr = buf.as_mut_ptr() as *mut libc::rt_msghdr;
    unsafe {
        (*hdr).rtm_msglen = total as u16;
        (*hdr).rtm_version = RTM_VERSION;
        (*hdr).rtm_type = RTM_ADD;
        (*hdr).rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
        (*hdr).rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        (*hdr).rtm_seq = 1;
        let mut off = hdr_len;
        std::ptr::copy_nonoverlapping(&dst as *const _ as *const u8, buf.as_mut_ptr().add(off), dst.sin_len as usize);
        off += dlen;
        std::ptr::copy_nonoverlapping(&gw as *const _ as *const u8, buf.as_mut_ptr().add(off), gw.sin_len as usize);
        off += glen;
        std::ptr::copy_nonoverlapping(&mask as *const _ as *const u8, buf.as_mut_ptr().add(off), mask.sin_len as usize);
    }
    use_socket(libc::AF_ROUTE, libc::SOCK_RAW, 0, |s| {
        let n = unsafe { libc::write(s, buf.as_ptr() as *const _, buf.len()) };
        if n < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("RTM_ADD: {}", last_err())));
        }
        Ok(())
    })
}

fn write_rtm6(dst: libc::sockaddr_in6, gw: libc::sockaddr_in6, mask: libc::sockaddr_in6) -> io::Result<()> {
    let hdr_len = mem::size_of::<libc::rt_msghdr>();
    let dlen = roundup(dst.sin6_len as usize);
    let glen = roundup(gw.sin6_len as usize);
    let mlen = roundup(mask.sin6_len as usize);
    let total = hdr_len + dlen + glen + mlen;
    let mut buf = vec![0u8; total];
    let hdr = buf.as_mut_ptr() as *mut libc::rt_msghdr;
    unsafe {
        (*hdr).rtm_msglen = total as u16;
        (*hdr).rtm_version = RTM_VERSION;
        (*hdr).rtm_type = RTM_ADD;
        (*hdr).rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY;
        (*hdr).rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        (*hdr).rtm_seq = 1;
        let mut off = hdr_len;
        std::ptr::copy_nonoverlapping(&dst as *const _ as *const u8, buf.as_mut_ptr().add(off), dst.sin6_len as usize);
        off += dlen;
        std::ptr::copy_nonoverlapping(&gw as *const _ as *const u8, buf.as_mut_ptr().add(off), gw.sin6_len as usize);
        off += glen;
        std::ptr::copy_nonoverlapping(&mask as *const _ as *const u8, buf.as_mut_ptr().add(off), mask.sin6_len as usize);
    }
    use_socket(libc::AF_ROUTE, libc::SOCK_RAW, 0, |s| {
        let n = unsafe { libc::write(s, buf.as_ptr() as *const _, buf.len()) };
        if n < 0 {
            return Err(io::Error::new(io::ErrorKind::Other, format!("RTM_ADD: {}", last_err())));
        }
        Ok(())
    })
}
