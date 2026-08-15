//! Shared Linux tproxy sockopts and original-destination cmsg decode.

use crate::inbound::redirect::decode_sock_addr;
use hy_core::Error;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

#[cfg(target_os = "linux")]
/// Linux `IP_TRANSPARENT` (SOL_IP).
pub const IP_TRANSPARENT: libc::c_int = 19;
#[cfg(target_os = "linux")]
/// Linux `IPV6_TRANSPARENT` (SOL_IPV6).
pub const IPV6_TRANSPARENT: libc::c_int = 75;
#[cfg(target_os = "linux")]
/// Linux `IP_RECVORIGDSTADDR` / `IP_ORIGDSTADDR` (SOL_IP).
pub const IP_ORIGDSTADDR: libc::c_int = 20;
#[cfg(target_os = "linux")]
/// Linux `IPV6_RECVORIGDSTADDR` / `IPV6_ORIGDSTADDR` (SOL_IPV6).
pub const IPV6_ORIGDSTADDR: libc::c_int = 74;

/// Decode `IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR` cmsg payload (`sockaddr_in` / `sockaddr_in6`).
///
/// Layout matches D1 `sockAddr` / official go-tproxy: family + BE port + address bytes.
pub fn decode_origdst_cmsg(data: &[u8]) -> Result<SocketAddr, Error> {
    if data.len() < 8 {
        return Err(Error::protocol("origdst cmsg too short"));
    }
    let family = u16::from_ne_bytes([data[0], data[1]]);
    let port = [data[2], data[3]];
    let mut padded = [0u8; 24];
    let n = (data.len() - 4).min(24);
    padded[..n].copy_from_slice(&data[4..4 + n]);
    decode_sock_addr(family, port, &padded)
}

#[cfg(target_os = "linux")]
pub(crate) fn set_reuseaddr(fd: libc::c_int) -> Result<(), Error> {
    let yes: libc::c_int = 1;
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&yes) as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn set_ip_transparent(fd: libc::c_int, v6: bool) -> Result<(), Error> {
    let yes: libc::c_int = 1;
    if v6 {
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_TRANSPARENT,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    } else {
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                IP_TRANSPARENT,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn set_recv_origdstaddr(fd: libc::c_int, v6: bool) -> Result<(), Error> {
    let yes: libc::c_int = 1;
    if v6 {
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IPV6,
                IPV6_ORIGDSTADDR,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    } else {
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_IP,
                IP_ORIGDSTADDR,
                &yes as *const _ as *const libc::c_void,
                std::mem::size_of_val(&yes) as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn sockaddr_storage(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        match addr {
            SocketAddr::V4(a) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
                (*sa).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sa).sin_port = a.port().to_be();
                (*sa).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(a.ip().octets()),
                };
                (storage, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            }
            SocketAddr::V6(a) => {
                let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
                (*sa).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sa).sin6_port = a.port().to_be();
                (*sa).sin6_flowinfo = a.flowinfo();
                (*sa).sin6_addr = libc::in6_addr {
                    s6_addr: a.ip().octets(),
                };
                (*sa).sin6_scope_id = a.scope_id();
                (storage, std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn from_sockaddr_storage(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
    unsafe {
        match storage.ss_family as i32 {
            libc::AF_INET => {
                let sa = &*(storage as *const _ as *const libc::sockaddr_in);
                let ip = std::net::Ipv4Addr::from(sa.sin_addr.s_addr.to_ne_bytes());
                let port = u16::from_be(sa.sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                let sa = &*(storage as *const _ as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                let port = u16::from_be(sa.sin6_port);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    sa.sin6_flowinfo,
                    sa.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ipv4_1_2_3_4_443() {
        // sockaddr_in: family=AF_INET(2), port=443 BE, addr=1.2.3.4
        let mut data = [0u8; 16];
        data[0..2].copy_from_slice(&2u16.to_ne_bytes());
        data[2..4].copy_from_slice(&443u16.to_be_bytes());
        data[4..8].copy_from_slice(&[1, 2, 3, 4]);
        let addr = decode_origdst_cmsg(&data).unwrap();
        assert_eq!(addr, "1.2.3.4:443".parse().unwrap());
    }

    #[test]
    fn decode_ipv6_loopback_80() {
        // sockaddr_in6: family=AF_INET6(10), port=80 BE, flowinfo, ::1
        let mut data = [0u8; 28];
        data[0..2].copy_from_slice(&10u16.to_ne_bytes());
        data[2..4].copy_from_slice(&80u16.to_be_bytes());
        // flowinfo at [4..8] stays 0; address at [8..24]
        data[8 + 15] = 1; // ::1
        let addr = decode_origdst_cmsg(&data).unwrap();
        assert_eq!(addr, "[::1]:80".parse().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn setsockopt_ip_transparent_eperm_ok() {
        // Optional: may EPERM without CAP_NET_ADMIN — must not fail the suite.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let r = set_ip_transparent(fd, false);
        unsafe {
            libc::close(fd);
        }
        match r {
            Ok(()) => {}
            Err(Error::Io(e)) => {
                let code = e.raw_os_error();
                assert!(
                    code == Some(libc::EPERM) || code == Some(libc::EACCES),
                    "unexpected setsockopt error: {e}"
                );
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
