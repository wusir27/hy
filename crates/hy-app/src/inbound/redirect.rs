//! Linux TCP redirect (`tcpRedirect`) via `SO_ORIGINAL_DST`.

use crate::inbound::forward::relay_tcp;
use crate::listen::parse_listen;
use hy_core::client::Client;
use hy_core::Error;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Decode an official-style `sockAddr` (family + BE port + 24-byte data).
///
/// AF_INET → IP from `data[0..4]`; AF_INET6 → IP from `data[4..20]` (skip flowinfo).
pub fn decode_sock_addr(family: u16, port: [u8; 2], data: &[u8; 24]) -> Result<SocketAddr, Error> {
    let port = u16::from_be_bytes(port);
    match family {
        2 => {
            // AF_INET
            let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
            Ok(SocketAddr::from((ip, port)))
        }
        10 => {
            // AF_INET6 — data[0..4] is flowinfo; address at [4..20]
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::from((Ipv6Addr::from(octets), port)))
        }
        _ => Err(Error::protocol("address family not IPv4 or IPv6")),
    }
}

#[cfg(target_os = "linux")]
pub async fn run(listen: &str, client: Arc<dyn Client>) -> Result<(), Error> {
    if listen.is_empty() {
        return Err(Error::config(
            "tcpRedirect.listen",
            "listen address is empty",
        ));
    }
    let addr = parse_listen(listen, "tcpRedirect.listen")?;
    let ln = tokio::net::TcpListener::bind(addr).await.map_err(Error::Io)?;
    tracing::info!("tcpRedirect listen {addr}");
    loop {
        let (inc, _) = ln.accept().await.map_err(Error::Io)?;
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let Ok(dst) = original_dst(&inc) else {
                // Fail silently if we can't get the original destination (official).
                return;
            };
            let Ok(out) = client.tcp(&dst.to_string()).await else {
                return;
            };
            let _ = relay_tcp(inc, out).await;
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(_listen: &str, _client: Arc<dyn Client>) -> Result<(), Error> {
    Err(Error::config("tcpRedirect", "not supported"))
}

#[cfg(target_os = "linux")]
fn original_dst(stream: &tokio::net::TcpStream) -> Result<SocketAddr, Error> {
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;

    #[repr(C)]
    struct SockAddrRaw {
        family: u16,
        port: [u8; 2],
        data: [u8; 24],
    }

    let fd = stream.as_raw_fd();
    let mut addr = SockAddrRaw {
        family: 0,
        port: [0; 2],
        data: [0; 24],
    };
    let mut len = std::mem::size_of::<SockAddrRaw>() as libc::socklen_t;

    // Try IPv6 first (SOL_IPV6=41), then IPv4 (SOL_IP=0).
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r == 0 {
        return decode_sock_addr(addr.family, addr.port, &addr.data);
    }

    len = std::mem::size_of::<SockAddrRaw>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    decode_sock_addr(addr.family, addr.port, &addr.data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_ipv4_1_2_3_4_443() {
        let mut data = [0u8; 24];
        data[0..4].copy_from_slice(&[1, 2, 3, 4]);
        let addr = decode_sock_addr(2, 443u16.to_be_bytes(), &data).unwrap();
        assert_eq!(addr, "1.2.3.4:443".parse().unwrap());
    }

    #[test]
    fn decode_ipv6_loopback_80() {
        let mut data = [0u8; 24];
        // flowinfo at [0..4]; ::1 at [4..20]
        data[4 + 15] = 1;
        let addr = decode_sock_addr(10, 80u16.to_be_bytes(), &data).unwrap();
        assert_eq!(addr, "[::1]:80".parse().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn smoke_bind_connect_without_redirect() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let connect = tokio::spawn(async move {
            let _s = tokio::net::TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        let (inc, _) = ln.accept().await.unwrap();
        // Without iptables REDIRECT, original_dst may fail (ok) or return local dest.
        let _ = original_dst(&inc);
        drop(inc);
        connect.await.unwrap();
    }
}