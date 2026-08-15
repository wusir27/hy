//! Linux UDP transparent proxy (`udpTProxy`) via `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`.
//!
//! Official flow: listen → ReadFromUDP (src, dst, first pkt) → DialUDP(dst→src) so
//! replies look like the original dest → `client.udp()` → send first pkt → bidir copy.
//! Idle timeout defaults to 60s (`defaultTimeout`).
//!
//! Reply spoofing prefers Dial-from-dst (bind transparent UDP to original dest, connect
//! to client) like go-tproxy. If that fails (e.g. EPERM without CAP_NET_ADMIN), downlink
//! uses plain `send_to(src)` on the listen socket (no source spoof). Uplink is always
//! demuxed on the listen socket by `(src,dst)` so sessions work without full TPROXY
//! divert (subsequent packets may still hit the listen fd).

#[cfg(target_os = "linux")]
use crate::inbound::tproxy::{
    decode_origdst_cmsg, set_ip_transparent, set_recv_origdstaddr, set_reuseaddr,
    sockaddr_storage, IP_ORIGDSTADDR, IPV6_ORIGDSTADDR,
};
#[cfg(target_os = "linux")]
use crate::listen::parse_listen;
use hy_core::client::Client;
use hy_core::Error;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::net::UdpSocket;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;

const UDP_BUF: usize = 4096;

#[cfg(target_os = "linux")]
pub async fn run(listen: &str, timeout: Duration, client: Arc<dyn Client>) -> Result<(), Error> {
    if listen.is_empty() {
        return Err(Error::config(
            "udpTProxy.listen",
            "listen address is empty",
        ));
    }
    let addr = parse_listen(listen, "udpTProxy.listen")?;
    let sock = Arc::new(bind_tproxy_udp(addr)?);
    tracing::info!("udpTProxy listen {addr}");
    let idle = if timeout.is_zero() {
        Duration::from_secs(60)
    } else {
        timeout
    };

    let mut txs: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUF];
    let mut oob = vec![0u8; 1024];

    loop {
        let (n, src, dst) = recv_tproxy(&sock, &mut buf, &mut oob).await?;
        let pkt = buf[..n].to_vec();
        let key = (src, dst);
        txs.retain(|_, tx| !tx.is_closed());
        if let Some(tx) = txs.get(&key) {
            let _ = tx.try_send(pkt);
            continue;
        }

        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        let _ = tx.try_send(pkt);
        txs.insert(key, tx);

        let client = Arc::clone(&client);
        let listen_sock = Arc::clone(&sock);
        let reply = match dial_udp_transparent(dst, src) {
            Ok(pair) => {
                tracing::debug!("udpTProxy DialUDP({dst}→{src}) ok");
                Some(pair)
            }
            Err(e) => {
                tracing::debug!(
                    "udpTProxy DialUDP({dst}→{src}) failed ({e}); replies without sendfrom spoof"
                );
                None
            }
        };

        tokio::spawn(async move {
            let _ = session_forward(listen_sock, reply, rx, client, src, dst, idle).await;
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run(
    _listen: &str,
    _timeout: Duration,
    _client: Arc<dyn Client>,
) -> Result<(), Error> {
    Err(Error::config("udpTProxy", "not supported"))
}

#[cfg(target_os = "linux")]
async fn session_forward(
    listen: Arc<UdpSocket>,
    reply: Option<UdpSocket>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    client: Arc<dyn Client>,
    src: SocketAddr,
    dst: SocketAddr,
    idle: Duration,
) -> Result<(), Error> {
    let mut hy = client.udp().await?;
    let dst_s = dst.to_string();
    let reply = reply.map(Arc::new);

    // First / subsequent uplink packets from listen demux.
    while let Some(pkt) = rx.recv().await {
        hy.send(&pkt, &dst_s).await?;
        loop {
            // Also drain divert socket if DialUDP succeeded (official path).
            let pair_recv = async {
                if let Some(ref p) = reply {
                    let mut b = vec![0u8; UDP_BUF];
                    let n = p.recv(&mut b).await.map_err(Error::Io)?;
                    Ok::<_, Error>(b[..n].to_vec())
                } else {
                    std::future::pending::<Result<Vec<u8>, Error>>().await
                }
            };

            tokio::select! {
                biased;
                Some(more) = rx.recv() => {
                    hy.send(&more, &dst_s).await?;
                }
                r = pair_recv => {
                    let more = r?;
                    hy.send(&more, &dst_s).await?;
                }
                r = tokio::time::timeout(idle, hy.receive()) => {
                    match r {
                        Ok(Ok((payload, _))) => {
                            if let Some(ref p) = reply {
                                let _ = p.send(&payload).await;
                            } else {
                                let _ = listen.send_to(&payload, src).await;
                            }
                        }
                        Ok(Err(_)) => {
                            let _ = hy.close().await;
                            return Ok(());
                        }
                        Err(_) => {
                            // Idle: exit if no pending uplink on the channel.
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

#[cfg(target_os = "linux")]
fn bind_tproxy_udp(addr: SocketAddr) -> Result<UdpSocket, Error> {
    let v6 = addr.is_ipv6();
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let guard = FdGuard(fd);
    set_reuseaddr(fd)?;
    set_ip_transparent(fd, v6)?;
    set_recv_origdstaddr(fd, v6)?;
    let (storage, len) = sockaddr_storage(addr);
    let r = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, len) };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let fd = guard.into_raw();
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true).map_err(Error::Io)?;
    UdpSocket::from_std(std_sock).map_err(Error::Io)
}

/// Dial UDP bound to `local` (original dest) connected to `remote` (client), with
/// `IP_TRANSPARENT`, matching go-tproxy `DialUDP`.
#[cfg(target_os = "linux")]
fn dial_udp_transparent(local: SocketAddr, remote: SocketAddr) -> Result<UdpSocket, Error> {
    let v6 = local.is_ipv6() || remote.is_ipv6();
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let guard = FdGuard(fd);
    set_reuseaddr(fd)?;
    set_ip_transparent(fd, v6)?;
    let (lstor, llen) = sockaddr_storage(local);
    let r = unsafe { libc::bind(fd, &lstor as *const _ as *const libc::sockaddr, llen) };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let (rstor, rlen) = sockaddr_storage(remote);
    let r = unsafe { libc::connect(fd, &rstor as *const _ as *const libc::sockaddr, rlen) };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let fd = guard.into_raw();
    let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    std_sock.set_nonblocking(true).map_err(Error::Io)?;
    UdpSocket::from_std(std_sock).map_err(Error::Io)
}

#[cfg(target_os = "linux")]
async fn recv_tproxy(
    sock: &UdpSocket,
    buf: &mut [u8],
    oob: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr), Error> {
    loop {
        sock.readable().await.map_err(Error::Io)?;
        match try_recvmsg(sock, buf, oob) {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

#[cfg(target_os = "linux")]
fn try_recvmsg(
    sock: &UdpSocket,
    buf: &mut [u8],
    oob: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, SocketAddr)> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    unsafe {
        let mut name: libc::sockaddr_storage = std::mem::zeroed();
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = oob.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = oob.len() as _;

        let n = libc::recvmsg(fd, &mut msg, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let src = crate::inbound::tproxy::from_sockaddr_storage(&name).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad src sockaddr")
        })?;
        let dst = parse_origdst_cmsgs(oob, msg.msg_controllen as usize).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing IP_ORIGDSTADDR cmsg",
            )
        })?;
        Ok((n as usize, src, dst))
    }
}

/// Walk Linux cmsg buffer for `IP_ORIGDSTADDR` / `IPV6_ORIGDSTADDR`.
#[cfg(target_os = "linux")]
fn parse_origdst_cmsgs(control: &[u8], len: usize) -> Option<SocketAddr> {
    let control = &control[..len.min(control.len())];
    let align = std::mem::size_of::<usize>();
    let hdr_len = std::mem::size_of::<libc::cmsghdr>();
    let mut off = 0usize;
    while off + hdr_len <= control.len() {
        let len_field = usize::from_ne_bytes(control[off..off + align].try_into().ok()?);
        if len_field < hdr_len || off + len_field > control.len() {
            break;
        }
        let level = i32::from_ne_bytes(control[off + align..off + align + 4].try_into().ok()?);
        let ty = i32::from_ne_bytes(control[off + align + 4..off + align + 8].try_into().ok()?);
        let data = &control[off + hdr_len..off + len_field];
        let is_orig = (level == libc::SOL_IP && ty == IP_ORIGDSTADDR)
            || (level == libc::SOL_IPV6 && ty == IPV6_ORIGDSTADDR);
        if is_orig {
            if let Ok(addr) = decode_origdst_cmsg(data) {
                return Some(addr);
            }
        }
        let step = (len_field + align - 1) & !(align - 1);
        if step == 0 {
            break;
        }
        off = off.checked_add(step)?;
    }
    None
}

#[cfg(target_os = "linux")]
struct FdGuard(RawFd);

#[cfg(target_os = "linux")]
impl FdGuard {
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

#[cfg(target_os = "linux")]
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_listen_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt.block_on(async {
            struct Noop;
            #[async_trait::async_trait]
            impl Client for Noop {
                async fn tcp(
                    &self,
                    _: &str,
                ) -> Result<Box<dyn hy_core::client::HyTcpConn>, Error> {
                    Err(Error::Closed(None))
                }
                async fn udp(&self) -> Result<Box<dyn hy_core::client::HyUdpConn>, Error> {
                    Err(Error::Closed(None))
                }
                async fn close(&self) -> Result<(), Error> {
                    Ok(())
                }
            }
            run("", Duration::from_secs(60), Arc::new(Noop))
                .await
                .unwrap_err()
        });
        match err {
            Error::Config { field, reason } => {
                assert_eq!(field, "udpTProxy.listen");
                assert!(reason.contains("empty"), "{reason}");
            }
            other => panic!("expected config empty, got {other}"),
        }
    }
}
