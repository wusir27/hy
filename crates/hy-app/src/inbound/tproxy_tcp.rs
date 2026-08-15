//! Linux TCP transparent proxy (`tcpTProxy`) via `IP_TRANSPARENT`.
//!
//! After accept, `LocalAddr` is the original destination (we masquerade as the remote)
//! and `RemoteAddr` is the client — same as official go-tproxy / hysteria.

use crate::inbound::forward::relay_tcp;
use crate::inbound::tproxy::{set_ip_transparent, set_reuseaddr, sockaddr_storage};
use crate::listen::parse_listen;
use hy_core::client::Client;
use hy_core::Error;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub async fn run(listen: &str, client: Arc<dyn Client>) -> Result<(), Error> {
    if listen.is_empty() {
        return Err(Error::config(
            "tcpTProxy.listen",
            "listen address is empty",
        ));
    }
    let addr = parse_listen(listen, "tcpTProxy.listen")?;
    let ln = bind_tproxy_tcp(addr)?;
    tracing::info!("tcpTProxy listen {addr}");
    loop {
        let (inc, _peer) = ln.accept().await.map_err(Error::Io)?;
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            // LocalAddr is the original destination under TProxy.
            let Ok(dst) = inc.local_addr() else {
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
    Err(Error::config("tcpTProxy", "not supported"))
}

#[cfg(target_os = "linux")]
fn bind_tproxy_tcp(addr: SocketAddr) -> Result<tokio::net::TcpListener, Error> {
    let v6 = addr.is_ipv6();
    let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let guard = FdGuard(fd);
    set_reuseaddr(fd)?;
    set_ip_transparent(fd, v6)?;
    let (storage, len) = sockaddr_storage(addr);
    let r = unsafe { libc::bind(fd, &storage as *const _ as *const libc::sockaddr, len) };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let r = unsafe { libc::listen(fd, 128) };
    if r != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let fd = guard.into_raw();
    let std_ln = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    std_ln.set_nonblocking(true).map_err(Error::Io)?;
    tokio::net::TcpListener::from_std(std_ln).map_err(Error::Io)
}

#[cfg(target_os = "linux")]
struct FdGuard(libc::c_int);

#[cfg(target_os = "linux")]
impl FdGuard {
    fn into_raw(self) -> libc::c_int {
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
            run("", Arc::new(Noop)).await.unwrap_err()
        });
        match err {
            Error::Config { field, reason } => {
                assert_eq!(field, "tcpTProxy.listen");
                assert!(reason.contains("empty"), "{reason}");
            }
            other => panic!("expected config empty, got {other}"),
        }
    }
}
