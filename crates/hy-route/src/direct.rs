//! Direct outbound sockets that bypass TUN (Linux fwmark / Darwin NIC bind).

use crate::dest::Dest;
use crate::error::Error;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{SocketAddr, TcpStream as StdTcpStream, UdpSocket as StdUdpSocket};
use tokio::net::{TcpStream, UdpSocket};

/// Default `SO_MARK` / `ip rule fwmark` (Linux). Ignored on other OS.
pub const DEFAULT_FWMARK: u32 = 0x162;

/// Candidate interface for Darwin default-route selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceCandidate {
    pub name: String,
    pub default: bool,
}

/// `utun*` is the Darwin tunnel; never bind DIRECT / QUIC to it.
pub fn is_utun_name(name: &str) -> bool {
    name.trim().to_ascii_lowercase().starts_with("utun")
}

/// Pick the default-route NIC that is not `utun`. Error if none.
pub fn pick_non_utun_default(ifaces: &[IfaceCandidate]) -> Result<&IfaceCandidate, Error> {
    ifaces
        .iter()
        .find(|i| i.default && !is_utun_name(&i.name))
        .ok_or_else(|| Error::direct("no non-utun default-route interface"))
}

/// Parse `route -n get default` stdout for `interface: NAME`.
pub fn parse_darwin_route_get(stdout: &str) -> Result<String, Error> {
    for line in stdout.lines() {
        let line = line.trim();
        let Some(name) = line
            .strip_prefix("interface:")
            .or_else(|| line.strip_prefix("Interface:"))
        else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if is_utun_name(name) {
            return Err(Error::direct(format!(
                "default route is {name}, need a non-utun NIC"
            )));
        }
        return Ok(name.to_string());
    }
    Err(Error::direct("no default interface in route get"))
}

/// Local TCP/UDP dialer. Linux: `SO_MARK`. Darwin: bind to a non-utun default NIC.
///
/// Never silently uses an unmarked/unbound socket: a failed mark/bind is an error
/// (an unmarked socket would loop into TUN). Tests may use [`Self::relaxed`] so
/// `EPERM` on `SO_MARK` is allowed without `CAP_NET_ADMIN`.
#[derive(Debug, Clone)]
pub struct DirectDialer {
    fwmark: u32,
    strict: bool,
    #[cfg(target_os = "macos")]
    iface: String,
}

impl DirectDialer {
    /// Production dialer. Linux stores `fwmark` (applied per socket). Darwin
    /// resolves the non-utun default-route iface immediately.
    pub fn new(fwmark: u32) -> Result<Self, Error> {
        #[cfg(target_os = "macos")]
        {
            let iface = discover_darwin_iface()?;
            return Ok(Self {
                fwmark,
                strict: true,
                iface,
            });
        }
        #[cfg(not(target_os = "macos"))]
        {
            Ok(Self {
                fwmark,
                strict: true,
            })
        }
    }

    /// Same as [`Self::new`] but `SO_MARK` `EPERM` is not fatal (unit tests).
    pub fn relaxed(fwmark: u32) -> Self {
        #[cfg(target_os = "macos")]
        {
            Self {
                fwmark,
                strict: false,
                iface: String::new(),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self {
                fwmark,
                strict: false,
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn with_iface(fwmark: u32, iface: String) -> Result<Self, Error> {
        if is_utun_name(&iface) {
            return Err(Error::direct(format!(
                "refusing to bind DIRECT to utun {iface}"
            )));
        }
        Ok(Self {
            fwmark,
            strict: true,
            iface,
        })
    }

    pub fn fwmark(&self) -> u32 {
        self.fwmark
    }

    pub fn is_strict(&self) -> bool {
        self.strict
    }

    /// Connect TCP to `dest` on a marked/bound socket.
    pub async fn tcp(&self, dest: &Dest) -> Result<TcpStream, Error> {
        let addr = resolve_dest(dest).await?;
        let std = tokio::task::spawn_blocking({
            let d = self.clone();
            move || d.tcp_std(addr)
        })
        .await
        .map_err(|e| Error::direct(e.to_string()))??;
        let stream = TcpStream::from_std(std).map_err(|e| Error::direct(e.to_string()))?;
        stream
            .writable()
            .await
            .map_err(|e| Error::direct(e.to_string()))?;
        if let Ok(Some(e)) = stream.take_error() {
            return Err(Error::direct(e.to_string()));
        }
        Ok(stream)
    }

    /// Bind a marked/bound UDP socket (unconnected). Family follows `v6`.
    pub async fn udp_bind(&self, v6: bool) -> Result<UdpSocket, Error> {
        let std = tokio::task::spawn_blocking({
            let d = self.clone();
            move || d.udp_std(v6)
        })
        .await
        .map_err(|e| Error::direct(e.to_string()))??;
        UdpSocket::from_std(std).map_err(|e| Error::direct(e.to_string()))
    }

    fn tcp_std(&self, addr: SocketAddr) -> Result<StdTcpStream, Error> {
        let sock = new_socket(addr.is_ipv6(), true)?;
        self.apply_mark_bind(&sock, addr.is_ipv6())?;
        sock.set_nonblocking(true)
            .map_err(|e| Error::direct(e.to_string()))?;
        match sock.connect(&SockAddr::from(addr)) {
            Ok(()) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(Error::direct(format!("connect {addr}: {e}"))),
        }
        Ok(sock.into())
    }

    fn udp_std(&self, v6: bool) -> Result<StdUdpSocket, Error> {
        let sock = new_socket(v6, false)?;
        self.apply_mark_bind(&sock, v6)?;
        sock.set_nonblocking(true)
            .map_err(|e| Error::direct(e.to_string()))?;
        let bind: SocketAddr = if v6 {
            ([0u8; 16], 0).into()
        } else {
            ([0u8, 0, 0, 0], 0).into()
        };
        sock.bind(&SockAddr::from(bind))
            .map_err(|e| Error::direct(format!("udp bind: {e}")))?;
        Ok(sock.into())
    }

    fn apply_mark_bind(&self, sock: &Socket, v6: bool) -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            let _ = v6;
            apply_linux_mark(sock, self.fwmark, self.strict)?;
        }
        #[cfg(target_os = "macos")]
        {
            if self.iface.is_empty() {
                if self.strict {
                    return Err(Error::direct("no physical NIC to bind"));
                }
            } else {
                bind_darwin_iface(sock, &self.iface, v6)?;
            }
            let _ = v6;
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = (sock, v6, self.fwmark, self.strict);
        }
        Ok(())
    }
}

fn new_socket(v6: bool, tcp: bool) -> Result<Socket, Error> {
    let domain = if v6 { Domain::IPV6 } else { Domain::IPV4 };
    let (ty, proto) = if tcp {
        (Type::STREAM, Protocol::TCP)
    } else {
        (Type::DGRAM, Protocol::UDP)
    };
    Socket::new(domain, ty, Some(proto)).map_err(|e| Error::direct(e.to_string()))
}

#[cfg(target_os = "linux")]
fn apply_linux_mark(sock: &Socket, mark: u32, strict: bool) -> Result<(), Error> {
    match sock.set_mark(mark) {
        Ok(()) => {
            let got = so_mark(sock).map_err(|e| Error::direct(format!("getsockopt SO_MARK: {e}")))?;
            if got != mark {
                return Err(Error::direct(format!(
                    "SO_MARK verify failed: set {mark:#x} got {got:#x}"
                )));
            }
            Ok(())
        }
        Err(e) if !strict && e.raw_os_error() == Some(libc::EPERM) => Ok(()),
        Err(e) => Err(Error::direct(format!(
            "SO_MARK {mark:#x} failed (not falling back to unmarked): {e}"
        ))),
    }
}

/// `SO_MARK` via getsockopt (Linux).
#[cfg(target_os = "linux")]
pub fn so_mark(sock: &Socket) -> io::Result<u32> {
    so_mark_fd(std::os::fd::AsRawFd::as_raw_fd(sock))
}

/// Read `SO_MARK` from a tokio UDP socket.
#[cfg(target_os = "linux")]
pub fn so_mark_udp(sock: &UdpSocket) -> io::Result<u32> {
    so_mark_fd(std::os::fd::AsRawFd::as_raw_fd(sock))
}

#[cfg(target_os = "linux")]
pub fn so_mark_tcp(sock: &TcpStream) -> io::Result<u32> {
    so_mark_fd(std::os::fd::AsRawFd::as_raw_fd(sock))
}

#[cfg(target_os = "linux")]
fn so_mark_fd(fd: std::os::fd::RawFd) -> io::Result<u32> {
    let mut mark: libc::c_uint = 0;
    let mut len = std::mem::size_of::<libc::c_uint>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(mark as u32)
}

#[cfg(target_os = "linux")]
pub fn can_set_so_mark(mark: u32) -> bool {
    let Ok(sock) = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) else {
        return false;
    };
    sock.set_mark(mark).is_ok()
}

#[cfg(target_os = "macos")]
fn bind_darwin_iface(sock: &Socket, name: &str, v6: bool) -> Result<(), Error> {
    if is_utun_name(name) {
        return Err(Error::direct(format!("refusing to bind to utun {name}")));
    }
    let cname = std::ffi::CString::new(name).map_err(|e| Error::direct(e.to_string()))?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        return Err(Error::direct(format!(
            "if_nametoindex({name}) failed: {}",
            io::Error::last_os_error()
        )));
    }
    let idx = idx as libc::c_uint;
    let fd = std::os::fd::AsRawFd::as_raw_fd(sock);
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &idx as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if r != 0 {
        return Err(Error::direct(format!(
            "IP_BOUND_IF {name} failed (not falling back): {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn discover_darwin_iface() -> Result<String, Error> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| Error::direct(format!("route get default: {e}")))?;
    if !out.status.success() {
        return Err(Error::direct(format!(
            "route get default failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    parse_darwin_route_get(&String::from_utf8_lossy(&out.stdout))
}

async fn resolve_dest(dest: &Dest) -> Result<SocketAddr, Error> {
    if let Some(ip) = dest.ip {
        return Ok(SocketAddr::new(ip, dest.port));
    }
    let host = dest
        .host
        .as_deref()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| Error::direct("empty dest"))?;
    let mut addrs = tokio::net::lookup_host((host, dest.port))
        .await
        .map_err(|e| Error::direct(format!("resolve {host}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::direct(format!("resolve {host}: no addresses")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dest::Proto;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn picker_skips_utun_keeps_en0() {
        let rows = [
            IfaceCandidate {
                name: "utun0".into(),
                default: true,
            },
            IfaceCandidate {
                name: "en0".into(),
                default: true,
            },
            IfaceCandidate {
                name: "lo0".into(),
                default: false,
            },
        ];
        let p = pick_non_utun_default(&rows).unwrap();
        assert_eq!(p.name, "en0");
        assert!(!is_utun_name(&p.name));
    }

    #[test]
    fn picker_rejects_only_utun() {
        let rows = [IfaceCandidate {
            name: "utun3".into(),
            default: true,
        }];
        let e = pick_non_utun_default(&rows).unwrap_err();
        assert!(e.to_string().contains("utun") || e.to_string().contains("non-utun"), "{e}");
        assert!(is_utun_name("utun3"));
        assert!(is_utun_name("UTUN0"));
        assert!(!is_utun_name("en0"));
        assert!(!is_utun_name("eth0"));
    }

    #[test]
    fn parse_darwin_route_get_en0() {
        let out = "   route to: default\n destination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE>\n";
        assert_eq!(parse_darwin_route_get(out).unwrap(), "en0");
    }

    #[test]
    fn parse_darwin_route_get_rejects_utun() {
        let out = "  interface: utun2\n";
        let e = parse_darwin_route_get(out).unwrap_err();
        assert!(e.to_string().contains("utun"), "{e}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tcp_udp_have_so_mark() {
        let mark = 0x162;
        if !can_set_so_mark(mark) && std::env::var_os("HY_ROUTE_USERNS").is_none() {
            let exe = std::env::current_exe().unwrap();
            let out = std::process::Command::new("unshare")
                .args(["--user", "--map-root-user", "--net"])
                .arg(&exe)
                .args(["linux_tcp_udp_have_so_mark", "--nocapture"])
                .env("HY_ROUTE_USERNS", "1")
                .output()
                .expect("unshare");
            assert!(
                out.status.success(),
                "unshare SO_MARK test failed: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        if !can_set_so_mark(mark) {
            panic!("cannot set SO_MARK even in user namespace");
        }
        let tcp_sock = new_socket(false, true).unwrap();
        apply_linux_mark(&tcp_sock, mark, true).unwrap();
        assert_eq!(so_mark(&tcp_sock).unwrap(), mark, "TCP SO_MARK");

        let udp_sock = new_socket(false, false).unwrap();
        apply_linux_mark(&udp_sock, mark, true).unwrap();
        assert_eq!(so_mark(&udp_sock).unwrap(), mark, "UDP SO_MARK");

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let d = DirectDialer::new(mark).unwrap();
            let udp = d.udp_bind(false).await.unwrap();
            assert_eq!(so_mark_udp(&udp).unwrap(), mark);
        });
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn strict_mark_failure_does_not_fallback() {
        if can_set_so_mark(0x162) {
            return;
        }
        let d = DirectDialer::new(0x162).unwrap();
        let dest = Dest::from_socket_addr(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
            Proto::Tcp,
        );
        let e = d.tcp(&dest).await.unwrap_err();
        let s = e.to_string();
        assert!(
            s.contains("SO_MARK") || s.contains("not falling back"),
            "{s}"
        );
        let e = d.udp_bind(false).await.unwrap_err();
        let s = e.to_string();
        assert!(
            s.contains("SO_MARK") || s.contains("not falling back"),
            "{s}"
        );
    }

    #[tokio::test]
    async fn relaxed_tcp_udp_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });
        let d = DirectDialer::relaxed(0x162);
        let dest = Dest::from_socket_addr(addr, Proto::Tcp);
        let tcp = d.tcp(&dest).await.unwrap();
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut tcp = tcp;
            tcp.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            tcp.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        }

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let eaddr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let (n, src) = echo.recv_from(&mut buf).await.unwrap();
            let _ = echo.send_to(&buf[..n], src).await;
        });
        let u = d.udp_bind(false).await.unwrap();
        u.send_to(b"hi", eaddr).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = u.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn default_fwmark_is_0x162() {
        assert_eq!(DEFAULT_FWMARK, 0x162);
    }
}
