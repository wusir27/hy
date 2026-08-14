//! SOCKS5 CONNECT + UDP ASSOCIATE (RFC1928).

use crate::inbound::forward::relay_tcp;
use crate::listen::parse_listen;
use hy_core::client::{Client, HyUdpConn};
use hy_core::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn run(cfg: &crate::config::Socks5Yaml, client: Arc<dyn Client>) -> Result<(), Error> {
    let listen = cfg.listen.as_deref().ok_or_else(|| Error::config("socks5.listen", "must be set"))?;
    let addr = parse_listen(listen, "socks5.listen")?;
    let ln = TcpListener::bind(addr).await.map_err(Error::Io)?;
    tracing::info!("socks5 listen {addr}");
    let user = cfg.username.clone().unwrap_or_default();
    let pass = cfg.password.clone().unwrap_or_default();
    let disable_udp = cfg.disable_udp.unwrap_or(false);
    loop {
        let (s, _) = ln.accept().await.map_err(Error::Io)?;
        let client = Arc::clone(&client);
        let user = user.clone();
        let pass = pass.clone();
        tokio::spawn(async move {
            let _ = handle(s, client, &user, &pass, disable_udp).await;
        });
    }
}

async fn handle(
    mut s: TcpStream,
    client: Arc<dyn Client>,
    user: &str,
    pass: &str,
    disable_udp: bool,
) -> Result<(), Error> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await.map_err(Error::Io)?;
    if hdr[0] != 5 {
        return Ok(());
    }
    let n = hdr[1] as usize;
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await.map_err(Error::Io)?;
    let need_auth = !user.is_empty();
    if need_auth {
        if !methods.contains(&2) {
            s.write_all(&[5, 0xff]).await.map_err(Error::Io)?;
            return Ok(());
        }
        s.write_all(&[5, 2]).await.map_err(Error::Io)?;
        let mut h = [0u8; 2];
        s.read_exact(&mut h).await.map_err(Error::Io)?;
        let ulen = h[1] as usize;
        let mut ubuf = vec![0u8; ulen];
        s.read_exact(&mut ubuf).await.map_err(Error::Io)?;
        let mut plen = [0u8; 1];
        s.read_exact(&mut plen).await.map_err(Error::Io)?;
        let mut pbuf = vec![0u8; plen[0] as usize];
        s.read_exact(&mut pbuf).await.map_err(Error::Io)?;
        if ubuf != user.as_bytes() || pbuf != pass.as_bytes() {
            s.write_all(&[1, 1]).await.map_err(Error::Io)?;
            return Ok(());
        }
        s.write_all(&[1, 0]).await.map_err(Error::Io)?;
    } else {
        s.write_all(&[5, 0]).await.map_err(Error::Io)?;
    }

    let mut req = [0u8; 4];
    s.read_exact(&mut req).await.map_err(Error::Io)?;
    if req[0] != 5 {
        return Ok(());
    }
    let dest = read_addr(&mut s, req[3]).await?;
    match req[1] {
        1 => {
            // CONNECT
            match client.tcp(&dest).await {
                Ok(out) => {
                    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(Error::Io)?;
                    relay_tcp(s, out).await
                }
                Err(_) => {
                    s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(Error::Io)?;
                    Ok(())
                }
            }
        }
        3 if !disable_udp => associate(s, client).await,
        _ => {
            s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(Error::Io)?;
            Ok(())
        }
    }
}

async fn associate(mut s: TcpStream, client: Arc<dyn Client>) -> Result<(), Error> {
    let udp = match client.udp().await {
        Ok(u) => u,
        Err(_) => {
            s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(Error::Io)?;
            return Ok(());
        }
    };
    let udp: Arc<dyn HyUdpConn> = Arc::from(udp);
    // Bind UDP on the same address family / IP as the TCP control connection.
    let host = s.local_addr().map_err(Error::Io)?;
    let sock = match UdpSocket::bind(SocketAddr::new(host.ip(), 0)).await {
        Ok(s) => Arc::new(s),
        Err(_) => {
            s.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(Error::Io)?;
            return Ok(());
        }
    };
    let local = sock.local_addr().map_err(Error::Io)?;
    let p = local.port().to_be_bytes();
    match local.ip() {
        IpAddr::V4(ip) => {
            let o = ip.octets();
            s.write_all(&[5, 0, 0, 1, o[0], o[1], o[2], o[3], p[0], p[1]])
                .await
                .map_err(Error::Io)?;
        }
        IpAddr::V6(ip) => {
            let mut pkt = vec![5, 0, 0, 4];
            pkt.extend_from_slice(&ip.octets());
            pkt.extend_from_slice(&p);
            s.write_all(&pkt).await.map_err(Error::Io)?;
        }
    }

    let client_src: Arc<std::sync::Mutex<Option<SocketAddr>>> = Arc::new(std::sync::Mutex::new(None));
    let down_started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sock_up = Arc::clone(&sock);
    let udp_up = Arc::clone(&udp);
    let src_up = Arc::clone(&client_src);
    let started_up = Arc::clone(&down_started);

    let up = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = sock_up.recv_from(&mut buf).await.map_err(Error::Io)?;
            if n < 10 {
                continue;
            }
            if buf[2] != 0 {
                continue;
            }
            let Ok((dest, off)) = decode_udp_dest(&buf[3..n]) else {
                continue;
            };
            {
                let mut g = src_up.lock().unwrap();
                match *g {
                    None => {
                        *g = Some(src);
                    }
                    Some(known) if known != src => continue,
                    Some(_) => {}
                }
            }
            if !started_up.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let udp_dn = Arc::clone(&udp_up);
                let sock_dn = Arc::clone(&sock_up);
                let reply_to = src;
                tokio::spawn(async move {
                    loop {
                        match udp_dn.receive().await {
                            Ok((payload, addr)) => {
                                let pkt = encode_udp_reply(&addr, &payload);
                                let _ = sock_dn.send_to(&pkt, reply_to).await;
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            let _ = udp_up.send(&buf[3 + off..n], &dest).await;
        }
        #[allow(unreachable_code)]
        Ok::<_, Error>(())
    };

    tokio::select! {
        r = up => { let _ = r; }
        _ = async {
            let mut tmp = [0u8; 64];
            loop {
                match s.read(&mut tmp).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        } => {}
    }
    let _ = udp.close().await;
    Ok(())
}

async fn read_addr(s: &mut TcpStream, atyp: u8) -> Result<String, Error> {
    match atyp {
        1 => {
            let mut a = [0u8; 6];
            s.read_exact(&mut a).await.map_err(Error::Io)?;
            let ip = Ipv4Addr::new(a[0], a[1], a[2], a[3]);
            let port = u16::from_be_bytes([a[4], a[5]]);
            Ok(format!("{ip}:{port}"))
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(Error::Io)?;
            let mut name = vec![0u8; l[0] as usize];
            s.read_exact(&mut name).await.map_err(Error::Io)?;
            let mut p = [0u8; 2];
            s.read_exact(&mut p).await.map_err(Error::Io)?;
            let port = u16::from_be_bytes(p);
            Ok(format!("{}:{port}", String::from_utf8_lossy(&name)))
        }
        4 => {
            let mut a = [0u8; 18];
            s.read_exact(&mut a).await.map_err(Error::Io)?;
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&a[..16]);
            let ip = Ipv6Addr::from(oct);
            let port = u16::from_be_bytes([a[16], a[17]]);
            Ok(format!("[{ip}]:{port}"))
        }
        _ => Err(Error::protocol("bad socks atyp")),
    }
}

fn decode_udp_dest(buf: &[u8]) -> Result<(String, usize), Error> {
    if buf.is_empty() {
        return Err(Error::protocol("short"));
    }
    match buf[0] {
        1 if buf.len() >= 7 => {
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((format!("{ip}:{port}"), 7))
        }
        3 if buf.len() >= 2 => {
            let l = buf[1] as usize;
            if buf.len() < 2 + l + 2 {
                return Err(Error::protocol("short"));
            }
            let name = String::from_utf8_lossy(&buf[2..2 + l]);
            let port = u16::from_be_bytes([buf[2 + l], buf[3 + l]]);
            Ok((format!("{name}:{port}"), 2 + l + 2))
        }
        4 if buf.len() >= 19 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(&buf[1..17]);
            let ip = Ipv6Addr::from(oct);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((format!("[{ip}]:{port}"), 19))
        }
        _ => Err(Error::protocol("bad udp atyp")),
    }
}

fn encode_udp_reply(addr: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0];
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        match sa.ip() {
            IpAddr::V4(ip) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&sa.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&sa.port().to_be_bytes());
            }
        }
    } else {
        out.push(1);
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    out.extend_from_slice(payload);
    out
}
