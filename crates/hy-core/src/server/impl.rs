//! Server `serve` + TCP/UDP proxy.

use super::udp::ServerUdpSm;
use super::{
    Authenticator, Config, EventLogger, HyTcpStream, HyUdpSocket, Outbound, Server, TrafficLogger,
};
use crate::congestion::apply_cc_mode;
use crate::error::Error;
use crate::protocol::varint_decode;
use crate::protocol::{
    read_tcp_request_bytes, write_tcp_response_bytes, CLOSE_EXCESSIVE_LOAD, CLOSE_OK, FRAME_TYPE_TCP_REQUEST,
};
use crate::transport::h3_auth;
use crate::transport::quic;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Notify;

struct ServerInner {
    cfg: Config,
    endpoint: quinn::Endpoint,
    shutdown: Notify,
    closed: AtomicBool,
}

/// Build endpoint and return a runnable server. Call [`Server::serve`] to accept.
pub async fn serve(mut cfg: Config) -> Result<Arc<dyn Server>, Error> {
    cfg.fill()?;
    let conn = cfg.conn.clone().expect("filled");
    let endpoint = quic::build_server_endpoint(
        conn,
        &cfg.tls,
        &cfg.quic,
        &cfg.congestion.ty,
        cfg.bandwidth.disable_loss_compensation,
    )?;
    Ok(Arc::new(ServerInner {
        cfg,
        endpoint,
        shutdown: Notify::new(),
        closed: AtomicBool::new(false),
    }))
}

#[async_trait]
impl Server for ServerInner {
    async fn serve(&self) -> Result<(), Error> {
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let cfg = ServerConnCfg {
                        authenticator: self.cfg.authenticator.clone().expect("filled"),
                        outbound: self.cfg.outbound.clone().unwrap_or_else(|| Arc::new(DefaultOutbound)),
                        ignore_client_bw: self.cfg.ignore_client_bandwidth,
                        max_tx: self.cfg.bandwidth.max_tx,
                        max_rx: self.cfg.bandwidth.max_rx,
                        disable_udp: self.cfg.disable_udp,
                        udp_idle: self.cfg.udp_idle_timeout,
                        request_hook: self.cfg.request_hook.clone(),
                        masq: self.cfg.masq_handler.clone(),
                        event_logger: self.cfg.event_logger.clone(),
                        traffic_logger: self.cfg.traffic_logger.clone(),
                    };
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                if let Err(e) = handle_conn(conn, cfg).await {
                                    tracing_log(&e);
                                }
                            }
                            Err(_) => {}
                        }
                    });
                }
                _ = self.shutdown.notified() => {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
        self.endpoint
            .close(quinn::VarInt::from_u32(CLOSE_OK as u32), b"");
        Ok(())
    }
}

fn tracing_log(_e: &Error) {
    // no tracing dep required
}

struct ServerConnCfg {
    authenticator: Arc<dyn Authenticator>,
    outbound: Arc<dyn Outbound>,
    ignore_client_bw: bool,
    max_tx: u64,
    max_rx: u64,
    disable_udp: bool,
    udp_idle: Duration,
    request_hook: Option<Arc<dyn super::RequestHook>>,
    masq: Option<Arc<dyn super::MasqHandler>>,
    event_logger: Option<Arc<dyn EventLogger>>,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
}

async fn handle_conn(conn: Connection, cfg: ServerConnCfg) -> Result<(), Error> {
    let remote = conn.remote_address();
    let (auth, h3_keep) = h3_auth::server_authenticate(
        conn.clone(),
        cfg.authenticator.clone(),
        cfg.ignore_client_bw,
        cfg.max_tx,
        cfg.max_rx,
        cfg.disable_udp,
        cfg.masq.clone(),
    )
    .await?;

    let Some((auth_id, _auth_resp, cc_choice)) = auth else {
        let _ = conn.closed().await;
        drop(h3_keep);
        return Ok(());
    };

    apply_cc_mode(&conn, cc_choice);

    if let Some(ref ev) = cfg.event_logger {
        ev.connect(remote, &auth_id, cfg.max_tx);
    }
    if let Some(ref tl) = cfg.traffic_logger {
        tl.log_online_state(&auth_id, true);
    }

    // Hold h3 so Drop does not close QUIC; stop accepting h3 requests.
    let hold_conn = conn.clone();
    tokio::spawn(async move {
        let _h3 = h3_keep;
        let _ = hold_conn.closed().await;
    });

    // UDP SM (even when disable_udp — it silently drops datagrams).
    let _udp_sm = ServerUdpSm::start(
        conn.clone(),
        cfg.outbound.clone(),
        cfg.request_hook.clone(),
        cfg.event_logger.clone(),
        cfg.traffic_logger.clone(),
        auth_id.clone(),
        remote,
        cfg.udp_idle,
        cfg.disable_udp,
    );

    // Authenticated: accept_bi for TCP (frame 0x401).
    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                match bi {
                    Ok((send, recv)) => {
                        let outbound = cfg.outbound.clone();
                        let auth_id = auth_id.clone();
                        let remote = remote;
                        let ev = cfg.event_logger.clone();
                        let tl = cfg.traffic_logger.clone();
                        let c = conn.clone();
                        tokio::spawn(async move {
                            let _ = handle_tcp(send, recv, outbound, remote, &auth_id, ev, tl, c).await;
                        });
                    }
                    Err(_) => break,
                }
            }
            err = conn.closed() => {
                if let Some(ref ev) = cfg.event_logger {
                    let e = Error::Closed(Some(err.to_string()));
                    ev.disconnect(remote, &auth_id, Some(&e));
                }
                if let Some(ref tl) = cfg.traffic_logger {
                    tl.log_online_state(&auth_id, false);
                }
                break;
            }
        }
    }
    Ok(())
}

async fn handle_tcp(
    mut send: SendStream,
    mut recv: RecvStream,
    outbound: Arc<dyn Outbound>,
    remote: SocketAddr,
    auth_id: &str,
    event_logger: Option<Arc<dyn EventLogger>>,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    conn: Connection,
) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(256);
    let (addr, after_req) = loop {
        let mut tmp = [0u8; 512];
        let n = recv
            .read(&mut tmp)
            .await
            .map_err(|e| Error::Closed(Some(e.to_string())))?
            .ok_or_else(|| Error::Protocol("eof before tcp request".into()))?;
        buf.extend_from_slice(&tmp[..n]);

        let (frame, frame_n) = match varint_decode(&buf) {
            Ok(v) => v,
            Err(_) if buf.len() < 8 => continue,
            Err(e) => return Err(e),
        };
        if frame != FRAME_TYPE_TCP_REQUEST {
            let _ = send.finish();
            let _ = recv.stop(quinn::VarInt::from_u32(0));
            return Ok(());
        }
        match read_tcp_request_bytes(&buf[frame_n..]) {
            Ok((addr, consumed)) => break (addr, frame_n + consumed),
            Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
            Err(e) => return Err(e),
        }
    };
    let _putback = if after_req < buf.len() {
        buf[after_req..].to_vec()
    } else {
        Vec::new()
    };

    if let Some(ref ev) = event_logger {
        ev.tcp_request(remote, auth_id, &addr);
    }

    match outbound.tcp(&addr).await {
        Err(e) => {
            let msg = e.to_string();
            let resp = write_tcp_response_bytes(false, &msg);
            let _ = send.write_all(&resp).await;
            let _ = send.finish();
            if let Some(ref ev) = event_logger {
                ev.tcp_error(remote, auth_id, &addr, Some(&e));
            }
            return Ok(());
        }
        Ok(mut remote_tcp) => {
            let resp = write_tcp_response_bytes(true, "Connected");
            send.write_all(&resp)
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

            if !_putback.is_empty() {
                let _ = remote_tcp.write(&_putback).await;
            }

            let err = copy_two_way(&mut send, &mut recv, remote_tcp.as_mut(), auth_id, traffic_logger.as_deref()).await;
            if matches!(&err, Some(Error::Closed(Some(m))) if m == "kicked") {
                conn.close(quinn::VarInt::from_u32(CLOSE_EXCESSIVE_LOAD as u32), b"kicked");
            }
            if let Some(ref ev) = event_logger {
                ev.tcp_error(remote, auth_id, &addr, err.as_ref());
            }
            let _ = send.finish();
            let _ = remote_tcp.close().await;
        }
    }
    Ok(())
}

/// Bidirectional copy. Either side finishing ends both.
async fn copy_two_way(
    send: &mut SendStream,
    recv: &mut RecvStream,
    remote: &mut dyn HyTcpStream,
    auth_id: &str,
    traffic: Option<&dyn TrafficLogger>,
) -> Option<Error> {
    let mut c2r_buf = vec![0u8; 32 * 1024];
    let mut r2c_buf = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            n = recv.read(&mut c2r_buf) => {
                match n {
                    Ok(Some(0)) | Ok(None) => return None,
                    Ok(Some(n)) => {
                        if let Some(tl) = traffic {
                            if !tl.log_traffic(auth_id, n as u64, 0) {
                                return Some(Error::Closed(Some("kicked".into())));
                            }
                        }
                        if let Err(e) = remote.write(&c2r_buf[..n]).await {
                            return Some(e);
                        }
                    }
                    Err(e) => return Some(Error::Closed(Some(e.to_string()))),
                }
            }
            n = remote.read(&mut r2c_buf) => {
                match n {
                    Ok(0) => return None,
                    Ok(n) => {
                        if let Some(tl) = traffic {
                            if !tl.log_traffic(auth_id, 0, n as u64) {
                                return Some(Error::Closed(Some("kicked".into())));
                            }
                        }
                        if let Err(e) = send.write_all(&r2c_buf[..n]).await {
                            return Some(Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)));
                        }
                    }
                    Err(e) => return Some(e),
                }
            }
        }
    }
}

/// Password authenticator (const password). extras/auth can replace later.
pub struct PasswordAuthenticator {
    pub password: String,
}

impl PasswordAuthenticator {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }
}

#[async_trait]
impl Authenticator for PasswordAuthenticator {
    async fn authenticate(&self, _addr: SocketAddr, auth: &str, _tx: u64) -> (bool, String) {
        if ct_eq(auth.as_bytes(), self.password.as_bytes()) {
            (true, "user".into())
        } else {
            (false, String::new())
        }
    }
}

/// Default outbound: TCP dial 10s; UDP `0.0.0.0:0` full-cone. `check_udp` always Ok.
pub struct DefaultOutbound;

#[async_trait]
impl Outbound for DefaultOutbound {
    async fn tcp(&self, req_addr: &str) -> Result<Box<dyn HyTcpStream>, Error> {
        let addr = req_addr.to_string();
        let fut = TcpStream::connect(addr);
        match tokio::time::timeout(Duration::from_secs(10), fut).await {
            Ok(Ok(stream)) => Ok(Box::new(TokioTcp(stream))),
            Ok(Err(e)) => Err(Error::Dial(e.to_string())),
            Err(_) => Err(Error::Dial("tcp dial timeout".into())),
        }
    }

    async fn udp(&self, _req_addr: &str) -> Result<Box<dyn HyUdpSocket>, Error> {
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| Error::Dial(e.to_string()))?;
        Ok(Box::new(TokioUdp(sock)))
    }

    async fn check_udp(&self, _req_addr: &str) -> Result<(), Error> {
        Ok(())
    }
}

struct TokioTcp(TcpStream);

#[async_trait]
impl HyTcpStream for TokioTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.0.read(buf).await.map_err(Error::Io)
    }

    async fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf).await.map_err(Error::Io)
    }

    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.0.shutdown().await;
        Ok(())
    }
}

struct TokioUdp(UdpSocket);

#[async_trait]
impl HyUdpSocket for TokioUdp {
    async fn read_from(&mut self, buf: &mut [u8]) -> Result<(usize, String), Error> {
        let (n, addr) = self.0.recv_from(buf).await.map_err(Error::Io)?;
        Ok((n, addr.to_string()))
    }

    async fn write_to(&mut self, buf: &[u8], addr: &str) -> Result<usize, Error> {
        let dest = resolve_udp_addr(addr).await?;
        self.0.send_to(buf, dest).await.map_err(Error::Io)
    }

    async fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

async fn resolve_udp_addr(addr: &str) -> Result<SocketAddr, Error> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let mut iter = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| Error::Dial(e.to_string()))?;
    iter.next()
        .ok_or_else(|| Error::Dial(format!("cannot resolve {addr}")))
}

/// Default masq: 404 empty.
pub struct DefaultMasq;

#[async_trait]
impl super::MasqHandler for DefaultMasq {
    async fn handle(&self, _method: &str, _host: &str, _path: &str) -> super::MasqResponse {
        super::MasqResponse {
            status: 404,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}
