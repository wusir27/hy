//! Server `serve` + TCP/UDP proxy.

use super::udp::ServerUdpSm;
use super::{
    Authenticator, Config, EventLogger, HyTcpStream, HyUdpSocket, Outbound, Server, TrafficLogger,
};
use crate::congestion::apply_cc_mode;
use crate::error::Error;
use crate::protocol::{
    read_tcp_request_bytes, write_tcp_response_bytes, AuthResponse, CLOSE_EXCESSIVE_LOAD, CLOSE_OK,
};
use crate::transport::h3_auth;
use crate::transport::h3_dispatch::StreamDispatcher;
use crate::transport::quic;
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

fn tracing_log(e: &Error) {
    tracing::info!(err = %e, "server conn error");
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
    let authenticated = Arc::new(AtomicBool::new(false));
    let auth_id_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    let on_tcp = {
        let outbound = cfg.outbound.clone();
        let hook = cfg.request_hook.clone();
        let auth_id_slot = auth_id_slot.clone();
        let ev = cfg.event_logger.clone();
        let tl = cfg.traffic_logger.clone();
        let c = conn.clone();
        Arc::new(move |send: SendStream, recv: RecvStream, leftover: Vec<u8>| {
            let outbound = outbound.clone();
            let hook = hook.clone();
            let auth_id = auth_id_slot.lock().unwrap().clone();
            let ev = ev.clone();
            let tl = tl.clone();
            let c = c.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_tcp(
                    send, recv, leftover, outbound, hook, remote, &auth_id, ev, tl, c,
                )
                .await
                {
                    tracing::info!(remote = %remote, id = %auth_id, err = %e, "tcp stream error");
                }
            });
        }) as crate::transport::h3_dispatch::TcpHijack
    };

    let dispatcher = StreamDispatcher::new(conn.clone(), authenticated.clone(), on_tcp);
    let mut h3_conn = h3::server::Connection::new(dispatcher)
        .await
        .map_err(|e| Error::Connect(format!("h3 server: {e}")))?;

    let mut first_auth: Option<(String, AuthResponse)> = None;
    let mut udp_sm = None;
    let mut accept_err: Option<Error> = None;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (req, stream) = match resolver.resolve_request().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::info!(remote = %remote, err = %e, "h3 resolve");
                        continue;
                    }
                };
                let already = first_auth
                    .as_ref()
                    .map(|(id, resp)| (id.as_str(), resp));
                match h3_auth::server_handle_auth_request(
                    req,
                    stream,
                    remote,
                    cfg.authenticator.as_ref(),
                    cfg.ignore_client_bw,
                    cfg.max_tx,
                    cfg.max_rx,
                    cfg.disable_udp,
                    cfg.masq.as_deref(),
                    already,
                )
                .await
                {
                    Ok(Some((id, resp, cc))) => {
                        *auth_id_slot.lock().unwrap() = id.clone();
                        authenticated.store(true, Ordering::Release);
                        apply_cc_mode(&conn, cc);
                        if let Some(ref ev) = cfg.event_logger {
                            ev.connect(remote, &id, cfg.max_tx);
                        }
                        if let Some(ref tl) = cfg.traffic_logger {
                            tl.log_online_state(&id, true);
                        }
                        udp_sm = Some(ServerUdpSm::start(
                            conn.clone(),
                            cfg.outbound.clone(),
                            cfg.request_hook.clone(),
                            cfg.event_logger.clone(),
                            cfg.traffic_logger.clone(),
                            id.clone(),
                            remote,
                            cfg.udp_idle,
                            cfg.disable_udp,
                        ));
                        first_auth = Some((id, resp));
                    }
                    Ok(None) => {}
                    Err(e) => tracing_log(&e),
                }
            }
            Ok(None) => break,
            Err(e) => {
                accept_err = Some(Error::Connect(format!("h3 accept: {e}")));
                break;
            }
        }
    }

    let _ = udp_sm;
    if let Some((id, _)) = &first_auth {
        let closed = conn.close_reason().map(|e| Error::Closed(Some(e.to_string())));
        if let Some(ref ev) = cfg.event_logger {
            ev.disconnect(remote, id, closed.as_ref());
        }
        if let Some(ref tl) = cfg.traffic_logger {
            tl.log_online_state(id, false);
        }
    }
    match accept_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

async fn handle_tcp(
    mut send: SendStream,
    recv: RecvStream,
    leftover: Vec<u8>,
    outbound: Arc<dyn Outbound>,
    request_hook: Option<Arc<dyn super::RequestHook>>,
    remote: SocketAddr,
    auth_id: &str,
    event_logger: Option<Arc<dyn EventLogger>>,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    conn: Connection,
) -> Result<(), Error> {
    // 0x401 already consumed by StreamDispatcher (official ReadTCPRequest
    // starts at address length).
    let mut buf = leftover;
    let mut recv = recv;
    let (mut addr, after_req) = loop {
        match read_tcp_request_bytes(&buf) {
            Ok((addr, consumed)) => break (addr, consumed),
            Err(Error::Protocol(_)) if buf.len() < 8192 => {
                let mut tmp = [0u8; 512];
                let n = recv
                    .read(&mut tmp)
                    .await
                    .map_err(|e| Error::Closed(Some(e.to_string())))?
                    .ok_or_else(|| Error::Protocol("eof before tcp request".into()))?;
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(e) => return Err(e),
        }
    };
    let leftover = if after_req < buf.len() {
        buf[after_req..].to_vec()
    } else {
        Vec::new()
    };

    let mut hooked = false;
    let mut hook_putback = Vec::new();
    let mut client = RecvAsHyTcp {
        leftover,
        recv,
    };

    if let Some(ref hook) = request_hook {
        if hook.check(false, &addr) {
            let resp = write_tcp_response_bytes(true, "RequestHook enabled");
            send.write_all(&resp)
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            hooked = true;
            hook_putback = hook.tcp(&mut client, &mut addr).await?;
        }
    }

    if let Some(ref ev) = event_logger {
        ev.tcp_request(remote, auth_id, &addr);
    }
    tracing::info!(remote = %remote, id = %auth_id, dest = %addr, "tcp request");

    match outbound.tcp(&addr).await {
        Err(e) => {
            tracing::info!(
                remote = %remote,
                id = %auth_id,
                dest = %addr,
                result = e.outbound_result(),
                err = %e,
                "tcp outbound"
            );
            if !hooked {
                let msg = e.to_string();
                let resp = write_tcp_response_bytes(false, &msg);
                let _ = send.write_all(&resp).await;
            }
            let _ = send.finish();
            if let Some(ref ev) = event_logger {
                ev.tcp_error(remote, auth_id, &addr, Some(&e));
            }
            return Ok(());
        }
        Ok(mut remote_tcp) => {
            tracing::info!(
                remote = %remote,
                id = %auth_id,
                dest = %addr,
                result = "ok",
                "tcp outbound"
            );
            if !hooked {
                let resp = write_tcp_response_bytes(true, "Connected");
                send.write_all(&resp)
                    .await
                    .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
            }

            // Hook putback (bytes sniffed from client) plus any unused leftover.
            let mut to_remote = hook_putback;
            if !client.leftover.is_empty() {
                to_remote.extend_from_slice(&client.leftover);
                client.leftover.clear();
            }
            if !to_remote.is_empty() {
                let _ = remote_tcp.write(&to_remote).await;
            }

            let err = copy_two_way(
                &mut send,
                &mut client,
                remote_tcp.as_mut(),
                auth_id,
                traffic_logger.as_deref(),
            )
            .await;
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

/// Wraps a QUIC recv stream plus bytes already read after the TCP request.
struct RecvAsHyTcp {
    leftover: Vec<u8>,
    recv: RecvStream,
}

#[async_trait]
impl HyTcpStream for RecvAsHyTcp {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        if !self.leftover.is_empty() {
            let n = std::cmp::min(buf.len(), self.leftover.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }
        match self.recv.read(buf).await {
            Ok(Some(n)) => Ok(n),
            Ok(None) => Ok(0),
            Err(e) => Err(Error::Closed(Some(e.to_string()))),
        }
    }

    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::Protocol("RecvAsHyTcp is read-only".into()))
    }

    async fn close(&mut self) -> Result<(), Error> {
        let _ = self.recv.stop(quinn::VarInt::from_u32(0));
        Ok(())
    }
}

/// Bidirectional copy. Either side finishing ends both.
async fn copy_two_way(
    send: &mut SendStream,
    client: &mut dyn HyTcpStream,
    remote: &mut dyn HyTcpStream,
    auth_id: &str,
    traffic: Option<&dyn TrafficLogger>,
) -> Option<Error> {
    let mut c2r_buf = vec![0u8; 32 * 1024];
    let mut r2c_buf = vec![0u8; 32 * 1024];

    loop {
        tokio::select! {
            n = client.read(&mut c2r_buf) => {
                match n {
                    Ok(0) => return None,
                    Ok(n) => {
                        if let Some(tl) = traffic {
                            if !tl.log_traffic(auth_id, n as u64, 0) {
                                return Some(Error::Closed(Some("kicked".into())));
                            }
                        }
                        if let Err(e) = remote.write(&c2r_buf[..n]).await {
                            return Some(e);
                        }
                    }
                    Err(e) => return Some(e),
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
