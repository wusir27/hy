//! Server `serve` + TCP/UDP proxy.

use super::udp::ServerUdpSm;
use super::{
    Authenticator, Config, EventLogger, HyTcpStream, HyUdpSocket, Outbound, Server, StreamDump,
    StreamStats, TrafficLogger,
};
use crate::congestion::apply_cc_mode;
use crate::error::Error;
use crate::p9x::{alloc_conn_seq, parse_close_code, P9xConn, TcpByteCounts}; // side = "hy"
use crate::protocol::varint_decode;
use crate::protocol::{
    read_tcp_request_bytes, write_tcp_response_bytes, CLOSE_OK, FRAME_TYPE_TCP_REQUEST,
};
use crate::transport::h3_auth;
use crate::transport::h3_uni::QueuedTcpBidi;
use crate::transport::quic;
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h3::quic::{BidiStream, RecvStream as H3RecvStream, SendStream as H3SendStream, SendStreamUnframed};
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
                                let p9x = P9xConn::new(alloc_conn_seq(), conn.remote_address());
                                p9x.conn_accept();
                                if let Err(e) = handle_conn(conn, cfg, p9x).await {
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
    tracing::error!(err = %e, "server conn error");
}

fn h3_display_is_peer_normal_close(e: &impl std::fmt::Display) -> bool {
    let s = e.to_string();
    s.contains("ApplicationClose: 0x0") || s.contains("H3_NO_ERROR")
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

async fn handle_conn(conn: Connection, cfg: ServerConnCfg, p9x: P9xConn) -> Result<(), Error> {
    let remote = conn.remote_address();
    let (auth, mut h3_keep, mut tcp_rx) = h3_auth::server_authenticate(
        conn.clone(),
        cfg.authenticator.clone(),
        cfg.ignore_client_bw,
        cfg.max_tx,
        cfg.max_rx,
        cfg.disable_udp,
        cfg.masq.clone(),
        p9x,
    )
    .await?;

    let Some((auth_id, auth_resp, cc_choice)) = auth else {
        // Unauthenticated: drop queued 0x401 without outbound dial.
        drop(tcp_rx);
        let err = conn.closed().await;
        let err_s = err.to_string();
        p9x.close_remote("remote", parse_close_code(&err_s), &err_s);
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
        p9x,
    );

    // Drain 0x401 peeked during authenticate. Outbound only after 233.
    let mut tcp_started = false;
    while let Ok(queued) = tcp_rx.try_recv() {
        tcp_started = true;
        spawn_queued_tcp(
            queued,
            cfg.outbound.clone(),
            cfg.request_hook.clone(),
            remote,
            auth_id.clone(),
            cfg.event_logger.clone(),
            cfg.traffic_logger.clone(),
            conn.clone(),
            p9x,
        );
    }

    // Keep polling the same wrapper in this task. Hold is only so Drop does
    // not close QUIC — a spawn that parks h3 without polling would eat 0x401.
    // After ApplicationClose 0x0, stop polling accept (sticky error) but keep
    // the wrapper so held extra unis are not Drop/STOP_SENDING, and leave
    // in-flight handle_tcp copy tasks running until QUIC itself closes.
    let mut h3_gone = false;
    loop {
        tokio::select! {
            h3 = h3_keep.accept(), if !h3_gone => {
                match h3 {
                    Ok(Some(resolver)) => {
                        let auth_resp = auth_resp.clone();
                        let masq = cfg.masq.clone();
                        let p9x = p9x;
                        tokio::spawn(async move {
                            match resolver.resolve_request().await {
                                Ok((req, stream)) => {
                                    if let Err(e) = h3_auth::server_handle_authed_http(
                                        req,
                                        stream,
                                        &auth_resp,
                                        masq.as_deref(),
                                        p9x,
                                    )
                                    .await
                                    {
                                        if h3_auth::later_http_peer_closed(&e) {
                                            tracing::debug!(err = %e, "h3 later request");
                                        } else {
                                            tracing::error!(err = %e, "h3 later request");
                                        }
                                    }
                                }
                                Err(e) => {
                                    if h3_display_is_peer_normal_close(&e) {
                                        tracing::debug!(err = %e, "h3 resolve");
                                    } else {
                                        tracing::error!(err = %e, "h3 resolve");
                                    }
                                }
                            }
                        });
                    }
                    Ok(None) => {
                        tracing::debug!("h3 accept ended");
                        if tcp_started {
                            h3_gone = true;
                        } else {
                            let err = conn.closed().await;
                            let err_s = err.to_string();
                            p9x.close_remote("remote", parse_close_code(&err_s), &err_s);
                            emit_disconnect(&cfg, remote, &auth_id, &err);
                            break;
                        }
                    }
                    Err(e) => {
                        if h3_auth::h3_accept_is_peer_normal_close(&e) {
                            tracing::debug!(err = %e, "h3 accept");
                        } else {
                            tracing::error!(err = %e, "h3 accept");
                        }
                        if tcp_started && h3_auth::h3_accept_is_peer_normal_close(&e) {
                            let err_s = e.to_string();
                            p9x.close_remote("remote", parse_close_code(&err_s), &err_s);
                            h3_gone = true;
                        } else {
                            let err = conn.closed().await;
                            let err_s = err.to_string();
                            p9x.close_remote("remote", parse_close_code(&err_s), &err_s);
                            emit_disconnect(&cfg, remote, &auth_id, &err);
                            break;
                        }
                    }
                }
            }
            queued = tcp_rx.recv() => {
                if let Some(queued) = queued {
                    tcp_started = true;
                    spawn_queued_tcp(
                        queued,
                        cfg.outbound.clone(),
                        cfg.request_hook.clone(),
                        remote,
                        auth_id.clone(),
                        cfg.event_logger.clone(),
                        cfg.traffic_logger.clone(),
                        conn.clone(),
                        p9x,
                    );
                }
            }
            err = conn.closed() => {
                let err_s = err.to_string();
                p9x.close_remote("remote", parse_close_code(&err_s), &err_s);
                emit_disconnect(&cfg, remote, &auth_id, &err);
                break;
            }
        }
    }
    Ok(())
}

fn emit_disconnect(
    cfg: &ServerConnCfg,
    remote: SocketAddr,
    auth_id: &str,
    err: &quinn::ConnectionError,
) {
    if let Some(ref ev) = cfg.event_logger {
        let e = Error::Closed(Some(err.to_string()));
        ev.disconnect(remote, auth_id, Some(&e));
    }
    if let Some(ref tl) = cfg.traffic_logger {
        tl.log_online_state(auth_id, false);
    }
}

fn spawn_queued_tcp(
    queued: QueuedTcpBidi,
    outbound: Arc<dyn Outbound>,
    hook: Option<Arc<dyn super::RequestHook>>,
    remote: SocketAddr,
    auth_id: String,
    ev: Option<Arc<dyn EventLogger>>,
    tl: Option<Arc<dyn TrafficLogger>>,
    c: Connection,
    p9x: P9xConn,
) {
    let (stream, prefix) = queued;
    let (send, recv) = stream.split();
    spawn_tcp(
        TcpSend::H3(send),
        TcpRecv::H3 {
            leftover: prefix,
            inner: recv,
        },
        outbound,
        hook,
        remote,
        auth_id,
        ev,
        tl,
        c,
        p9x,
    );
}

fn spawn_tcp(
    send: TcpSend,
    recv: TcpRecv,
    outbound: Arc<dyn Outbound>,
    hook: Option<Arc<dyn super::RequestHook>>,
    remote: SocketAddr,
    auth_id: String,
    ev: Option<Arc<dyn EventLogger>>,
    tl: Option<Arc<dyn TrafficLogger>>,
    c: Connection,
    p9x: P9xConn,
) {
    tokio::spawn(async move {
        if let Err(e) = handle_tcp(
            send, recv, outbound, hook, remote, &auth_id, ev, tl, c, p9x,
        )
        .await
        {
            tracing::error!(remote = %remote, id = %auth_id, err = %e, "tcp stream error");
        }
    });
}

enum TcpSend {
    #[allow(dead_code)]
    Quinn(SendStream),
    H3(h3_quinn::SendStream<Bytes>),
}

enum TcpRecv {
    #[allow(dead_code)]
    Quinn(RecvStream),
    H3 {
        leftover: Bytes,
        inner: h3_quinn::RecvStream,
    },
}

impl TcpSend {
    async fn write_all(&mut self, buf: &[u8]) -> Result<(), Error> {
        match self {
            TcpSend::Quinn(s) => s
                .write_all(buf)
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e))),
            TcpSend::H3(s) => {
                let mut remaining = buf;
                while !remaining.is_empty() {
                    let n = std::future::poll_fn(|cx| {
                        SendStreamUnframed::poll_send(s, cx, &mut remaining)
                    })
                    .await
                    .map_err(|e| Error::Quic(e.to_string()))?;
                    if n == 0 {
                        break;
                    }
                }
                Ok(())
            }
        }
    }

    async fn finish(&mut self) -> Result<(), Error> {
        match self {
            TcpSend::Quinn(s) => {
                let _ = s.finish();
                Ok(())
            }
            TcpSend::H3(s) => {
                let _ = std::future::poll_fn(|cx| H3SendStream::poll_finish(s, cx)).await;
                Ok(())
            }
        }
    }

    fn quic_stream_id(&self) -> u64 {
        match self {
            TcpSend::Quinn(s) => u64::from(s.id()),
            TcpSend::H3(s) => H3SendStream::send_id(s).into_inner(),
        }
    }
}

impl TcpRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            TcpRecv::Quinn(r) => match r.read(buf).await {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Ok(0),
                Err(e) => Err(Error::Closed(Some(e.to_string()))),
            },
            TcpRecv::H3 { leftover, inner } => {
                if leftover.is_empty() {
                    match std::future::poll_fn(|cx| H3RecvStream::poll_data(inner, cx)).await {
                        Ok(Some(b)) => *leftover = b,
                        Ok(None) => return Ok(0),
                        Err(e) => return Err(Error::Closed(Some(e.to_string()))),
                    }
                }
                if leftover.is_empty() {
                    return Ok(0);
                }
                let n = leftover.len().min(buf.len());
                buf[..n].copy_from_slice(&leftover[..n]);
                leftover.advance(n);
                Ok(n)
            }
        }
    }

    fn stop(&mut self) {
        match self {
            TcpRecv::Quinn(r) => {
                let _ = r.stop(quinn::VarInt::from_u32(0));
            }
            TcpRecv::H3 { inner, .. } => inner.stop_sending(0),
        }
    }
}

async fn handle_tcp(
    mut send: TcpSend,
    recv: TcpRecv,
    outbound: Arc<dyn Outbound>,
    request_hook: Option<Arc<dyn super::RequestHook>>,
    remote: SocketAddr,
    auth_id: &str,
    event_logger: Option<Arc<dyn EventLogger>>,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    conn: Connection,
    p9x: P9xConn,
) -> Result<(), Error> {
    let mut buf = Vec::with_capacity(256);
    let mut recv = recv;
    let (mut addr, after_req) = loop {
        let mut tmp = [0u8; 512];
        let n = recv.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::Protocol("eof before tcp request".into()));
        }
        buf.extend_from_slice(&tmp[..n]);

        let (frame, frame_n) = match varint_decode(&buf) {
            Ok(v) => v,
            Err(_) if buf.len() < 8 => continue,
            Err(e) => return Err(e),
        };
        if frame != FRAME_TYPE_TCP_REQUEST {
            let _ = send.finish().await;
            recv.stop();
            return Ok(());
        }
        match read_tcp_request_bytes(&buf[frame_n..]) {
            Ok((addr, consumed)) => break (addr, frame_n + consumed),
            Err(Error::Protocol(_)) if buf.len() < 8192 => continue,
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
            send.write_all(&resp).await?;
            hooked = true;
            hook_putback = hook.tcp(&mut client, &mut addr).await?;
        }
    }

    p9x.tcp_start(&addr.to_string(), None);
    let mut counts = TcpByteCounts::default();
    counts.add_initial_c2s(&client.leftover, &hook_putback);

    if let Some(ref ev) = event_logger {
        ev.tcp_request(remote, auth_id, &addr);
    }
    tracing::info!(remote = %remote, id = %auth_id, dest = %addr, "tcp request");

    let dump = StreamDump::maybe_start(
        traffic_logger.as_ref(),
        send.quic_stream_id(),
        StreamStats {
            auth_id: auth_id.to_string(),
            conn_id: p9x.conn_seq as u32,
            req_addr: addr.clone(),
            ..Default::default()
        },
    );

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
            let _ = send.finish().await;
            if let Some(ref ev) = event_logger {
                ev.tcp_error(remote, auth_id, &addr, Some(&e));
            }
            let err_s = e.to_string();
            p9x.tcp_end(&addr.to_string(), counts.c2s, counts.s2c, Some(&err_s), None);
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
                if let Err(e) = send.write_all(&resp).await {
                    let err_s = e.to_string();
                    p9x.tcp_end(&addr.to_string(), counts.c2s, counts.s2c, Some(&err_s), None);
                    return Err(e);
                }
            }

            // Hook putback (bytes sniffed from client) plus any unused leftover.
            let mut to_remote = hook_putback;
            if !client.leftover.is_empty() {
                to_remote.extend_from_slice(&client.leftover);
                client.leftover.clear();
            }
            if !to_remote.is_empty() {
                let n = to_remote.len() as u64;
                let _ = remote_tcp.write(&to_remote).await;
                if let Some(d) = dump.as_ref() {
                    d.stats.tx.fetch_add(n, Ordering::Relaxed);
                }
            }

            let err = copy_two_way(
                &mut send,
                &mut client,
                remote_tcp.as_mut(),
                auth_id,
                traffic_logger.as_deref(),
                dump.as_ref().map(|d| d.stats.as_ref()),
                &mut counts,
            )
            .await;
            if matches!(&err, Some(Error::Closed(Some(m))) if m == "kicked") {
                p9x.close_local(crate::protocol::CLOSE_EXCESSIVE_LOAD as u64);
                conn.close(
                    quinn::VarInt::from_u32(crate::protocol::CLOSE_EXCESSIVE_LOAD as u32),
                    b"kicked",
                );
            }
            let err_s = err.as_ref().map(|e| e.to_string());
            p9x.tcp_end(
                &addr.to_string(),
                counts.c2s,
                counts.s2c,
                err_s.as_deref(),
                None,
            );
            if let Some(ref ev) = event_logger {
                ev.tcp_error(remote, auth_id, &addr, err.as_ref());
            }
            let _ = send.finish().await;
            let _ = remote_tcp.close().await;
        }
    }
    Ok(())
}

/// Wraps a QUIC recv stream plus bytes already read after the TCP request.
struct RecvAsHyTcp {
    leftover: Vec<u8>,
    recv: TcpRecv,
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
        self.recv.read(buf).await
    }

    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::Protocol("RecvAsHyTcp is read-only".into()))
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.recv.stop();
        Ok(())
    }
}

/// Bidirectional copy. Either side finishing ends both.
async fn copy_two_way(
    send: &mut TcpSend,
    client: &mut dyn HyTcpStream,
    remote: &mut dyn HyTcpStream,
    auth_id: &str,
    traffic: Option<&dyn TrafficLogger>,
    dump: Option<&StreamStats>,
    counts: &mut TcpByteCounts,
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
                        if let Some(s) = dump {
                            s.tx.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        counts.add_c2s(n as u64);
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
                            return Some(e);
                        }
                        if let Some(s) = dump {
                            s.rx.fetch_add(n as u64, Ordering::Relaxed);
                        }
                        counts.add_s2c(n as u64);
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
