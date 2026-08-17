//! Server UDP session manager.

use super::{EventLogger, HyUdpSocket, Outbound, RequestHook, TrafficLogger};
use crate::error::Error;
use crate::frag::{frag_udp_message, Defragger};
use crate::protocol::{parse_udp_message, UdpMessage, CLOSE_EXCESSIVE_LOAD, MAX_UDP_SIZE};
use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const IDLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_SESSION_ACL_CACHE: usize = 256;
const WRITE_CHAN_CAP: usize = 256;

pub struct ServerUdpSm {
    conn: Connection,
    outbound: Arc<dyn Outbound>,
    hook: Option<Arc<dyn RequestHook>>,
    event_logger: Option<Arc<dyn EventLogger>>,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    auth_id: String,
    remote: SocketAddr,
    idle: Duration,
    sessions: Mutex<HashMap<u32, Arc<Session>>>,
    disable_udp: bool,
}

struct Session {
    id: u32,
    override_addr: Mutex<Option<String>>,
    original_addr: Mutex<Option<String>>,
    defrag: Mutex<Defragger>,
    last_ms: AtomicU64,
    /// Outbound writes; receive_loop owns the socket and drains this.
    write_tx: Mutex<Option<mpsc::Sender<(Vec<u8>, String)>>>,
    closed: AtomicBool,
    acl_cache: Mutex<HashMap<String, Option<String>>>,
}

impl ServerUdpSm {
    pub fn start(
        conn: Connection,
        outbound: Arc<dyn Outbound>,
        hook: Option<Arc<dyn RequestHook>>,
        event_logger: Option<Arc<dyn EventLogger>>,
        traffic_logger: Option<Arc<dyn TrafficLogger>>,
        auth_id: String,
        remote: SocketAddr,
        idle: Duration,
        disable_udp: bool,
    ) -> Arc<Self> {
        let sm = Arc::new(Self {
            conn: conn.clone(),
            outbound,
            hook,
            event_logger,
            traffic_logger,
            auth_id,
            remote,
            idle,
            sessions: Mutex::new(HashMap::new()),
            disable_udp,
        });
        let sm2 = Arc::clone(&sm);
        tokio::spawn(async move {
            let _ = sm2.run().await;
        });
        sm
    }

    async fn run(self: Arc<Self>) -> Result<(), Error> {
        let sm_idle = Arc::clone(&self);
        let idle_task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(IDLE_CLEANUP_INTERVAL);
            loop {
                tick.tick().await;
                sm_idle.cleanup_idle().await;
            }
        });

        let result = loop {
            let bytes = match self.conn.read_datagram().await {
                Ok(b) => b,
                Err(e) => break Err(Error::Closed(Some(e.to_string()))),
            };
            udp_trace(&format!("recv_dgram len={}", bytes.len()));
            if self.disable_udp {
                continue;
            }
            let msg = match parse_udp_message(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    udp_trace(&format!("parse_err len={} {e}", bytes.len()));
                    continue;
                }
            };
            if !self.note_traffic(msg.data.len() as u64, 0) {
                break Err(Error::Closed(Some("kicked".into())));
            }
            udp_trace(&format!(
                "parsed sid={} pkt={} frag={}/{} addr_len={} data_len={}",
                msg.session_id, msg.packet_id, msg.frag_id, msg.frag_count, msg.addr.len(), msg.data.len()
            ));
            self.feed(msg).await;
        };

        idle_task.abort();
        self.cleanup_all().await;
        result
    }

    async fn feed(self: &Arc<Self>, msg: UdpMessage) {
        let session_id = msg.session_id;
        let session = {
            let mut map = self.sessions.lock().unwrap();
            if let Some(s) = map.get(&session_id) {
                Arc::clone(s)
            } else {
                let s = Arc::new(Session {
                    id: session_id,
                    override_addr: Mutex::new(None),
                    original_addr: Mutex::new(None),
                    defrag: Mutex::new(Defragger::new()),
                    last_ms: AtomicU64::new(now_ms()),
                    write_tx: Mutex::new(None),
                    closed: AtomicBool::new(false),
                    acl_cache: Mutex::new(HashMap::new()),
                });
                map.insert(session_id, Arc::clone(&s));
                s
            }
        };

        session.last_ms.store(now_ms(), Ordering::SeqCst);

        let complete = {
            let mut d = session.defrag.lock().unwrap();
            d.feed(msg)
        };
        let Some(complete) = complete else {
            return;
        };

        // First complete packet: dial + spawn io loop.
        let need_init = session.write_tx.lock().unwrap().is_none()
            && !session.closed.load(Ordering::SeqCst);
        if need_init {
            match self.init_session(&session, &complete).await {
                Ok(sock) => {
                    if session.override_addr.lock().unwrap().is_none() {
                        let mut cache = session.acl_cache.lock().unwrap();
                        cache.insert(complete.addr.clone(), None);
                    }
                    let (tx, rx) = mpsc::channel(WRITE_CHAN_CAP);
                    *session.write_tx.lock().unwrap() = Some(tx);
                    self.spawn_io_loop(Arc::clone(&session), sock, rx);
                }
                Err(e) => {
                    self.close_session(&session, Some(e)).await;
                    return;
                }
            }
        }

        if session.closed.load(Ordering::SeqCst) {
            return;
        }

        let addr = {
            let over = session.override_addr.lock().unwrap().clone();
            if let Some(a) = over {
                a
            } else {
                if let Err(e) = self.check_udp_cached(&session, &complete.addr).await {
                    tracing::info!(
                        remote = %self.remote,
                        id = %self.auth_id,
                        dest = %complete.addr,
                        result = e.outbound_result(),
                        err = %e,
                        "udp outbound"
                    );
                    return;
                }
                complete.addr.clone()
            }
        };

        let tx = session.write_tx.lock().unwrap().clone();
        if let Some(tx) = tx {
            let _ = tx.try_send((complete.data, addr)); // full → drop
        }
    }

    async fn init_session(
        &self,
        session: &Session,
        first: &UdpMessage,
    ) -> Result<Box<dyn HyUdpSocket>, Error> {
        let mut addr = first.addr.clone();
        if let Some(ref hook) = self.hook {
            if hook.check(true, &addr) {
                hook.udp(&first.data, &mut addr).await?;
            }
        }
        let actual = addr.clone();
        if let Some(ref ev) = self.event_logger {
            ev.udp_request(self.remote, &self.auth_id, session.id, &addr);
        }
        tracing::info!(
            remote = %self.remote,
            id = %self.auth_id,
            sid = session.id,
            dest = %addr,
            "udp request"
        );
        let sock = match self.outbound.udp(&addr).await {
            Ok(sock) => {
                tracing::info!(
                    remote = %self.remote,
                    id = %self.auth_id,
                    sid = session.id,
                    dest = %addr,
                    result = "ok",
                    "udp outbound"
                );
                sock
            }
            Err(e) => {
                tracing::info!(
                    remote = %self.remote,
                    id = %self.auth_id,
                    sid = session.id,
                    dest = %addr,
                    result = e.outbound_result(),
                    err = %e,
                    "udp outbound"
                );
                return Err(e);
            }
        };
        if first.addr != actual {
            *session.override_addr.lock().unwrap() = Some(actual);
            *session.original_addr.lock().unwrap() = Some(first.addr.clone());
        }
        Ok(sock)
    }

    async fn check_udp_cached(&self, session: &Session, addr: &str) -> Result<(), Error> {
        {
            let cache = session.acl_cache.lock().unwrap();
            if let Some(decision) = cache.get(addr) {
                return match decision {
                    None => Ok(()),
                    Some(msg) => Err(Error::Dial(msg.clone())),
                };
            }
        }
        let decision = match self.outbound.check_udp(addr).await {
            Ok(()) => None,
            Err(e) => Some(e.to_string()),
        };
        {
            let mut cache = session.acl_cache.lock().unwrap();
            if cache.len() >= MAX_SESSION_ACL_CACHE {
                if let Some(k) = cache.keys().next().cloned() {
                    cache.remove(&k);
                }
            }
            cache.insert(addr.to_string(), decision.clone());
        }
        match decision {
            None => Ok(()),
            Some(msg) => Err(Error::Dial(msg)),
        }
    }

    fn spawn_io_loop(
        self: &Arc<Self>,
        session: Arc<Session>,
        mut sock: Box<dyn HyUdpSocket>,
        mut write_rx: mpsc::Receiver<(Vec<u8>, String)>,
    ) {
        let sm = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_SIZE];
            loop {
                if session.closed.load(Ordering::SeqCst) {
                    let _ = sock.close().await;
                    break;
                }
                tokio::select! {
                    w = write_rx.recv() => {
                        match w {
                            Some((data, addr)) => {
                                if let Err(e) = sock.write_to(&data, &addr).await {
                                    sm.close_session(&session, Some(e)).await;
                                    break;
                                }
                            }
                            None => {
                                let _ = sock.close().await;
                                break;
                            }
                        }
                    }
                    r = sock.read_from(&mut buf) => {
                        match r {
                            Ok((n, raddr)) => {
                                session.last_ms.store(now_ms(), Ordering::SeqCst);
                                let addr = {
                                    let orig = session.original_addr.lock().unwrap();
                                    orig.clone().unwrap_or(raddr)
                                };
                                let msg = UdpMessage {
                                    session_id: session.id,
                                    packet_id: 0,
                                    frag_id: 0,
                                    frag_count: 1,
                                    addr,
                                    data: buf[..n].to_vec(),
                                };
                                if !sm.note_traffic(0, n as u64) {
                                    sm.close_session(&session, Some(Error::Closed(Some("kicked".into())))).await;
                                    break;
                                }
                                if let Err(e) = send_message_auto_frag(&sm.conn, &msg) {
                                    sm.close_session(&session, Some(e)).await;
                                    break;
                                }
                            }
                            Err(e) => {
                                sm.close_session(&session, Some(e)).await;
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    async fn close_session(&self, session: &Session, err: Option<Error>) {
        if session
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // Dropping write_tx closes the channel → io loop exits.
        *session.write_tx.lock().unwrap() = None;
        {
            let mut map = self.sessions.lock().unwrap();
            map.remove(&session.id);
        }
        if let Some(ref ev) = self.event_logger {
            ev.udp_error(self.remote, &self.auth_id, session.id, err.as_ref());
        }
    }

    async fn cleanup_idle(self: &Arc<Self>) {
        let now = now_ms();
        let idle_ms = self.idle.as_millis() as u64;
        let stale: Vec<Arc<Session>> = {
            let map = self.sessions.lock().unwrap();
            map.values()
                .filter(|s| now.saturating_sub(s.last_ms.load(Ordering::SeqCst)) > idle_ms)
                .cloned()
                .collect()
        };
        for s in stale {
            self.close_session(&s, None).await;
        }
    }

    async fn cleanup_all(self: &Arc<Self>) {
        let all: Vec<Arc<Session>> = {
            let map = self.sessions.lock().unwrap();
            map.values().cloned().collect()
        };
        for s in all {
            self.close_session(&s, None).await;
        }
    }
}

impl ServerUdpSm {
    fn note_traffic(&self, tx: u64, rx: u64) -> bool {
        let Some(tl) = &self.traffic_logger else {
            return true;
        };
        if tl.log_traffic(&self.auth_id, tx, rx) {
            return true;
        }
        self.conn.close(
            quinn::VarInt::from_u32(CLOSE_EXCESSIVE_LOAD as u32),
            b"kicked",
        );
        false
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn send_message_auto_frag(conn: &Connection, msg: &UdpMessage) -> Result<(), Error> {
    let budget = crate::transport::quic::datagram_send_budget(conn);
    if msg.size() <= budget {
        return match send_datagram(conn, msg) {
            Ok(()) => Ok(()),
            Err(SendFail::TooLarge) => send_frags(conn, msg.clone(), budget),
            Err(SendFail::Other(e)) => Err(e),
        };
    }
    send_frags(conn, msg.clone(), budget)
}

fn send_frags(conn: &Connection, mut msg: UdpMessage, max: usize) -> Result<(), Error> {
    msg.packet_id = rand::thread_rng().gen_range(1..=0xFFFF);
    let frags = frag_udp_message(&msg, max);
    for f in frags {
        send_datagram(conn, &f).map_err(|e| match e {
            SendFail::TooLarge => Error::Protocol("datagram still too large".into()),
            SendFail::Other(e) => e,
        })?;
    }
    Ok(())
}

enum SendFail {
    TooLarge,
    Other(Error),
}

fn send_datagram(conn: &Connection, msg: &UdpMessage) -> Result<(), SendFail> {
    let mut buf = vec![0u8; MAX_UDP_SIZE];
    let n = msg.serialize(&mut buf);
    if n < 0 {
        return Ok(());
    }
    udp_trace(&format!("send_dgram len={n} sid={} frag={}/{}", msg.session_id, msg.frag_id, msg.frag_count));
    match conn.send_datagram(Bytes::copy_from_slice(&buf[..n as usize])) {
        Ok(()) => Ok(()),
        Err(SendDatagramError::TooLarge) => Err(SendFail::TooLarge),
        Err(SendDatagramError::ConnectionLost(e)) => {
            Err(SendFail::Other(Error::Closed(Some(e.to_string()))))
        }
        Err(e) => Err(SendFail::Other(Error::Quic(e.to_string()))),
    }
}

fn udp_trace(msg: &str) {
    if std::env::var_os("HY_UDP_TRACE").is_none() {
        return;
    }
    let line = format!("{msg}\n");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/hy-udp-trace.log")
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(line.as_bytes())
        });
}
