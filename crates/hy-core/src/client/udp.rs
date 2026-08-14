//! Client UDP session manager.

use super::HyUdpConn;
use crate::error::Error;
use crate::frag::{frag_udp_message, Defragger};
use crate::protocol::{parse_udp_message, UdpMessage, MAX_UDP_SIZE};
use async_trait::async_trait;
use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use rand::Rng;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const UDP_CHAN_CAP: usize = 1024;

pub struct ClientUdpSm {
    conn: Connection,
    sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
    next_id: AtomicU32,
    closed: AtomicBool,
}

impl ClientUdpSm {
    pub fn start(conn: Connection) -> Arc<Self> {
        let sm = Arc::new(Self {
            conn: conn.clone(),
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
        });
        let sm2 = Arc::clone(&sm);
        tokio::spawn(async move {
            let _ = sm2.run().await;
        });
        sm
    }

    async fn run(self: Arc<Self>) -> Result<(), Error> {
        loop {
            let bytes = match self.conn.read_datagram().await {
                Ok(b) => b,
                Err(_) => {
                    self.close_all();
                    return Err(Error::Closed(None));
                }
            };
            let Ok(msg) = parse_udp_message(&bytes) else {
                continue;
            };
            let tx = {
                let map = self.sessions.lock().unwrap();
                map.get(&msg.session_id).cloned()
            };
            if let Some(tx) = tx {
                let _ = tx.try_send(msg); // full → drop
            }
            // unknown downlink session_id: drop
        }
    }

    fn close_all(&self) {
        self.closed.store(true, Ordering::SeqCst);
        let mut map = self.sessions.lock().unwrap();
        map.clear(); // drop senders → receivers get None
    }

    pub fn new_udp(self: &Arc<Self>) -> Result<Box<dyn HyUdpConn>, Error> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed(None));
        }
        let mut map = self.sessions.lock().unwrap();
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed(None));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(UDP_CHAN_CAP);
        map.insert(id, tx);
        drop(map);

        let sm = Arc::clone(self);
        Ok(Box::new(UdpSession {
            id,
            recv: tokio::sync::Mutex::new(RecvState {
                rx,
                defrag: Defragger::new(),
            }),
            conn: self.conn.clone(),
            send_mu: tokio::sync::Mutex::new(()),
            closed: AtomicBool::new(false),
            on_close: Box::new(move || {
                let mut map = sm.sessions.lock().unwrap();
                map.remove(&id);
            }),
        }))
    }
}

struct RecvState {
    rx: mpsc::Receiver<UdpMessage>,
    defrag: Defragger,
}

struct UdpSession {
    id: u32,
    recv: tokio::sync::Mutex<RecvState>,
    conn: Connection,
    send_mu: tokio::sync::Mutex<()>,
    closed: AtomicBool,
    on_close: Box<dyn Fn() + Send + Sync>,
}

#[async_trait]
impl HyUdpConn for UdpSession {
    async fn receive(&self) -> Result<(Vec<u8>, String), Error> {
        let mut st = self.recv.lock().await;
        loop {
            let msg = match st.rx.recv().await {
                Some(m) => m,
                None => return Err(Error::Closed(None)),
            };
            if let Some(complete) = st.defrag.feed(msg) {
                return Ok((complete.data, complete.addr));
            }
        }
    }

    async fn send(&self, data: &[u8], addr: &str) -> Result<(), Error> {
        let _guard = self.send_mu.lock().await;
        let msg = UdpMessage {
            session_id: self.id,
            packet_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: addr.to_string(),
            data: data.to_vec(),
        };
        let budget = crate::transport::quic::datagram_send_budget(&self.conn);
        if msg.size() <= budget {
            return match send_datagram(&self.conn, &msg) {
                Ok(()) => Ok(()),
                Err(SendFail::TooLarge) => send_frags(&self.conn, msg, budget),
                Err(SendFail::Other(e)) => Err(e),
            };
        }
        send_frags(&self.conn, msg, budget)
    }

    async fn close(&self) -> Result<(), Error> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            (self.on_close)();
        }
        Ok(())
    }
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
        // buffer too small — silent drop (Go align)
        return Ok(());
    }
    match conn.send_datagram(Bytes::copy_from_slice(&buf[..n as usize])) {
        Ok(()) => Ok(()),
        Err(SendDatagramError::TooLarge) => Err(SendFail::TooLarge),
        Err(SendDatagramError::ConnectionLost(e)) => {
            Err(SendFail::Other(Error::Closed(Some(e.to_string()))))
        }
        Err(e) => Err(SendFail::Other(Error::Quic(e.to_string()))),
    }
}
