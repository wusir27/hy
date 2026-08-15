//! `PunchPacketConn` — demux registered punch packets from QUIC/STUN on one UDP socket.
//!
//! Only registered attempts (magic+nonce match) are siphoned. STUN Binding
//! Success, QUIC, and unrecognized packets are returned as-is from `recv_from`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hy_core::io::DatagramIo;
use tokio::sync::mpsc;

use crate::realm::punch::{decode_punch_packet, decode_punch_metadata, PunchMetadata, PunchPacket};

const DEFAULT_EVENT_BUFFER: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrInvalidPunchAttempt;

impl std::fmt::Display for ErrInvalidPunchAttempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid punch attempt")
    }
}
impl std::error::Error for ErrInvalidPunchAttempt {}

#[derive(Debug, Clone)]
pub struct PunchPacketEvent {
    pub attempt_id: String,
    pub from: SocketAddr,
    pub packet: PunchPacket,
}

/// Routes registered punch packets to an event channel; other packets
/// (STUN, QUIC, unrecognized) pass through for `recv_from` callers.
pub struct PunchPacketConn {
    inner: Arc<dyn DatagramIo>,
    attempts: Mutex<HashMap<String, PunchMetadata>>,
    events_tx: mpsc::Sender<PunchPacketEvent>,
    events_rx: Mutex<Option<mpsc::Receiver<PunchPacketEvent>>>,
}

impl PunchPacketConn {
    pub fn new(inner: Arc<dyn DatagramIo>, event_buffer: usize) -> Result<Self, ErrInvalidPunchAttempt> {
        let buf = if event_buffer == 0 {
            DEFAULT_EVENT_BUFFER
        } else {
            event_buffer
        };
        let (events_tx, events_rx) = mpsc::channel(buf);
        Ok(Self {
            inner,
            attempts: Mutex::new(HashMap::new()),
            events_tx,
            events_rx: Mutex::new(Some(events_rx)),
        })
    }

    pub fn take_events(&self) -> Option<mpsc::Receiver<PunchPacketEvent>> {
        self.events_rx.lock().unwrap().take()
    }

    pub fn add_punch_attempt(
        &self,
        id: &str,
        meta: PunchMetadata,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if id.is_empty() {
            return Err(Box::new(ErrInvalidPunchAttempt));
        }
        decode_punch_metadata(&meta)?;
        self.attempts.lock().unwrap().insert(id.to_string(), meta);
        Ok(())
    }

    pub fn remove_punch_attempt(&self, id: &str) {
        self.attempts.lock().unwrap().remove(id);
    }

    pub fn inner(&self) -> Arc<dyn DatagramIo> {
        self.inner.clone()
    }
}

#[async_trait]
impl DatagramIo for PunchPacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            let (n, addr) = self.inner.recv_from(buf).await?;
            let packet = &buf[..n];
            let attempts = self.attempts.lock().unwrap().clone();
            let mut matched = None;
            for (id, meta) in &attempts {
                if let Ok(punch) = decode_punch_packet(packet, meta) {
                    matched = Some(PunchPacketEvent {
                        attempt_id: id.clone(),
                        from: addr,
                        packet: punch,
                    });
                    break;
                }
            }
            if let Some(ev) = matched {
                let _ = self.events_tx.try_send(ev);
                continue;
            }
            return Ok((n, addr));
        }
    }

    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, dest).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_read_buffer(&self, n: usize) -> std::io::Result<()> {
        self.inner.set_read_buffer(n)
    }

    fn set_write_buffer(&self, n: usize) -> std::io::Result<()> {
        self.inner.set_write_buffer(n)
    }
}
