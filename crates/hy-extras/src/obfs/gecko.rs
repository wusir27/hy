//! Gecko shape obfuscation on top of Salamander.
//!
//! QUIC long-header packets are fragmented; short-header packets pass through.
//! Layer: QUIC → Gecko → Salamander → (UdpHop?) → UDP.

use crate::obfs::gecko_frame::{
    decode_frame, encode_frame, FrameHeader, GECKO_HEADER_SIZE, GECKO_MAX_FRAGMENT_CHUNKS,
    GECKO_MIN_FRAGMENT_CHUNKS,
};
use crate::obfs::salamander::{ObfsSalamander, SALT_LEN};
use crate::udphop::{HopInterval, UdpHop};
use async_trait::async_trait;
use hy_core::io::{ConnFactory, DatagramIo, StdUdpFactory};
use hy_core::Error;
use rand::Rng;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const REASSEMBLY_TTL: Duration = Duration::from_secs(8);
const MAX_REASSEMBLY: usize = 4096;
const MAX_PER_SOURCE: usize = 8;
const DEFAULT_MIN_PACKET: usize = 512;
const DEFAULT_MAX_PACKET: usize = 1200;
const GECKO_BUFFER_SIZE: usize = 2048;

struct ReassemblyKey {
    addr: String,
    msg_id: u8,
}

impl PartialEq for ReassemblyKey {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.msg_id == other.msg_id
    }
}
impl Eq for ReassemblyKey {}
impl std::hash::Hash for ReassemblyKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.msg_id.hash(state);
    }
}

struct ReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

struct ReassemblyState {
    map: HashMap<ReassemblyKey, ReassemblyEntry>,
    per_source: HashMap<String, usize>,
}

impl ReassemblyState {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            per_source: HashMap::new(),
        }
    }

    fn gc_expired(&mut self, now: Instant) {
        let expired: Vec<ReassemblyKey> = self
            .map
            .iter()
            .filter(|(_, e)| now > e.deadline)
            .map(|(k, _)| ReassemblyKey {
                addr: k.addr.clone(),
                msg_id: k.msg_id,
            })
            .collect();
        for k in expired {
            self.drop_entry(&k);
        }
    }

    fn drop_entry(&mut self, k: &ReassemblyKey) {
        if self.map.remove(k).is_none() {
            return;
        }
        if let Some(c) = self.per_source.get_mut(&k.addr) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_source.remove(&k.addr);
            }
        }
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .map
            .iter()
            .min_by_key(|(_, e)| e.deadline)
            .map(|(k, _)| ReassemblyKey {
                addr: k.addr.clone(),
                msg_id: k.msg_id,
            });
        if let Some(k) = oldest {
            self.drop_entry(&k);
        }
    }

    /// Returns reassembled plaintext when complete.
    fn accept_chunk(
        &mut self,
        addr: SocketAddr,
        h: FrameHeader,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.gc_expired(now);

        let key = ReassemblyKey {
            addr: addr.to_string(),
            msg_id: h.msg_id,
        };

        if !self.map.contains_key(&key) {
            let count = self.per_source.get(&key.addr).copied().unwrap_or(0);
            if count >= MAX_PER_SOURCE {
                return None;
            }
            if self.map.len() >= MAX_REASSEMBLY {
                self.evict_oldest();
            }
            self.map.insert(
                ReassemblyKey {
                    addr: key.addr.clone(),
                    msg_id: key.msg_id,
                },
                ReassemblyEntry {
                    chunks: vec![None; h.total_chunks as usize],
                    received: 0,
                    total: h.total_chunks,
                    deadline: now + REASSEMBLY_TTL,
                },
            );
            *self.per_source.entry(key.addr.clone()).or_insert(0) += 1;
        } else if self.map.get(&key).map(|e| e.total) != Some(h.total_chunks) {
            return None;
        }

        let e = self.map.get_mut(&key)?;
        let idx = h.chunk_idx as usize;
        if idx >= e.chunks.len() || e.chunks[idx].is_some() {
            return None;
        }
        e.chunks[idx] = Some(payload.to_vec());
        e.received += 1;
        if e.received < e.total as usize {
            return None;
        }

        let mut out = Vec::new();
        for c in &e.chunks {
            out.extend_from_slice(c.as_ref().unwrap());
        }
        self.drop_entry(&key);
        Some(out)
    }
}

/// DatagramIo decorator. `inner` must be [`ObfsSalamander`] (or equivalent).
/// Prefer [`ObfsGecko::wrap`] which builds Salamander then Gecko.
pub struct ObfsGecko {
    inner: Arc<dyn DatagramIo>,
    min_pkt: usize,
    max_pkt: usize,
    msg_id: AtomicU32,
    reassembly: Mutex<ReassemblyState>,
}

impl ObfsGecko {
    /// Validate sizes and wrap `inner` (already Salamander).
    pub fn new(inner: Arc<dyn DatagramIo>, min_pkt: usize, max_pkt: usize) -> Result<Self, Error> {
        let min_pkt = if min_pkt == 0 {
            DEFAULT_MIN_PACKET
        } else {
            min_pkt
        };
        let max_pkt = if max_pkt == 0 {
            DEFAULT_MAX_PACKET
        } else {
            max_pkt
        };
        if min_pkt == 0 || min_pkt > max_pkt || max_pkt > GECKO_BUFFER_SIZE {
            return Err(Error::config(
                "obfs.gecko",
                "invalid min/max packet size",
            ));
        }
        Ok(Self {
            inner,
            min_pkt,
            max_pkt,
            msg_id: AtomicU32::new(0),
            reassembly: Mutex::new(ReassemblyState::new()),
        })
    }

    /// Official `WrapPacketConnGecko`: Salamander first, then Gecko on top.
    pub fn wrap(
        inner: Arc<dyn DatagramIo>,
        password: &[u8],
        min_pkt: usize,
        max_pkt: usize,
    ) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::config("obfs.gecko", "password is required"));
        }
        let sal = ObfsSalamander::new(inner, password).map_err(|e| match e {
            Error::Config { reason, .. } => Error::config("obfs.gecko", reason),
            other => other,
        })?;
        Self::new(Arc::new(sal), min_pkt, max_pkt)
    }

    fn random_pad_len(&self, chunk_len: usize) -> u16 {
        let base = SALT_LEN + GECKO_HEADER_SIZE + chunk_len;
        let lo = self.min_pkt.max(base);
        if lo > self.max_pkt {
            return 0;
        }
        let span = self.max_pkt - lo + 1;
        let extra = rand::thread_rng().gen_range(0..span);
        (lo - base + extra) as u16
    }

    fn random_fragment_chunks() -> usize {
        let lo = GECKO_MIN_FRAGMENT_CHUNKS as usize;
        let hi = GECKO_MAX_FRAGMENT_CHUNKS as usize;
        rand::thread_rng().gen_range(lo..=hi)
    }

    async fn write_fragmented(&self, p: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let chunks = Self::random_fragment_chunks();
        let chunk_size = p.len() / chunks;
        let msg_id = self.msg_id.fetch_add(1, Ordering::Relaxed) as u8;
        for i in 0..chunks {
            let start = i * chunk_size;
            let end = if i < chunks - 1 {
                start + chunk_size
            } else {
                p.len()
            };
            let chunk = &p[start..end];
            let pad_len = self.random_pad_len(chunk.len());
            let needed = GECKO_HEADER_SIZE + pad_len as usize + chunk.len();
            let mut buf = vec![0u8; needed];
            let h = FrameHeader {
                pad_len,
                msg_id,
                chunk_idx: i as u8,
                total_chunks: chunks as u8,
            };
            let n = encode_frame(h, chunk, &mut buf).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            })?;
            self.inner.send_to(&buf[..n], dest).await?;
        }
        Ok(p.len())
    }
}

#[async_trait]
impl DatagramIo for ObfsGecko {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut wire = [0u8; 65535];
        loop {
            let (n, addr) = self.inner.recv_from(&mut wire).await?;
            if n == 0 {
                continue;
            }
            // Top bit clear → short-header / non-gecko; pass through.
            if wire[0] & 0x80 == 0 {
                let copy_n = n.min(buf.len());
                buf[..copy_n].copy_from_slice(&wire[..copy_n]);
                return Ok((copy_n, addr));
            }
            let (h, payload) = match decode_frame(&wire[..n]) {
                Ok(v) => v,
                Err(_) => continue, // malformed: drop silently
            };
            let out = {
                let mut st = self.reassembly.lock().unwrap();
                st.accept_chunk(addr, h, payload)
            };
            if let Some(out) = out {
                let copy_n = out.len().min(buf.len());
                buf[..copy_n].copy_from_slice(&out[..copy_n]);
                return Ok((copy_n, addr));
            }
        }
    }

    async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if buf[0] & 0x80 != 0 {
            return self.write_fragmented(buf, dest).await;
        }
        self.inner.send_to(buf, dest).await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn set_read_buffer(&self, n: usize) -> io::Result<()> {
        self.inner.set_read_buffer(n)
    }

    fn set_write_buffer(&self, n: usize) -> io::Result<()> {
        self.inner.set_write_buffer(n)
    }
}

/// `ConnFactory`: hop-or-StdUdp → Salamander → Gecko.
pub struct GeckoFactory {
    pub password: Vec<u8>,
    pub min_packet_size: usize,
    pub max_packet_size: usize,
    pub hop_ports: Option<Vec<u16>>,
    pub hop_interval: HopInterval,
}

impl GeckoFactory {
    pub fn new(password: Vec<u8>, min_packet_size: usize, max_packet_size: usize) -> Self {
        Self {
            password,
            min_packet_size,
            max_packet_size,
            hop_ports: None,
            hop_interval: HopInterval::default_30s(),
        }
    }

    pub fn with_hop(mut self, ports: Vec<u16>, interval: HopInterval) -> Self {
        self.hop_ports = Some(ports);
        self.hop_interval = interval;
        self
    }
}

#[async_trait]
impl ConnFactory for GeckoFactory {
    async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let inner: Arc<dyn DatagramIo> = if let Some(ports) = &self.hop_ports {
            UdpHop::new(server.ip(), ports.clone(), self.hop_interval)
                .await
                .map_err(Error::Io)?
        } else {
            StdUdpFactory.open(server).await?
        };
        let gecko = ObfsGecko::wrap(
            inner,
            &self.password,
            self.min_packet_size,
            self.max_packet_size,
        )?;
        Ok(Arc::new(gecko))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hy_core::io::StdUdp;
    use std::sync::atomic::AtomicUsize;

    struct CountingIo {
        inner: Arc<dyn DatagramIo>,
        sends: AtomicUsize,
    }

    #[async_trait]
    impl DatagramIo for CountingIo {
        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.inner.recv_from(buf).await
        }
        async fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.inner.send_to(buf, dest).await
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }
        fn set_read_buffer(&self, n: usize) -> io::Result<()> {
            self.inner.set_read_buffer(n)
        }
        fn set_write_buffer(&self, n: usize) -> io::Result<()> {
            self.inner.set_write_buffer(n)
        }
    }

    #[tokio::test]
    async fn long_header_roundtrip() {
        let a = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dest = b.local_addr().unwrap();
        let psk = b"test";
        let send = ObfsGecko::wrap(Arc::new(a), psk, 0, 0).unwrap();
        let recv = ObfsGecko::wrap(Arc::new(b), psk, 0, 0).unwrap();

        let mut msg = vec![0u8; 400];
        rand::thread_rng().fill(&mut msg[..]);
        msg[0] = 0xc0; // long header

        let n = send.send_to(&msg, dest).await.unwrap();
        assert_eq!(n, msg.len());
        let mut buf = [0u8; 2048];
        let (m, _) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..m], msg.as_slice());
    }

    #[tokio::test]
    async fn short_header_not_fragmented() {
        let a = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let b = StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let dest = b.local_addr().unwrap();
        let counter = Arc::new(CountingIo {
            inner: Arc::new(a),
            sends: AtomicUsize::new(0),
        });
        let sends = Arc::clone(&counter);
        let psk = b"test";
        let send = ObfsGecko::wrap(counter, psk, 0, 0).unwrap();
        let recv = ObfsGecko::wrap(Arc::new(b), psk, 0, 0).unwrap();

        let mut msg = vec![0u8; 400];
        rand::thread_rng().fill(&mut msg[..]);
        msg[0] = 0x40; // short header

        let n = send.send_to(&msg, dest).await.unwrap();
        assert_eq!(n, msg.len());
        assert_eq!(sends.sends.load(Ordering::SeqCst), 1);

        let mut buf = [0u8; 2048];
        let (m, _) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..m], msg.as_slice());
    }

    #[test]
    fn empty_password_rejected() {
        let err = match ObfsGecko::wrap(Arc::new(DummyIo), b"", 0, 0) {
            Ok(_) => panic!("expected err"),
            Err(e) => e,
        };
        match err {
            Error::Config { field, reason } => {
                assert_eq!(field, "obfs.gecko");
                assert!(reason.contains("password"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn invalid_min_max() {
        let io = Arc::new(DummyIo);
        let sal = Arc::new(ObfsSalamander::new(io, b"test").unwrap());
        let err = match ObfsGecko::new(sal, 100, 50) {
            Ok(_) => panic!("expected err"),
            Err(e) => e,
        };
        match err {
            Error::Config { field, reason } => {
                assert_eq!(field, "obfs.gecko");
                assert_eq!(reason, "invalid min/max packet size");
            }
            other => panic!("{other:?}"),
        }
    }

    struct DummyIo;
    #[async_trait]
    impl DatagramIo for DummyIo {
        async fn recv_from(&self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            Err(io::Error::other("dummy"))
        }
        async fn send_to(&self, _: &[u8], _: SocketAddr) -> io::Result<usize> {
            Err(io::Error::other("dummy"))
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Err(io::Error::other("dummy"))
        }
        fn set_read_buffer(&self, _: usize) -> io::Result<()> {
            Ok(())
        }
        fn set_write_buffer(&self, _: usize) -> io::Result<()> {
            Ok(())
        }
    }
}
