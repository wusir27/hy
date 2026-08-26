//! UDP port hopping. Aligns with hysteria `extras/transport/udphop`.

use async_trait::async_trait;
use hy_core::io::{ConnFactory, DatagramIo, StdUdp};
use hy_core::Error;
use rand::Rng;
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;

const PACKET_QUEUE_SIZE: usize = 1024;
const UDP_BUFFER_SIZE: usize = 2048;
pub const DEFAULT_HOP_INTERVAL: Duration = Duration::from_secs(30);

/// Min/max hop interval. Unit tests may use short durations; YAML fill enforces ≥5s.
#[derive(Debug, Clone, Copy)]
pub struct HopInterval {
    pub min: Duration,
    pub max: Duration,
}

impl HopInterval {
    pub fn fixed(d: Duration) -> Self {
        Self { min: d, max: d }
    }

    pub fn default_30s() -> Self {
        Self::fixed(DEFAULT_HOP_INTERVAL)
    }

    fn next(&self) -> Duration {
        if self.min == self.max {
            return self.min;
        }
        let lo = self.min.as_nanos();
        let hi = self.max.as_nanos();
        let n = rand::thread_rng().gen_range(lo..=hi);
        Duration::from_nanos(n as u64)
    }
}

/// Parse hop port-union (`18530,10000-10002`) into a flat list in **declaration order**.
/// Unlike sniff's sorted union, the first written port stays first (`ports[0]` = bind/main).
pub fn parse_port_union(s: &str) -> Option<Vec<u16>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return None;
        }
        if let Some((a, b)) = part.split_once('-') {
            let mut start: u16 = a.trim().parse().ok()?;
            let mut end: u16 = b.trim().parse().ok()?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let p: u16 = part.parse().ok()?;
            ports.push(p);
        }
    }
    if ports.is_empty() {
        None
    } else {
        Some(ports)
    }
}

struct RecvPacket {
    buf: Vec<u8>,
    n: usize,
    err: Option<std::io::Error>,
}

struct SockSlot {
    sock: Arc<dyn DatagramIo>,
    recv: JoinHandle<()>,
}

async fn hop_bind(
    inner: &Option<Arc<dyn ConnFactory>>,
    server_ip: IpAddr,
) -> std::io::Result<Arc<dyn DatagramIo>> {
    if let Some(f) = inner {
        f.open(SocketAddr::new(server_ip, 0))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))
    } else {
        Ok(Arc::new(
            StdUdp::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?,
        ))
    }
}

struct HopSocks {
    current: SockSlot,
    prev: Option<SockSlot>,
}

/// QUIC sees one `DatagramIo`; dest port rotates on interval.
pub struct UdpHop {
    server_ip: IpAddr,
    ports: Vec<u16>,
    interval: HopInterval,
    bind_inner: Option<Arc<dyn ConnFactory>>,
    addr_index: AtomicUsize,
    /// Logical addr returned from recv_from (first hop port), like official `Addr`.
    logical_addr: SocketAddr,
    cached_local: std::sync::Mutex<SocketAddr>,
    socks: Mutex<HopSocks>,
    recv_queue: Mutex<VecDeque<RecvPacket>>,
    recv_notify: Notify,
    closed: AtomicBool,
    close_notify: Notify,
    read_buf: std::sync::Mutex<usize>,
    write_buf: std::sync::Mutex<usize>,
}

impl UdpHop {
    pub async fn new(
        server_ip: IpAddr,
        ports: Vec<u16>,
        interval: HopInterval,
    ) -> std::io::Result<Arc<Self>> {
        Self::new_with_inner(server_ip, ports, interval, None).await
    }

    /// Bind hop sockets via `inner` (`MarkedUdpFactory`) when set.
    pub async fn new_with_inner(
        server_ip: IpAddr,
        ports: Vec<u16>,
        interval: HopInterval,
        inner: Option<Arc<dyn ConnFactory>>,
    ) -> std::io::Result<Arc<Self>> {
        if ports.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "udphop: empty port list",
            ));
        }
        let sock = hop_bind(&inner, server_ip).await?;
        let local = sock.local_addr()?;
        // First dest is the declared main port so hop syntax reaches a
        // server that only binds ports[0] (no DNAT required for the first interval).
        let addr_index = 0usize;
        let logical_addr = SocketAddr::new(server_ip, ports[0]);

        // Placeholder recv handle; replaced after `hop` Arc exists.
        let dummy = tokio::spawn(async {});
        let hop = Arc::new(Self {
            server_ip,
            ports,
            interval,
            bind_inner: inner,
            addr_index: AtomicUsize::new(addr_index),
            logical_addr,
            cached_local: std::sync::Mutex::new(local),
            socks: Mutex::new(HopSocks {
                current: SockSlot {
                    sock: Arc::clone(&sock),
                    recv: dummy,
                },
                prev: None,
            }),
            recv_queue: Mutex::new(VecDeque::new()),
            recv_notify: Notify::new(),
            closed: AtomicBool::new(false),
            close_notify: Notify::new(),
            read_buf: std::sync::Mutex::new(0),
            write_buf: std::sync::Mutex::new(0),
        });
        let recv = hop.spawn_recv(Arc::clone(&sock));
        {
            let mut socks = hop.socks.lock().await;
            socks.current.recv = recv;
        }
        hop.clone().spawn_hop_loop();
        Ok(hop)
    }

    /// Current destination used by `send_to` (test helper).
    pub fn current_dest(&self) -> SocketAddr {
        let idx = self.addr_index.load(Ordering::SeqCst);
        SocketAddr::new(self.server_ip, self.ports[idx])
    }

    fn spawn_recv(self: &Arc<Self>, sock: Arc<dyn DatagramIo>) -> JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = vec![0u8; UDP_BUFFER_SIZE];
            loop {
                if this.closed.load(Ordering::SeqCst) {
                    return;
                }
                match sock.recv_from(&mut buf).await {
                    Ok((n, _addr)) => {
                        let mut q = this.recv_queue.lock().await;
                        if q.len() < PACKET_QUEUE_SIZE {
                            q.push_back(RecvPacket {
                                buf: buf[..n].to_vec(),
                                n,
                                err: None,
                            });
                            this.recv_notify.notify_one();
                        }
                    }
                    Err(_e) => return,
                }
            }
        })
    }

    fn spawn_hop_loop(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                let wait = self.interval.next();
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {}
                    _ = self.close_notify.notified() => return,
                }
                if self.closed.load(Ordering::SeqCst) {
                    return;
                }
                let _ = self.hop_once().await;
            }
        });
    }

    async fn hop_once(self: &Arc<Self>) -> std::io::Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Ok(());
        }
        let new_sock = match hop_bind(&self.bind_inner, self.server_ip).await {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        if let Ok(la) = new_sock.local_addr() {
            *self.cached_local.lock().unwrap() = la;
        }
        {
            let rb = *self.read_buf.lock().unwrap();
            let wb = *self.write_buf.lock().unwrap();
            if rb > 0 {
                let _ = new_sock.set_read_buffer(rb);
            }
            if wb > 0 {
                let _ = new_sock.set_write_buffer(wb);
            }
        }
        let recv = self.spawn_recv(Arc::clone(&new_sock));
        {
            let mut socks = self.socks.lock().await;
            // Close prev (official); keep current receiving until next hop.
            if let Some(prev) = socks.prev.take() {
                prev.recv.abort();
                drop(prev.sock);
            }
            let old_current = std::mem::replace(
                &mut socks.current,
                SockSlot {
                    sock: Arc::clone(&new_sock),
                    recv,
                },
            );
            socks.prev = Some(old_current);
        }
        let new_idx = rand::thread_rng().gen_range(0..self.ports.len());
        self.addr_index.store(new_idx, Ordering::SeqCst);
        Ok(())
    }

    fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.close_notify.notify_waiters();
        }
    }
}

impl Drop for UdpHop {
    fn drop(&mut self) {
        self.close();
        if let Ok(mut socks) = self.socks.try_lock() {
            socks.current.recv.abort();
            if let Some(prev) = socks.prev.take() {
                prev.recv.abort();
            }
        }
    }
}

#[async_trait]
impl DatagramIo for UdpHop {
    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "udphop closed",
                ));
            }
            {
                let mut q = self.recv_queue.lock().await;
                if let Some(p) = q.pop_front() {
                    if let Some(e) = p.err {
                        return Err(e);
                    }
                    let n = std::cmp::min(buf.len(), p.n);
                    buf[..n].copy_from_slice(&p.buf[..n]);
                    return Ok((n, self.logical_addr));
                }
            }
            tokio::select! {
                _ = self.recv_notify.notified() => {}
                _ = self.close_notify.notified() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "udphop closed",
                    ));
                }
            }
        }
    }

    async fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> std::io::Result<usize> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "udphop closed",
            ));
        }
        let dest = self.current_dest();
        let socks = self.socks.lock().await;
        socks.current.sock.send_to(buf, dest).await
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(*self.cached_local.lock().unwrap())
    }

    fn set_read_buffer(&self, n: usize) -> std::io::Result<()> {
        *self.read_buf.lock().unwrap() = n;
        Ok(())
    }

    fn set_write_buffer(&self, n: usize) -> std::io::Result<()> {
        *self.write_buf.lock().unwrap() = n;
        Ok(())
    }
}

/// `ConnFactory` that builds a fresh `UdpHop` per reconnect.
///
/// Compose with salamander like official: hop first, then wrap via
/// [`UdpHopFactory::with_salamander`]. `inner` binds hop sockets (marked UDP).
pub struct UdpHopFactory {
    pub ports: Vec<u16>,
    pub interval: HopInterval,
    /// Innermost bind factory (`MarkedUdpFactory` when client-route is on).
    pub inner: Option<Arc<dyn ConnFactory>>,
    salamander_psk: Option<Vec<u8>>,
}

impl UdpHopFactory {
    pub fn new(ports: Vec<u16>, interval: HopInterval) -> Self {
        Self {
            ports,
            interval,
            inner: None,
            salamander_psk: None,
        }
    }

    pub fn with_inner(mut self, inner: Arc<dyn ConnFactory>) -> Self {
        self.inner = Some(inner);
        self
    }

    pub fn with_salamander(mut self, psk: Vec<u8>) -> Self {
        self.salamander_psk = Some(psk);
        self
    }
}

#[async_trait]
impl ConnFactory for UdpHopFactory {
    async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let hop = UdpHop::new_with_inner(
            server.ip(),
            self.ports.clone(),
            self.interval,
            self.inner.clone(),
        )
        .await
        .map_err(Error::Io)?;
        let io: Arc<dyn DatagramIo> = hop;
        if let Some(psk) = &self.salamander_psk {
            let wrapped = crate::obfs::ObfsSalamander::new(io, psk)?;
            return Ok(Arc::new(wrapped));
        }
        Ok(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_union_flat() {
        assert_eq!(
            parse_port_union("443,10000-10002").unwrap(),
            vec![443, 10000, 10001, 10002]
        );
    }

    #[test]
    fn parse_port_union_preserves_declaration_order() {
        let ports = parse_port_union("18530,10000-10002").unwrap();
        assert_eq!(ports[0], 18530);
        assert_eq!(ports, vec![18530, 10000, 10001, 10002]);
    }

    #[tokio::test]
    async fn dest_changes_after_interval() {
        let ports = vec![41000u16, 41001];
        let hop = UdpHop::new(
            "127.0.0.1".parse().unwrap(),
            ports.clone(),
            HopInterval::fixed(Duration::from_millis(50)),
        )
        .await
        .unwrap();
        let first = hop.current_dest().port();
        assert_eq!(first, ports[0], "initial dest must be the main/first port");
        let mut changed = false;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            let now = hop.current_dest().port();
            if now != first {
                changed = true;
                break;
            }
        }
        assert!(changed, "dest port should change after hop interval");
        drop(hop);
    }

    #[tokio::test]
    async fn hop_factory_inner_bind_is_used() {
        use hy_core::io::StdUdpFactory;
        use std::sync::atomic::AtomicUsize;

        struct CountingFactory {
            inner: Arc<dyn ConnFactory>,
            opens: AtomicUsize,
        }
        #[async_trait]
        impl ConnFactory for CountingFactory {
            async fn open(&self, server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                self.inner.open(server).await
            }
        }

        let counting = Arc::new(CountingFactory {
            inner: Arc::new(StdUdpFactory),
            opens: AtomicUsize::new(0),
        });
        let fac = UdpHopFactory::new(vec![443], HopInterval::fixed(Duration::from_secs(60)))
            .with_inner(counting.clone());
        let _io = fac
            .open("127.0.0.1:1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            counting.opens.load(Ordering::SeqCst) >= 1,
            "hop must bind via inner factory"
        );
    }
}
