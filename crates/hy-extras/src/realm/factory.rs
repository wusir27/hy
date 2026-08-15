//! Realm options + `ConnFactory` / server listen wiring.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hy_core::error::Error;
use hy_core::io::{ConnFactory, DatagramIo, StdUdp};

use crate::realm::addr::{is_realm_url, parse_addr, Addr};
use crate::realm::client::{ConnectRequest, RealmClient};
use crate::realm::punch::new_punch_metadata;
use crate::realm::punch_conn::{discover_on_punch, PunchPacketConn};
use crate::realm::punch_engine::{punch, PunchConfig, DEFAULT_PUNCH_TIMEOUT};
use crate::realm::stun::{AddrFamily, STUNConfig, DEFAULT_STUN_TIMEOUT};

/// Defaults from the P5.E1 prompt (nextcloud / sip.us / cloudflare).
pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.nextcloud.com:3478",
    "stun.sip.us:3478",
    "stun.cloudflare.com:3478",
];

#[derive(Debug, Clone)]
pub struct RealmOptions {
    pub stun_servers: Vec<String>,
    pub stun_timeout: Duration,
    pub punch_timeout: Duration,
    pub insecure: bool,
    pub family: AddrFamily,
    /// When set, skip public STUN and use these reflexive addresses (tests).
    pub inject_local_addrs: Option<Vec<SocketAddr>>,
}

impl Default for RealmOptions {
    fn default() -> Self {
        Self {
            stun_servers: DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            stun_timeout: DEFAULT_STUN_TIMEOUT,
            punch_timeout: DEFAULT_PUNCH_TIMEOUT,
            insecure: false,
            family: AddrFamily::Any,
            inject_local_addrs: None,
        }
    }
}

/// Shared slot written by [`RealmFactory::open`] with the punched peer.
pub type PeerSlot = Arc<Mutex<Option<SocketAddr>>>;

/// Client-side realm `ConnFactory`: STUN → Connect → Punch → `PunchPacketConn`.
pub struct RealmFactory {
    pub addr: Addr,
    pub opts: RealmOptions,
    pub peer_slot: PeerSlot,
}

impl RealmFactory {
    pub fn new(addr: Addr, opts: RealmOptions) -> (Self, PeerSlot) {
        let peer_slot = Arc::new(Mutex::new(None));
        (
            Self {
                addr,
                opts,
                peer_slot: peer_slot.clone(),
            },
            peer_slot,
        )
    }
}

#[async_trait]
impl ConnFactory for RealmFactory {
    async fn open(&self, _server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let bind = if self.addr.local_port != 0 {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.addr.local_port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let udp = StdUdp::bind(bind).await.map_err(Error::Io)?;
        let local = udp.local_addr().map_err(Error::Io)?;
        let punch_conn = Arc::new(
            PunchPacketConn::new(Arc::new(udp), 0)
                .map_err(|e| Error::config("realm", e.to_string()))?,
        );

        let local_addrs = if let Some(inj) = &self.opts.inject_local_addrs {
            if inj.is_empty() {
                eprintln!("realm: injected address list is empty; refusing punch");
                return Err(Error::config(
                    "realm.stun",
                    "no public STUN addresses available",
                ));
            }
            inj.clone()
        } else {
            let stun_servers = stun_servers_for(&self.addr, &self.opts);
            match discover_on_punch(
                punch_conn.as_ref(),
                STUNConfig {
                    servers: stun_servers,
                    timeout: self.opts.stun_timeout,
                    family: self.opts.family,
                },
            )
            .await
            {
                Ok(addrs) if !addrs.is_empty() => addrs,
                Ok(_) => {
                    eprintln!(
                        "realm: STUN returned no addresses (local={local}); refusing empty punch"
                    );
                    return Err(Error::config("realm.stun", "no STUN responses received"));
                }
                Err(e) => {
                    eprintln!("realm: STUN discovery failed: {e}");
                    return Err(Error::config("realm.stun", e.to_string()));
                }
            }
        };

        let meta = new_punch_metadata();
        let client = RealmClient::from_addr(&self.addr, self.opts.insecure)
            .map_err(|e| Error::config("realm", e))?;
        let addr_strs: Vec<String> = local_addrs.iter().map(|a| a.to_string()).collect();
        let resp = client
            .connect(
                &self.addr.realm_id,
                &ConnectRequest {
                    addresses: addr_strs,
                    meta: meta.clone(),
                },
            )
            .await
            .map_err(|e| Error::config("realm.connect", e.to_string()))?;

        let peer_addrs = parse_addr_ports(&resp.addresses)
            .map_err(|e| Error::config("realm.connect.addresses", e))?;
        if peer_addrs.is_empty() {
            return Err(Error::config(
                "realm.connect.addresses",
                "empty peer address list",
            ));
        }

        let result = punch(
            punch_conn.as_ref(),
            &local_addrs,
            &peer_addrs,
            &resp.meta,
            PunchConfig {
                timeout: self.opts.punch_timeout,
                interval: Duration::ZERO,
                family: self.opts.family,
            },
        )
        .await
        .map_err(|e| Error::config("realm.punch", e.to_string()))?;

        *self.peer_slot.lock().unwrap() = Some(result.peer_addr);
        Ok(punch_conn)
    }
}

/// Bind + wrap `PunchPacketConn` and start server realm runtime (Register + Events).
pub async fn open_server_realm(
    addr: &Addr,
    opts: &RealmOptions,
) -> Result<Arc<dyn DatagramIo>, Error> {
    let bind = if addr.local_port != 0 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), addr.local_port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let udp = StdUdp::bind(bind).await.map_err(Error::Io)?;
    let punch_conn = Arc::new(
        PunchPacketConn::new(Arc::new(udp), 0)
            .map_err(|e| Error::config("realm", e.to_string()))?,
    );

    let local_addrs = if let Some(inj) = &opts.inject_local_addrs {
        if inj.is_empty() {
            eprintln!("realm: injected address list is empty; refusing register");
            return Err(Error::config(
                "realm.stun",
                "no public STUN addresses available",
            ));
        }
        inj.clone()
    } else {
        let stun_servers = stun_servers_for(addr, opts);
        match discover_on_punch(
            punch_conn.as_ref(),
            STUNConfig {
                servers: stun_servers,
                timeout: opts.stun_timeout,
                family: opts.family,
            },
        )
        .await
        {
            Ok(addrs) if !addrs.is_empty() => addrs,
            Ok(_) => {
                eprintln!("realm: STUN returned no addresses; refusing register");
                return Err(Error::config("realm.stun", "no STUN responses received"));
            }
            Err(e) => {
                eprintln!("realm: STUN discovery failed: {e}");
                return Err(Error::config("realm.stun", e.to_string()));
            }
        }
    };

    let client =
        RealmClient::from_addr(addr, opts.insecure).map_err(|e| Error::config("realm", e))?;
    let addr_strs: Vec<String> = local_addrs.iter().map(|a| a.to_string()).collect();
    let reg = client
        .register(&addr.realm_id, &addr_strs)
        .await
        .map_err(|e| Error::config("realm.register", e.to_string()))?;

    let bg_conn = punch_conn.clone();
    let bg_client = client.clone();
    let realm_id = addr.realm_id.clone();
    let session_id = reg.session_id.clone();
    let family = opts.family;
    let punch_timeout = opts.punch_timeout;
    let local_addrs_bg = local_addrs.clone();
    tokio::spawn(async move {
        server_events_loop(
            bg_client,
            bg_conn,
            realm_id,
            session_id,
            local_addrs_bg,
            family,
            punch_timeout,
        )
        .await;
    });

    Ok(punch_conn as Arc<dyn DatagramIo>)
}

async fn server_events_loop(
    client: RealmClient,
    conn: Arc<PunchPacketConn>,
    realm_id: String,
    session_id: String,
    local_addrs: Vec<SocketAddr>,
    family: AddrFamily,
    punch_timeout: Duration,
) {
    loop {
        match client.events_once(&realm_id, &session_id).await {
            Ok(mut stream) => {
                while let Ok(Some(ev)) = stream.next_event() {
                    let peer_addrs = match parse_addr_ports(&ev.addresses) {
                        Ok(a) => a,
                        Err(e) => {
                            eprintln!("realm: invalid punch addresses: {e}");
                            continue;
                        }
                    };
                    let attempt = ev.meta.nonce.clone();
                    if let Err(e) = conn.add_punch_attempt(&attempt, ev.meta.clone()) {
                        eprintln!("realm: add punch attempt: {e}");
                        continue;
                    }
                    let addrs: Vec<String> = local_addrs.iter().map(|a| a.to_string()).collect();
                    let _ = client
                        .connect_response(&realm_id, &session_id, &ev.meta.nonce, &addrs)
                        .await;
                    if let Some(rx) = conn.take_events() {
                        let _ = crate::realm::punch_engine::punch_via_events(
                            conn.as_ref(),
                            rx,
                            &attempt,
                            &local_addrs,
                            &peer_addrs,
                            &ev.meta,
                            PunchConfig {
                                timeout: punch_timeout,
                                interval: Duration::ZERO,
                                family,
                            },
                        )
                        .await;
                    }
                    conn.remove_punch_attempt(&attempt);
                }
            }
            Err(e) => {
                eprintln!("realm: events stream failed: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        let _ = client
            .heartbeat(
                &realm_id,
                &session_id,
                &crate::realm::client::HeartbeatRequest::default(),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn stun_servers_for(addr: &Addr, opts: &RealmOptions) -> Vec<String> {
    if let Some(s) = addr.params.get("stun") {
        if !s.is_empty() {
            return s.clone();
        }
    }
    opts.stun_servers.clone()
}

fn parse_addr_ports(list: &[String]) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for s in list {
        let a: SocketAddr = s.parse().map_err(|_| format!("bad address {s}"))?;
        out.push(a);
    }
    Ok(out)
}

/// Detect realm mode for `server` / `listen` strings.
pub fn try_parse_realm_url(s: &str, field: &'static str) -> Result<Option<Addr>, Error> {
    if !is_realm_url(s) {
        return Ok(None);
    }
    match parse_addr(s) {
        Ok(a) => Ok(Some(a)),
        Err(e) => Err(Error::config(field, e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stun_list() {
        let o = RealmOptions::default();
        assert!(o.stun_servers.iter().any(|s| s.contains("nextcloud")));
        assert!(o.stun_servers.iter().any(|s| s.contains("cloudflare")));
    }
}
