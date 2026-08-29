//! Official camelCase YAML. Parse is loose; fill rejects v1-unimplemented keys.

use crate::acme::{self, AcmeYaml};
use crate::bps::parse_bps;
use crate::listen::{parse_listen, parse_server};
use crate::mimic::{fill_mimic, MimicHandle, MimicSpec, MimicYaml, Role};
use hy_core::client::{self as core_client};
use hy_core::congestion::{normalize_bbr_profile, normalize_type, CongestionType};
use hy_core::io::{DatagramIo, StdUdp, StdUdpFactory};
use hy_core::server::{self as core_server};
use hy_core::Error;
use hy_extras::auth::{CommandAuth, HttpAuth, Password, UserPass};
use hy_extras::obfs::{GeckoFactory, ObfsGecko, ObfsSalamander};
use hy_extras::outbounds::{
    AclEngine, Adapter, Direct, DirectMode, DohResolver, HttpOutbound, PluggableOutbound,
    Socks5Outbound, SpeedtestHandler, StandardResolver, SystemResolver,
};
use hy_extras::acl::CompiledRuleSet;
use crate::geoloader::{geo_interval_from_yaml, AppGeoLoader, DefaultHttp};
use hy_extras::masq::{FileMasq, MasqTcpServer, NotFoundMasq, ProxyMasq, StringMasq};
use hy_extras::sniff::{parse_port_union, Sniffer};
use hy_extras::trafficlogger::TrafficStats;
use hy_extras::realm::{
    open_server_realm, try_parse_realm_url, AddrFamily, RealmFactory, RealmOptions,
};
use hy_extras::udphop::{HopInterval, UdpHopFactory};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClientYaml {
    pub server: Option<String>,
    pub auth: Option<serde_yaml::Value>,
    pub tls: Option<ClientTlsYaml>,
    pub quic: Option<QuicYaml>,
    pub bandwidth: Option<BandwidthYaml>,
    pub congestion: Option<CongestionYaml>,
    pub fast_open: Option<bool>,
    pub lazy: Option<bool>,
    pub obfs: Option<ObfsYaml>,
    pub socks5: Option<Socks5Yaml>,
    pub http: Option<HttpYaml>,
    pub tcp_forwarding: Option<Vec<ForwardYaml>>,
    pub udp_forwarding: Option<Vec<ForwardYaml>>,
    pub transport: Option<serde_yaml::Value>,
    pub realm: Option<RealmYaml>,
    pub mimic: Option<MimicYaml>,
    pub tun: Option<TunYaml>,
    #[serde(rename = "tcpTProxy")]
    pub tcp_tproxy: Option<TcpTProxyYaml>,
    #[serde(rename = "udpTProxy")]
    pub udp_tproxy: Option<UdpTProxyYaml>,
    pub tcp_redirect: Option<TcpRedirectYaml>,
    /// Optional client routing (`route.file`). Command line `--route` wins.
    pub route: Option<ClientRouteYaml>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ClientRouteYaml {
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RealmYaml {
    pub stun_servers: Option<Vec<String>>,
    pub stun_timeout: Option<String>,
    pub punch_timeout: Option<String>,
    pub insecure: Option<bool>,
    pub ip_mode: Option<String>,
    /// Accepted for YAML compatibility; UPnP/NAT-PMP apply is a no-op this gate.
    pub port_mapping: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TunYaml {
    pub name: Option<String>,
    pub mtu: Option<u32>,
    pub timeout: Option<String>,
    pub address: Option<TunAddressYaml>,
    pub route: Option<TunRouteYaml>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TunAddressYaml {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TunRouteYaml {
    pub strict: Option<bool>,
    pub ipv4: Option<Vec<String>>,
    pub ipv6: Option<Vec<String>>,
    pub ipv4_exclude: Option<Vec<String>>,
    pub ipv6_exclude: Option<Vec<String>>,
}

/// Filled TUN inbound config (device open happens at `run`).
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u32,
    pub timeout: Duration,
    pub ipv4: String,
    pub ipv6: Option<String>,
    pub route: Option<TunRouteConfig>,
    /// When client-route is on, Linux actually excludes `ipv4Exclude` (subtract
    /// from default). Off: keep D3 ignore.
    pub apply_exclude: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TunRouteConfig {
    pub strict: bool,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub ipv4_exclude: Vec<String>,
    pub ipv6_exclude: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TcpTProxyYaml {
    pub listen: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UdpTProxyYaml {
    pub listen: Option<String>,
    pub timeout: Option<String>,
}

/// Filled `udpTProxy` with resolved idle timeout (default 60s).
#[derive(Debug, Clone)]
pub struct UdpTProxyConfig {
    pub listen: String,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TcpRedirectYaml {
    pub listen: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClientTlsYaml {
    pub sni: Option<String>,
    pub insecure: Option<bool>,
    #[serde(rename = "pinSHA256")]
    pub pin_sha256: Option<String>,
    pub ca: Option<String>,
    pub client_certificate: Option<String>,
    pub client_key: Option<String>,
    pub ech: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerYaml {
    pub listen: Option<String>,
    pub tls: Option<ServerTlsYaml>,
    pub auth: Option<ServerAuthYaml>,
    pub obfs: Option<ObfsYaml>,
    pub bandwidth: Option<BandwidthYaml>,
    pub ignore_client_bandwidth: Option<bool>,
    pub congestion: Option<CongestionYaml>,
    #[serde(rename = "disableUDP")]
    pub disable_udp: Option<bool>,
    pub udp_idle_timeout: Option<String>,
    pub resolver: Option<ResolverYaml>,
    pub acl: Option<AclYaml>,
    pub outbounds: Option<Vec<OutboundYaml>>,
    pub speed_test: Option<bool>,
    pub traffic_stats: Option<TrafficStatsYaml>,
    pub masquerade: Option<MasqYaml>,
    pub acme: Option<AcmeYaml>,
    pub ech: Option<serde_yaml::Value>,
    pub sniff: Option<SniffYaml>,
    pub realm: Option<RealmYaml>,
    pub mimic: Option<MimicYaml>,
    pub quic: Option<QuicYaml>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerTlsYaml {
    pub cert: Option<String>,
    pub key: Option<String>,
    pub sni_guard: Option<String>,
    #[serde(rename = "clientCA")]
    pub client_ca: Option<String>,
    pub ech: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ServerAuthYaml {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub password: Option<String>,
    pub userpass: Option<HashMap<String, String>>,
    pub http: Option<HttpAuthYaml>,
    pub command: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct HttpAuthYaml {
    pub url: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ObfsYaml {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub salamander: Option<SalamanderYaml>,
    pub gecko: Option<GeckoYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct SalamanderYaml {
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GeckoYaml {
    pub password: Option<String>,
    pub min_packet_size: Option<usize>,
    pub max_packet_size: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BandwidthYaml {
    pub up: Option<String>,
    pub down: Option<String>,
    pub disable_loss_compensation: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CongestionYaml {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub bbr_profile: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QuicYaml {
    pub init_stream_receive_window: Option<u64>,
    pub max_stream_receive_window: Option<u64>,
    pub init_conn_receive_window: Option<u64>,
    pub max_conn_receive_window: Option<u64>,
    pub max_idle_timeout: Option<String>,
    pub keep_alive_period: Option<String>,
    pub disable_path_mtu_discovery: Option<bool>,
    /// Official camelCase `disableChromeParrot`. Client-only; default false = parrot ON.
    pub disable_chrome_parrot: Option<bool>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Socks5Yaml {
    pub listen: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(rename = "disableUDP")]
    pub disable_udp: Option<bool>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct HttpYaml {
    pub listen: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub realm: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ForwardYaml {
    pub listen: Option<String>,
    pub remote: Option<String>,
    pub timeout: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResolverYaml {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub tcp: Option<ResolverEndpointYaml>,
    pub udp: Option<ResolverEndpointYaml>,
    pub tls: Option<ResolverTlsYaml>,
    pub https: Option<ResolverTlsYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResolverEndpointYaml {
    pub addr: Option<String>,
    pub timeout: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ResolverTlsYaml {
    pub addr: Option<String>,
    pub timeout: Option<String>,
    pub sni: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AclYaml {
    pub file: Option<String>,
    #[serde(default, deserialize_with = "de_acl_inline")]
    pub inline: Option<String>,
    pub geoip: Option<String>,
    pub geosite: Option<String>,
    #[serde(rename = "geoUpdateInterval")]
    pub geo_update_interval: Option<String>,
}

fn de_acl_inline<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    let v = Option::<serde_yaml::Value>::deserialize(d)?;
    match v {
        None | Some(serde_yaml::Value::Null) => Ok(None),
        Some(serde_yaml::Value::String(s)) => Ok(Some(s)),
        Some(serde_yaml::Value::Sequence(seq)) => {
            let mut lines = Vec::new();
            for x in seq {
                match x {
                    serde_yaml::Value::String(s) => lines.push(s),
                    other => {
                        return Err(serde::de::Error::custom(format!(
                            "acl.inline entry must be a string, got {other:?}"
                        )))
                    }
                }
            }
            Ok(Some(lines.join("
")))
        }
        Some(_) => Err(serde::de::Error::custom("acl.inline must be a string or sequence")),
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct OutboundYaml {
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub direct: Option<DirectYaml>,
    pub socks5: Option<OutboundSocks5Yaml>,
    pub http: Option<OutboundHttpYaml>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutboundSocks5Yaml {
    pub addr: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OutboundHttpYaml {
    pub url: Option<String>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DirectYaml {
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MasqYaml {
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub string: Option<MasqStringYaml>,
    pub file: Option<MasqFileYaml>,
    pub proxy: Option<MasqProxyYaml>,
    #[serde(rename = "listenHTTP")]
    pub listen_http: Option<String>,
    #[serde(rename = "listenHTTPS")]
    pub listen_https: Option<String>,
    #[serde(rename = "forceHTTPS")]
    pub force_https: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MasqStringYaml {
    pub status: Option<u16>,
    #[serde(rename = "statusCode")]
    pub status_code: Option<u16>,
    pub content: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MasqFileYaml {
    pub dir: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct MasqProxyYaml {
    pub url: Option<String>,
    #[serde(rename = "rewriteHost")]
    pub rewrite_host: Option<bool>,
    #[serde(rename = "xForwarded")]
    pub x_forwarded: Option<bool>,
    pub insecure: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct TrafficStatsYaml {
    pub listen: Option<String>,
    pub secret: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SniffYaml {
    pub enable: Option<bool>,
    pub timeout: Option<String>,
    pub rewrite_domain: Option<bool>,
    pub tcp_ports: Option<String>,
    pub udp_ports: Option<String>,
}

pub fn parse_client_yaml(s: &str) -> Result<ClientYaml, Error> {
    serde_yaml::from_str(s).map_err(|e| Error::config("YAML", e.to_string()))
}

pub fn parse_server_yaml(s: &str) -> Result<ServerYaml, Error> {
    serde_yaml::from_str(s).map_err(|e| Error::config("YAML", e.to_string()))
}

fn parse_dur(s: &str, field: &'static str) -> Result<Duration, Error> {
    let t = s.trim().to_ascii_lowercase();
    if let Some(n) = t.strip_suffix("ms") {
        let v: u64 = n.trim().parse().map_err(|_| Error::config(field, format!("bad duration {s}")))?;
        return Ok(Duration::from_millis(v));
    }
    if let Some(n) = t.strip_suffix('s') {
        let v: u64 = n.trim().parse().map_err(|_| Error::config(field, format!("bad duration {s}")))?;
        return Ok(Duration::from_secs(v));
    }
    Err(Error::config(field, format!("bad duration {s}")))
}

fn auth_string(v: &serde_yaml::Value) -> Result<String, Error> {
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    if let Some(m) = v.as_mapping() {
        if let Some(p) = m.get(serde_yaml::Value::from("password")).and_then(|x| x.as_str()) {
            return Ok(p.to_string());
        }
    }
    Err(Error::config("auth", "expected string or {password}"))
}

pub struct ClientApp {
    pub core: core_client::Config,
    pub socks5: Option<Socks5Yaml>,
    pub http: Option<HttpYaml>,
    pub tcp_fwd: Vec<ForwardYaml>,
    pub udp_fwd: Vec<ForwardYaml>,
    pub tcp_tproxy: Option<TcpTProxyYaml>,
    pub udp_tproxy: Option<UdpTProxyConfig>,
    pub tcp_redirect: Option<TcpRedirectYaml>,
    pub tun: Option<TunConfig>,
    pub lazy: bool,
    /// Present only when `mimic.enabled: true` passed fill. Spawn via [`ClientApp::start`].
    pub mimic: Option<MimicSpec>,
    /// Plain salamander (no hop/gecko/realm). Used to wrap a marked StdUdp inner.
    #[allow(dead_code)] // read from main.rs when `client-route` is on
    pub salamander_only_psk: Option<Vec<u8>>,
    #[allow(dead_code)]
    pub hop_mark: Option<(Vec<u16>, HopInterval, Option<Vec<u8>>)>,
    #[allow(dead_code)]
    pub gecko_mark: Option<(Vec<u8>, usize, usize, Option<Vec<u16>>, HopInterval)>,
    #[allow(dead_code)]
    pub realm_mark: Option<(hy_extras::realm::Addr, RealmOptions)>,
}

impl ClientApp {
    /// Spawn mimic (if enabled) before the first QUIC packet / `connect`.
    pub fn start(&self) -> Result<Option<MimicHandle>, Error> {
        crate::mimic::start(self.mimic.as_ref())
    }
}

pub fn fill_client(y: &ClientYaml) -> Result<ClientApp, Error> {
    let realm_opts = fill_realm_opts(y.realm.as_ref())?;
    let tun = fill_tun(y.tun.as_ref())?;
    let tcp_tproxy = fill_tcp_tproxy(y.tcp_tproxy.as_ref())?;
    let udp_tproxy = fill_udp_tproxy(y.udp_tproxy.as_ref())?;
    if let Some(r) = &y.tcp_redirect {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = r;
            return Err(Error::config("tcpRedirect", "not supported"));
        }
        #[cfg(target_os = "linux")]
        {
            let listen = r.listen.as_deref().unwrap_or("");
            if listen.is_empty() {
                return Err(Error::config(
                    "tcpRedirect.listen",
                    "listen address is empty",
                ));
            }
        }
    }
    if let Some(t) = &y.tls {
        if t.ech.is_some() {
            return Err(Error::config("tls.ech", "not implemented"));
        }
    }
    let hop_interval = hop_interval_from_transport(y.transport.as_ref())?;

    let server = y.server.as_deref().ok_or_else(|| Error::config("Server", "must be set"))?;
    let realm_addr = try_parse_realm_url(server, "server")?;
    if y.realm.is_some() && realm_addr.is_none() {
        return Err(Error::config(
            "realm",
            "realm URL required in server (realm://, realm+http://, or https://…)",
        ));
    }

    let mut cfg = core_client::Config::default();
    cfg.auth = match &y.auth {
        Some(v) => auth_string(v)?,
        None => String::new(),
    };
    if let Some(t) = &y.tls {
        cfg.tls.server_name = t.sni.clone().unwrap_or_default();
        cfg.tls.insecure_skip_verify = t.insecure.unwrap_or(false);
        cfg.tls.pin_sha256 = t.pin_sha256.clone();
        if let Some(ca) = &t.ca {
            cfg.tls.ca_pem = std::fs::read(ca).map_err(|e| Error::config("tls.ca", e.to_string()))?;
        }
        if let Some(c) = &t.client_certificate {
            cfg.tls.client_cert_pem = std::fs::read(c).map_err(|e| Error::config("tls.clientCertificate", e.to_string()))?;
        }
        if let Some(k) = &t.client_key {
            cfg.tls.client_key_pem = std::fs::read(k).map_err(|e| Error::config("tls.clientKey", e.to_string()))?;
        }
    }
    if let Some(q) = &y.quic {
        if let Some(s) = &q.max_idle_timeout {
            cfg.quic.max_idle_timeout = parse_dur(s, "quic.maxIdleTimeout")?;
        }
        if let Some(s) = &q.keep_alive_period {
            cfg.quic.keep_alive_period = parse_dur(s, "quic.keepAlivePeriod")?;
        }
        cfg.quic.disable_path_mtu_discovery = q.disable_path_mtu_discovery.unwrap_or(false);
        cfg.quic.disable_chrome_parrot = q.disable_chrome_parrot.unwrap_or(false);
    }
    if let Some(b) = &y.bandwidth {
        if let Some(u) = &b.up {
            cfg.bandwidth.max_tx = parse_bps(u)?;
        }
        if let Some(d) = &b.down {
            cfg.bandwidth.max_rx = parse_bps(d)?;
        }
        cfg.bandwidth.disable_loss_compensation = b.disable_loss_compensation.unwrap_or(false);
    }
    if let Some(c) = &y.congestion {
        cfg.congestion.ty = c.ty.clone().unwrap_or_default();
        cfg.congestion.bbr_profile = c.bbr_profile.clone().unwrap_or_default();
    }
    let cong_ty = normalize_type(&cfg.congestion.ty)?;
    if cong_ty == CongestionType::Bbr {
        let _ = normalize_bbr_profile(&cfg.congestion.bbr_profile)?;
    }
    cfg.fast_open = y.fast_open.unwrap_or(false);

    let mut salamander_psk: Option<Vec<u8>> = None;
    let mut gecko_opts: Option<(Vec<u8>, usize, usize)> = None;
    let mut salamander_only_psk: Option<Vec<u8>> = None;
    let mut hop_mark = None;
    let mut gecko_mark = None;
    let mut realm_mark = None;
    if let Some(o) = &y.obfs {
        let ty = o.ty.as_deref().unwrap_or("plain");
        if ty == "salamander" {
            let psk = o
                .salamander
                .as_ref()
                .and_then(|s| s.password.as_deref())
                .ok_or_else(|| Error::config("obfs.salamander.password", "must be set"))?;
            salamander_psk = Some(psk.as_bytes().to_vec());
        } else if ty == "gecko" {
            let g = o
                .gecko
                .as_ref()
                .ok_or_else(|| Error::config("obfs.gecko", "password is required"))?;
            let psk = g
                .password
                .as_deref()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| Error::config("obfs.gecko", "password is required"))?;
            let min = g.min_packet_size.unwrap_or(0);
            let max = g.max_packet_size.unwrap_or(0);
            let min_pkt = if min == 0 { 512 } else { min };
            let max_pkt = if max == 0 { 1200 } else { max };
            if min_pkt == 0 || min_pkt > max_pkt || max_pkt > 2048 {
                return Err(Error::config("obfs.gecko", "invalid min/max packet size"));
            }
            if psk.as_bytes().len() < 4 {
                return Err(Error::config("obfs.gecko", "must be at least 4 bytes"));
            }
            gecko_opts = Some((psk.as_bytes().to_vec(), min, max));
        } else if ty != "plain" {
            return Err(Error::config("obfs.type", format!("{ty} not implemented")));
        }
    }

    let mimic;
    if let Some(raddr) = realm_addr {
        if cfg.tls.server_name.is_empty() {
            cfg.tls.server_name = raddr.host.clone();
        }
        // Placeholder; RealmFactory.open writes the punched peer into server_addr_slot.
        cfg.server_addr = Some(std::net::SocketAddr::from(([0, 0, 0, 0], 0)));
        let (fac, slot) = RealmFactory::new(raddr.clone(), realm_opts.clone());
        cfg.server_addr_slot = Some(slot);
        cfg.conn_factory = Some(std::sync::Arc::new(fac));
        realm_mark = Some((raddr, realm_opts));
        let _ = (salamander_psk, gecko_opts); // obfs on realm path: wrap later if needed
        mimic = fill_mimic(
            y.mimic.as_ref(),
            false,
            cfg.server_addr.unwrap(),
            Role::Client,
        )?;
    } else {
        let parsed = parse_server(server)?;
        if cfg.tls.server_name.is_empty() {
            cfg.tls.server_name = parsed.host.clone();
        }
        cfg.server_addr = Some(parsed.addr);
        mimic = fill_mimic(
            y.mimic.as_ref(),
            parsed.hop_ports.is_some(),
            parsed.addr,
            Role::Client,
        )?;

        if let Some((psk, min, max)) = gecko_opts {
            let mut fac = GeckoFactory::new(psk.clone(), min, max);
            let hop_ports = parsed.hop_ports.clone();
            if let Some(ports) = parsed.hop_ports {
                fac = fac.with_hop(ports, hop_interval);
            }
            gecko_mark = Some((psk, min, max, hop_ports, hop_interval));
            cfg.conn_factory = Some(std::sync::Arc::new(fac));
        } else if let Some(ports) = parsed.hop_ports {
            let mut fac = UdpHopFactory::new(ports.clone(), hop_interval);
            let sal = salamander_psk.take();
            if let Some(psk) = sal.clone() {
                fac = fac.with_salamander(psk);
            }
            hop_mark = Some((ports, hop_interval, sal));
            cfg.conn_factory = Some(std::sync::Arc::new(fac));
        } else if let Some(psk) = salamander_psk {
            salamander_only_psk = Some(psk.clone());
            cfg.conn_factory = Some(std::sync::Arc::new(SalamanderFactory {
                psk,
                inner: std::sync::Arc::new(StdUdpFactory),
            }));
        }
    }
    if mimic.is_some() {
        cfg.quic.disable_gso = true;
    }

    Ok(ClientApp {
        core: cfg,
        socks5: y.socks5.clone(),
        http: y.http.clone(),
        tcp_fwd: y.tcp_forwarding.clone().unwrap_or_default(),
        udp_fwd: y.udp_forwarding.clone().unwrap_or_default(),
        tcp_tproxy,
        udp_tproxy,
        tcp_redirect: y.tcp_redirect.clone(),
        tun,
        lazy: y.lazy.unwrap_or(false),
        mimic,
        salamander_only_psk,
        hop_mark,
        gecko_mark,
        realm_mark,
    })
}

fn fill_tun(y: Option<&TunYaml>) -> Result<Option<TunConfig>, Error> {
    let Some(t) = y else {
        return Ok(None);
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = t;
        return Err(Error::config("tun", "not supported"));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let name = t.name.as_deref().unwrap_or("").trim();
        if name.is_empty() {
            return Err(Error::config("tun.name", "name is empty"));
        }
        #[cfg(target_os = "macos")]
        {
            if crate::inbound::tun::parse_utun_unit(name).is_err() {
                return Err(Error::config("tun.name", "bad tun name"));
            }
        }
        let mtu = match t.mtu {
            Some(0) | None => 1500,
            Some(m) => m,
        };
        let timeout = match &t.timeout {
            Some(s) => {
                let d = parse_dur(s, "tun.timeout")?;
                if d.is_zero() {
                    Duration::from_secs(300)
                } else {
                    d
                }
            }
            None => Duration::from_secs(300),
        };
        let ipv4 = t
            .address
            .as_ref()
            .and_then(|a| a.ipv4.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "100.100.100.101/30".to_string());
        parse_ip_prefix(&ipv4, false).map_err(|e| Error::config("tun.address.ipv4", e))?;

        let ipv6_raw = t
            .address
            .as_ref()
            .and_then(|a| a.ipv6.clone())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "2001::ffff:ffff:ffff:fff1/126".to_string());
        parse_ip_prefix(&ipv6_raw, true).map_err(|e| Error::config("tun.address.ipv6", e))?;

        let route = match &t.route {
            None => None,
            Some(r) => {
                let ipv4 = parse_route_list(r.ipv4.as_deref().unwrap_or(&[]), false, "tun.route.ipv4")?;
                let ipv6 = parse_route_list(r.ipv6.as_deref().unwrap_or(&[]), true, "tun.route.ipv6")?;
                let ipv4_exclude = parse_route_list(
                    r.ipv4_exclude.as_deref().unwrap_or(&[]),
                    false,
                    "tun.route.ipv4Exclude",
                )?;
                let ipv6_exclude = parse_route_list(
                    r.ipv6_exclude.as_deref().unwrap_or(&[]),
                    true,
                    "tun.route.ipv6Exclude",
                )?;
                Some(TunRouteConfig {
                    strict: r.strict.unwrap_or(false),
                    ipv4,
                    ipv6,
                    ipv4_exclude,
                    ipv6_exclude,
                })
            }
        };

        Ok(Some(TunConfig {
            name: name.to_string(),
            mtu,
            timeout,
            ipv4,
            ipv6: Some(ipv6_raw),
            route,
            apply_exclude: false,
        }))
    }
}

/// Merge skip-proxy / bypass CIDRs into TUN exclude and turn on Linux exclude install.
/// Called only when client-route is on. If `tun.route` is omitted, create a default
/// (empty ipv4 → install base `0.0.0.0/0`) so exclude is actually subtracted.
pub fn merge_tun_exclude(tun: &mut Option<TunConfig>, cidrs: &[(std::net::IpAddr, u8)]) {
    let Some(t) = tun else {
        return;
    };
    t.apply_exclude = true;
    let route = t.route.get_or_insert_with(TunRouteConfig::default);
    for &(ip, pfx) in cidrs {
        let s = format!("{ip}/{pfx}");
        match ip {
            std::net::IpAddr::V4(_) => {
                if !route.ipv4_exclude.contains(&s) {
                    route.ipv4_exclude.push(s);
                }
            }
            std::net::IpAddr::V6(_) => {
                if !route.ipv6_exclude.contains(&s) {
                    route.ipv6_exclude.push(s);
                }
            }
        }
    }
}

/// Parse `"addr/len"` or bare addr (full bit length). `v6` selects address family.
fn parse_ip_prefix(s: &str, v6: bool) -> Result<(std::net::IpAddr, u8), String> {
    let (addr_s, len) = if let Some((a, p)) = s.split_once('/') {
        let len: u8 = p
            .parse()
            .map_err(|_| format!("bad prefix length in {s}"))?;
        (a, len)
    } else {
        (s, if v6 { 128 } else { 32 })
    };
    let addr: std::net::IpAddr = addr_s
        .parse()
        .map_err(|_| format!("bad address in {s}"))?;
    match (addr, v6) {
        (std::net::IpAddr::V4(_), false) => {
            if len > 32 {
                return Err(format!("prefix length {len} > 32"));
            }
        }
        (std::net::IpAddr::V6(_), true) => {
            if len > 128 {
                return Err(format!("prefix length {len} > 128"));
            }
        }
        (std::net::IpAddr::V4(_), true) => return Err(format!("expected IPv6, got {s}")),
        (std::net::IpAddr::V6(_), false) => return Err(format!("expected IPv4, got {s}")),
    }
    Ok((addr, len))
}

fn parse_route_list(
    ss: &[String],
    v6: bool,
    field: &'static str,
) -> Result<Vec<String>, Error> {
    let mut out = Vec::with_capacity(ss.len());
    for s in ss {
        parse_ip_prefix(s, v6).map_err(|e| Error::config(field, e))?;
        out.push(s.clone());
    }
    Ok(out)
}

fn fill_tcp_tproxy(y: Option<&TcpTProxyYaml>) -> Result<Option<TcpTProxyYaml>, Error> {
    let Some(t) = y else {
        return Ok(None);
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = t;
        return Err(Error::config("tcpTProxy", "not supported"));
    }
    #[cfg(target_os = "linux")]
    {
        let listen = t.listen.as_deref().unwrap_or("");
        if listen.is_empty() {
            return Err(Error::config(
                "tcpTProxy.listen",
                "listen address is empty",
            ));
        }
        Ok(Some(t.clone()))
    }
}

fn fill_udp_tproxy(y: Option<&UdpTProxyYaml>) -> Result<Option<UdpTProxyConfig>, Error> {
    let Some(t) = y else {
        return Ok(None);
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = t;
        return Err(Error::config("udpTProxy", "not supported"));
    }
    #[cfg(target_os = "linux")]
    {
        let listen = t.listen.as_deref().unwrap_or("");
        if listen.is_empty() {
            return Err(Error::config(
                "udpTProxy.listen",
                "listen address is empty",
            ));
        }
        let timeout = match &t.timeout {
            Some(s) => parse_dur(s, "udpTProxy.timeout")?,
            None => Duration::from_secs(60),
        };
        Ok(Some(UdpTProxyConfig {
            listen: listen.to_string(),
            timeout,
        }))
    }
}

/// YAML hop interval (production ≥5s). Missing → 30s/30s.
fn fill_realm_opts(y: Option<&RealmYaml>) -> Result<RealmOptions, Error> {
    let mut opts = RealmOptions::default();
    let Some(y) = y else {
        return Ok(opts);
    };
    if let Some(s) = &y.stun_servers {
        if !s.is_empty() {
            opts.stun_servers = s.clone();
        }
    }
    if let Some(s) = &y.stun_timeout {
        opts.stun_timeout = parse_dur(s, "realm.stunTimeout")?;
    }
    if let Some(s) = &y.punch_timeout {
        opts.punch_timeout = parse_dur(s, "realm.punchTimeout")?;
    }
    opts.insecure = y.insecure.unwrap_or(false);
    let mode = y.ip_mode.as_deref().unwrap_or("dual");
    opts.family =
        AddrFamily::from_ip_mode(mode).map_err(|e| Error::config("realm.ipMode", e))?;
    // port_mapping: parse accepted; apply is a no-op this gate (official UPnP/NAT-PMP).
    let _ = &y.port_mapping;
    Ok(opts)
}

fn hop_interval_from_transport(transport: Option<&serde_yaml::Value>) -> Result<HopInterval, Error> {
    let Some(tr) = transport else {
        return Ok(HopInterval::default_30s());
    };
    let Some(m) = tr.as_mapping() else {
        return Ok(HopInterval::default_30s());
    };
    let Some(udp) = m.get(serde_yaml::Value::from("udp")).and_then(|v| v.as_mapping()) else {
        return Ok(HopInterval::default_30s());
    };

    let hop = udp
        .get(serde_yaml::Value::from("hopInterval"))
        .and_then(|v| v.as_str());
    let min_s = udp
        .get(serde_yaml::Value::from("minHopInterval"))
        .and_then(|v| v.as_str());
    let max_s = udp
        .get(serde_yaml::Value::from("maxHopInterval"))
        .and_then(|v| v.as_str());

    if hop.is_some() && (min_s.is_some() || max_s.is_some()) {
        return Err(Error::config(
            "transport.udp",
            "hopInterval cannot be used together with minHopInterval or maxHopInterval",
        ));
    }

    let interval = if let Some(h) = hop {
        let d = parse_dur(h, "transport.udp.hopInterval")?;
        HopInterval::fixed(d)
    } else if min_s.is_none() && max_s.is_none() {
        HopInterval::default_30s()
    } else {
        let min_s = min_s.ok_or_else(|| {
            Error::config(
                "transport.udp",
                "minHopInterval and maxHopInterval must both be set",
            )
        })?;
        let max_s = max_s.ok_or_else(|| {
            Error::config(
                "transport.udp",
                "minHopInterval and maxHopInterval must both be set",
            )
        })?;
        let min = parse_dur(min_s, "transport.udp.minHopInterval")?;
        let max = parse_dur(max_s, "transport.udp.maxHopInterval")?;
        if min > max {
            return Err(Error::config(
                "transport.udp",
                "min hop interval must not be greater than max hop interval",
            ));
        }
        HopInterval { min, max }
    };

    if interval.min < Duration::from_secs(5) {
        return Err(Error::config(
            "transport.udp",
            "hop interval must be at least 5 seconds",
        ));
    }
    Ok(interval)
}

pub(crate) struct SalamanderFactory {
    pub psk: Vec<u8>,
    pub inner: Arc<dyn hy_core::io::ConnFactory>,
}

#[async_trait::async_trait]
impl hy_core::io::ConnFactory for SalamanderFactory {
    async fn open(&self, server: std::net::SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let inner = self.inner.open(server).await?;
        Ok(Arc::new(ObfsSalamander::new(inner, &self.psk)?))
    }
}

pub struct ServerApp {
    pub core: core_server::Config,
    pub traffic: Option<(std::net::SocketAddr, std::sync::Arc<TrafficStats>)>,
    /// TCP HTTP(S) masquerade façade (listenHTTP / listenHTTPS).
    pub masq_tcp: Option<Arc<MasqTcpServer>>,
    pub masq_listen_http: Option<std::net::SocketAddr>,
    pub masq_listen_https: Option<std::net::SocketAddr>,
    /// Present only when `mimic.enabled: true` passed fill. Spawn via [`ServerApp::start`].
    pub mimic: Option<MimicSpec>,
}

impl ServerApp {
    /// Spawn mimic (if enabled) before `serve` (first QUIC packet). UDP may already
    /// be bound by fill; XDP attaches on the iface, not the socket.
    pub fn start(&self) -> Result<Option<MimicHandle>, Error> {
        crate::mimic::start(self.mimic.as_ref())
    }
}

pub async fn fill_server(y: &ServerYaml) -> Result<ServerApp, Error> {
    match (&y.tls, &y.acme) {
        (None, None) => {
            return Err(Error::config("tls", "must set either tls or acme"));
        }
        (Some(_), Some(_)) => {
            return Err(Error::config("tls", "cannot set both tls and acme"));
        }
        (None, Some(acme)) => {
            acme::validate(acme)?;
        }
        (Some(_), None) => {}
    }
    if y.ech.is_some() {
        return Err(Error::config("ech", "not implemented"));
    }
    if y.tls.as_ref().and_then(|t| t.ech.as_ref()).is_some() {
        return Err(Error::config("tls.ech", "not implemented"));
    }
    let realm_opts = fill_realm_opts(y.realm.as_ref())?;
    // Mimic fill (no spawn) before TLS file reads so `enabled: true` without path
    // is still a Config error in isolation, not a missing cert path.
    let mimic_addr = if y
        .mimic
        .as_ref()
        .map(|m| m.enabled.unwrap_or(false))
        .unwrap_or(false)
    {
        let listen = y.listen.as_deref().unwrap_or(":443");
        if try_parse_realm_url(listen, "listen")?.is_some() {
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            parse_listen(listen, "listen")?
        }
    } else {
        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mimic = fill_mimic(y.mimic.as_ref(), false, mimic_addr, Role::Server)?;
    // resolver.type validated in build_outbound (P5.A2: tcp/udp/tls/https/doh).
    if let Some(m) = &y.masquerade {
        let ty = m.ty.as_deref().unwrap_or("");
        match ty {
            "" | "404" => {}
            "string" => {
                let s = m
                    .string
                    .as_ref()
                    .ok_or_else(|| Error::config("masquerade.string", "must be set"))?;
                let content = s.content.clone().unwrap_or_default();
                if content.is_empty() {
                    return Err(Error::config(
                        "masquerade.string.content",
                        "empty string content",
                    ));
                }
                let status = s.status_code.or(s.status).unwrap_or(200);
                if status == 233 || !(200..=599).contains(&status) {
                    return Err(Error::config(
                        "masquerade.string.statusCode",
                        "invalid status code (must be 200-599, except 233)",
                    ));
                }
            }
            "file" => {
                let dir = m
                    .file
                    .as_ref()
                    .and_then(|f| f.dir.as_deref())
                    .unwrap_or("");
                if dir.is_empty() {
                    return Err(Error::config(
                        "masquerade.file.dir",
                        "empty file directory",
                    ));
                }
            }
            "proxy" => {
                let url = m
                    .proxy
                    .as_ref()
                    .and_then(|p| p.url.as_deref())
                    .unwrap_or("");
                if url.is_empty() {
                    return Err(Error::config("masquerade.proxy.url", "empty proxy url"));
                }
                let rewrite = m.proxy.as_ref().and_then(|p| p.rewrite_host).unwrap_or(false);
                let xf = m.proxy.as_ref().and_then(|p| p.x_forwarded).unwrap_or(false);
                let insecure = m.proxy.as_ref().and_then(|p| p.insecure).unwrap_or(false);
                let _ = ProxyMasq::new(url, rewrite, xf, insecure)?;
            }
            other => {
                return Err(Error::config(
                    "masquerade.type",
                    format!("{other} not implemented"),
                ));
            }
        }
    }
    // Validate outbound types early (before bind/TLS) so bare YAML fails as Config.
    if let Some(list) = &y.outbounds {
        for o in list {
            let ty = o.ty.as_deref().unwrap_or("direct").to_ascii_lowercase();
            match ty.as_str() {
                "direct" => {}
                "socks5" => {
                    let addr = o
                        .socks5
                        .as_ref()
                        .and_then(|s| s.addr.as_deref())
                        .unwrap_or("");
                    if addr.is_empty() {
                        return Err(Error::config(
                            "outbounds.socks5.addr",
                            "empty socks5 address",
                        ));
                    }
                }
                "http" => {
                    let url = o.http.as_ref().and_then(|h| h.url.as_deref()).unwrap_or("");
                    if url.is_empty() {
                        return Err(Error::config("outbounds.http.url", "empty http address"));
                    }
                    // Reject unsupported schemes early with a stable Config/Dial path.
                    let insecure = o.http.as_ref().and_then(|h| h.insecure).unwrap_or(false);
                    let _ = HttpOutbound::new(url, insecure)?;
                }
                other => {
                    return Err(Error::config(
                        "outbounds",
                        format!("{other} not implemented"),
                    ));
                }
            }
        }
    }
    let listen = y.listen.as_deref().unwrap_or(":443");
    let realm_addr = try_parse_realm_url(listen, "listen")?;
    if y.realm.is_some() && realm_addr.is_none() {
        return Err(Error::config(
            "realm",
            "realm URL required in listen (realm://, realm+http://, or https://…)",
        ));
    }
    let mut io: Arc<dyn DatagramIo> = if let Some(raddr) = realm_addr {
        open_server_realm(&raddr, &realm_opts).await?
    } else {
        let bind = parse_listen(listen, "listen")?;
        Arc::new(StdUdp::bind(bind).await.map_err(Error::Io)?)
    };
    if let Some(o) = &y.obfs {
        if o.ty.as_deref() == Some("salamander") {
            let psk = o
                .salamander
                .as_ref()
                .and_then(|s| s.password.as_deref())
                .ok_or_else(|| Error::config("obfs.salamander.password", "must be set"))?;
            io = Arc::new(ObfsSalamander::new(io, psk.as_bytes())?);
        } else if o.ty.as_deref() == Some("gecko") {
            let g = o
                .gecko
                .as_ref()
                .ok_or_else(|| Error::config("obfs.gecko", "password is required"))?;
            let psk = g
                .password
                .as_deref()
                .filter(|p| !p.is_empty())
                .ok_or_else(|| Error::config("obfs.gecko", "password is required"))?;
            let min = g.min_packet_size.unwrap_or(0);
            let max = g.max_packet_size.unwrap_or(0);
            io = Arc::new(ObfsGecko::wrap(io, psk.as_bytes(), min, max)?);
        }
    }

    let mut cfg = core_server::Config::default();
    if let Some(tls) = y.tls.as_ref() {
        let cert = tls
            .cert
            .as_deref()
            .ok_or_else(|| Error::config("tls.cert", "must be set"))?;
        let key = tls
            .key
            .as_deref()
            .ok_or_else(|| Error::config("tls.key", "must be set"))?;
        cfg.tls.cert_pem =
            std::fs::read(cert).map_err(|e| Error::config("tls.cert", e.to_string()))?;
        cfg.tls.key_pem =
            std::fs::read(key).map_err(|e| Error::config("tls.key", e.to_string()))?;
        if let Some(ca) = tls.client_ca.as_deref() {
            cfg.tls.client_ca_pem =
                std::fs::read(ca).map_err(|e| Error::config("tls.clientCA", e.to_string()))?;
        }
    } else {
        let acme = y.acme.as_ref().expect("acme Some after mutual-exclusion");
        let (cert_pem, key_pem) = acme::obtain(acme).await?;
        cfg.tls.cert_pem = cert_pem;
        cfg.tls.key_pem = key_pem;
    }
    cfg.conn = Some(io);
    cfg.disable_udp = y.disable_udp.unwrap_or(false);
    if let Some(s) = y.udp_idle_timeout.as_deref() {
        cfg.udp_idle_timeout = parse_dur(s, "udpIdleTimeout")?;
    }
    cfg.ignore_client_bandwidth = y.ignore_client_bandwidth.unwrap_or(false);
    if let Some(b) = &y.bandwidth {
        if let Some(u) = &b.up {
            cfg.bandwidth.max_tx = parse_bps(u)?;
        }
        if let Some(d) = &b.down {
            cfg.bandwidth.max_rx = parse_bps(d)?;
        }
        cfg.bandwidth.disable_loss_compensation = b.disable_loss_compensation.unwrap_or(false);
    }
    if let Some(c) = &y.congestion {
        cfg.congestion.ty = c.ty.clone().unwrap_or_default();
        cfg.congestion.bbr_profile = c.bbr_profile.clone().unwrap_or_default();
    }
    let cong_ty = normalize_type(&cfg.congestion.ty)?;
    if cong_ty == CongestionType::Bbr {
        let _ = normalize_bbr_profile(&cfg.congestion.bbr_profile)?;
    }

    cfg.authenticator = Some(build_auth(y.auth.as_ref())?);
    cfg.outbound = Some(build_outbound(y)?);
    if let Some(s) = &y.sniff {
        if s.enable == Some(true) {
            let mut sniffer = Sniffer::default();
            if let Some(t) = s.timeout.as_deref() {
                sniffer.timeout = parse_dur(t, "sniff.timeout")?;
            }
            sniffer.rewrite_domain = s.rewrite_domain.unwrap_or(false);
            if let Some(p) = s.tcp_ports.as_deref() {
                if !p.trim().is_empty() {
                    sniffer.tcp_ports = Some(
                        parse_port_union(p)
                            .ok_or_else(|| Error::config("sniff.tcpPorts", "invalid port union"))?,
                    );
                }
            }
            if let Some(p) = s.udp_ports.as_deref() {
                if !p.trim().is_empty() {
                    sniffer.udp_ports = Some(
                        parse_port_union(p)
                            .ok_or_else(|| Error::config("sniff.udpPorts", "invalid port union"))?,
                    );
                }
            }
            cfg.request_hook = Some(Arc::new(sniffer));
        }
    }
    let mut masq_proxy: Option<Arc<ProxyMasq>> = None;
    if let Some(m) = &y.masquerade {
        let ty = m.ty.as_deref().unwrap_or("");
        if ty == "string" {
            let s = m.string.as_ref().unwrap();
            let status = s.status_code.or(s.status).unwrap_or(200);
            let headers = s
                .headers
                .as_ref()
                .map(|h| h.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            cfg.masq_handler = Some(Arc::new(StringMasq::new(
                status,
                headers,
                s.content.clone().unwrap_or_default().into_bytes(),
            )));
        } else if ty == "file" {
            let dir = m.file.as_ref().unwrap().dir.as_deref().unwrap();
            cfg.masq_handler = Some(Arc::new(FileMasq::new(dir)));
        } else if ty == "proxy" {
            let p = m.proxy.as_ref().unwrap();
            let url = p.url.as_deref().unwrap();
            let rewrite = p.rewrite_host.unwrap_or(false);
            let xf = p.x_forwarded.unwrap_or(false);
            let insecure = p.insecure.unwrap_or(false);
            let proxy = Arc::new(ProxyMasq::new(url, rewrite, xf, insecure)?);
            masq_proxy = Some(Arc::clone(&proxy));
            cfg.masq_handler = Some(proxy);
        }
    }
    let traffic = if let Some(ts) = &y.traffic_stats {
        if let Some(listen) = ts.listen.as_deref() {
            let addr = parse_listen(listen, "trafficStats.listen")?;
            let logger = TrafficStats::new(ts.secret.clone().unwrap_or_default());
            cfg.traffic_logger = Some(logger.clone());
            Some((addr, logger))
        } else {
            None
        }
    } else {
        None
    };

    let (masq_tcp, masq_listen_http, masq_listen_https) = if let Some(m) = &y.masquerade {
        let want_http = m.listen_http.as_deref().filter(|s| !s.is_empty());
        let want_https = m.listen_https.as_deref().filter(|s| !s.is_empty());
        if want_http.is_none() && want_https.is_none() {
            (None, None, None)
        } else {
            let http_addr = match want_http {
                Some(s) => Some(parse_listen(s, "masquerade.listenHTTP")?),
                None => None,
            };
            let https_addr = match want_https {
                Some(s) => Some(parse_listen(s, "masquerade.listenHTTPS")?),
                None => None,
            };
            let quic_port = cfg
                .conn
                .as_ref()
                .and_then(|c| c.local_addr().ok())
                .map(|a| a.port())
                .unwrap_or(0);
            let https_port = https_addr.map(|a| a.port()).unwrap_or(443);
            let handler: Arc<dyn hy_core::server::MasqHandler> = cfg
                .masq_handler
                .clone()
                .unwrap_or_else(|| Arc::new(NotFoundMasq));
            let srv = Arc::new(MasqTcpServer {
                quic_port,
                https_port,
                handler,
                force_https: m.force_https.unwrap_or(false),
                proxy: masq_proxy,
                tls_cert_pem: cfg.tls.cert_pem.clone(),
                tls_key_pem: cfg.tls.key_pem.clone(),
            });
            (Some(srv), http_addr, https_addr)
        }
    } else {
        (None, None, None)
    };

    if mimic.is_some() {
        cfg.quic.disable_gso = true;
    }
    Ok(ServerApp {
        core: cfg,
        traffic,
        masq_tcp,
        masq_listen_http,
        masq_listen_https,
        mimic,
    })
}

fn build_auth(a: Option<&ServerAuthYaml>) -> Result<Arc<dyn hy_core::server::Authenticator>, Error> {
    let a = a.ok_or_else(|| Error::config("auth", "must be set"))?;
    let ty = a.ty.as_deref().unwrap_or("password");
    match ty {
        "password" => {
            let p = a.password.clone().ok_or_else(|| Error::config("auth.password", "must be set"))?;
            Ok(Arc::new(Password(p)))
        }
        "userpass" => {
            let m = a.userpass.clone().ok_or_else(|| Error::config("auth.userpass", "must be set"))?;
            Ok(Arc::new(UserPass::new(m)))
        }
        "http" => {
            let h = a.http.as_ref().ok_or_else(|| Error::config("auth.http", "must be set"))?;
            Ok(Arc::new(HttpAuth {
                url: h.url.clone().unwrap_or_default(),
                insecure: h.insecure.unwrap_or(false),
            }))
        }
        "command" => {
            let c = a.command.clone().ok_or_else(|| Error::config("auth.command", "must be set"))?;
            Ok(Arc::new(CommandAuth::new(PathBuf::from(c))))
        }
        other => Err(Error::config("auth.type", format!("{other} not implemented"))),
    }
}

fn build_outbound(y: &ServerYaml) -> Result<Arc<dyn hy_core::server::Outbound>, Error> {
    let direct: Arc<dyn PluggableOutbound> = Arc::new(Direct::new(DirectMode::Auto));
    let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
    table.insert("direct".into(), Arc::clone(&direct));

    let mut first_ob: Option<Arc<dyn PluggableOutbound>> = None;
    let mut has_explicit_default = false;

    if let Some(list) = &y.outbounds {
        for o in list {
            let name = o
                .name
                .clone()
                .unwrap_or_else(|| "default".into())
                .to_ascii_lowercase();
            let ty = o.ty.as_deref().unwrap_or("direct").to_ascii_lowercase();
            let d: Arc<dyn PluggableOutbound> = match ty.as_str() {
                "direct" => {
                    let mode = match o.direct.as_ref().and_then(|d| d.mode.as_deref()).unwrap_or("auto")
                    {
                        "auto" => DirectMode::Auto,
                        "64" => DirectMode::Prefer64,
                        "46" => DirectMode::Prefer46,
                        "6" => DirectMode::V6,
                        "4" => DirectMode::V4,
                        other => {
                            return Err(Error::config(
                                "outbounds.direct.mode",
                                format!("bad mode {other}"),
                            ))
                        }
                    };
                    Arc::new(Direct::new(mode))
                }
                "socks5" => {
                    let s = o.socks5.as_ref();
                    let addr = s.and_then(|x| x.addr.as_deref()).unwrap_or("");
                    if addr.is_empty() {
                        return Err(Error::config(
                            "outbounds.socks5.addr",
                            "empty socks5 address",
                        ));
                    }
                    let username = s
                        .and_then(|x| x.username.clone())
                        .unwrap_or_default();
                    let password = s
                        .and_then(|x| x.password.clone())
                        .unwrap_or_default();
                    Arc::new(Socks5Outbound::new(addr.to_string(), username, password))
                }
                "http" => {
                    let h = o.http.as_ref();
                    let url = h.and_then(|x| x.url.as_deref()).unwrap_or("");
                    if url.is_empty() {
                        return Err(Error::config("outbounds.http.url", "empty http address"));
                    }
                    let insecure = h.and_then(|x| x.insecure).unwrap_or(false);
                    Arc::new(HttpOutbound::new(url, insecure)?)
                }
                other => {
                    return Err(Error::config(
                        "outbounds",
                        format!("{other} not implemented"),
                    ))
                }
            };
            if first_ob.is_none() {
                first_ob = Some(Arc::clone(&d));
            }
            if name == "default" {
                has_explicit_default = true;
            }
            table.insert(name, d);
        }
    }

    if !has_explicit_default {
        if let Some(f) = first_ob {
            table.insert("default".into(), f);
        } else {
            table.insert("default".into(), Arc::clone(&direct));
        }
    }

    let default_ob = Arc::clone(table.get("default").unwrap_or(&direct));

    let mut next: Arc<dyn PluggableOutbound> = if let Some(acl) = &y.acl {
        let text = if let Some(inline) = &acl.inline {
            inline.clone()
        } else if let Some(file) = &acl.file {
            std::fs::read_to_string(file).map_err(|e| Error::config("acl.file", e.to_string()))?
        } else {
            String::new()
        };
        let interval = geo_interval_from_yaml(acl.geo_update_interval.as_deref())?;
        let loader = AppGeoLoader::new(
            acl.geoip.clone(),
            acl.geosite.clone(),
            interval,
            std::sync::Arc::new(DefaultHttp),
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        );
        let rules = CompiledRuleSet::compile_with(&text, Some(&loader))
            .map_err(|e| Error::config("acl", e.to_string()))?;
        Arc::new(AclEngine::new(rules, table))
    } else {
        default_ob
    };

    next = wrap_resolver(y, next)?;
    // Speedtest sits outside Resolver/ACL (pipeline: Speedtest → Resolver → ACL → Outbound).
    if y.speed_test == Some(true) {
        next = Arc::new(SpeedtestHandler { next });
    }
    Ok(Arc::new(Adapter(next)))
}

fn resolver_timeout(s: Option<&str>, field: &'static str) -> Result<Duration, Error> {
    match s {
        None | Some("") => Ok(Duration::ZERO), // StandardResolver/DohResolver apply default
        Some(t) => parse_dur(t, field),
    }
}

fn wrap_resolver(
    y: &ServerYaml,
    next: Arc<dyn PluggableOutbound>,
) -> Result<Arc<dyn PluggableOutbound>, Error> {
    let r = y.resolver.as_ref();
    let ty = r
        .and_then(|x| x.ty.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ty.as_str() {
        "" => {
            // No resolver section / empty type: wrap SystemResolver only when ACL is present.
            if y.acl.is_some() {
                Ok(Arc::new(SystemResolver { next }))
            } else {
                Ok(next)
            }
        }
        "system" => {
            // Explicit system: always wrap (same as prior need_resolver behavior).
            Ok(Arc::new(SystemResolver { next }))
        }
        "tcp" => {
            let ep = r.and_then(|x| x.tcp.as_ref());
            let addr = ep
                .and_then(|e| e.addr.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::config("resolver.tcp.addr", "empty resolver address"))?;
            let timeout = resolver_timeout(ep.and_then(|e| e.timeout.as_deref()), "resolver.tcp.timeout")?;
            Ok(Arc::new(StandardResolver::tcp(addr.to_string(), timeout, next)))
        }
        "udp" => {
            let ep = r.and_then(|x| x.udp.as_ref());
            let addr = ep
                .and_then(|e| e.addr.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::config("resolver.udp.addr", "empty resolver address"))?;
            let timeout = resolver_timeout(ep.and_then(|e| e.timeout.as_deref()), "resolver.udp.timeout")?;
            Ok(Arc::new(StandardResolver::udp(addr.to_string(), timeout, next)))
        }
        "tls" | "tcp-tls" => {
            let ep = r.and_then(|x| x.tls.as_ref());
            let addr = ep
                .and_then(|e| e.addr.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::config("resolver.tls.addr", "empty resolver address"))?;
            let timeout = resolver_timeout(ep.and_then(|e| e.timeout.as_deref()), "resolver.tls.timeout")?;
            let sni = ep.and_then(|e| e.sni.clone()).unwrap_or_default();
            let insecure = ep.and_then(|e| e.insecure).unwrap_or(false);
            Ok(Arc::new(StandardResolver::tls(
                addr.to_string(),
                timeout,
                sni,
                insecure,
                next,
            )))
        }
        "https" | "http" | "doh" => {
            let ep = r.and_then(|x| x.https.as_ref());
            let addr = ep
                .and_then(|e| e.addr.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::config("resolver.https.addr", "empty resolver address"))?;
            let timeout =
                resolver_timeout(ep.and_then(|e| e.timeout.as_deref()), "resolver.https.timeout")?;
            let sni = ep.and_then(|e| e.sni.clone()).unwrap_or_default();
            let insecure = ep.and_then(|e| e.insecure).unwrap_or(false);
            Ok(Arc::new(DohResolver::new(
                addr.to_string(),
                timeout,
                sni,
                insecure,
                next,
            )))
        }
        other => Err(Error::config(
            "resolver.type",
            format!("{other} not implemented"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_client_deserializes() {
        let y = parse_client_yaml(
            r#"
server: 127.0.0.1:18443
auth: test
tls: { insecure: true, sni: localhost }
socks5: { listen: 127.0.0.1:11080 }
http: { listen: ":8080" }
tcpForwarding: [{ listen: ":2222", remote: "1.1.1.1:22" }]
udpForwarding: [{ listen: ":53", remote: "1.1.1.1:53", timeout: 60s }]
bandwidth: { up: 100mbps, down: 500mbps }
congestion: { type: bbr, bbrProfile: standard }
obfs: { type: salamander, salamander: { password: "abcd" } }
"#,
        )
        .unwrap();
        assert_eq!(y.server.as_deref(), Some("127.0.0.1:18443"));
        assert!(y.socks5.is_some());
    }

    #[test]
    fn fill_client_bbr_profiles() {
        for profile in ["conservative", "aggressive"] {
            let y = parse_client_yaml(&format!(
                "server: 127.0.0.1:1\nauth: x\ncongestion: {{ type: bbr, bbrProfile: {profile} }}\n"
            ))
            .unwrap();
            let app = fill_client(&y).unwrap_or_else(|e| panic!("bbrProfile {profile}: {e:?}"));
            assert_eq!(app.core.congestion.ty, "bbr");
            assert_eq!(app.core.congestion.bbr_profile, profile);
        }
        let field = client_field("congestion: { type: bbr, bbrProfile: turbo }");
        assert!(
            field.contains("bbrProfile") || field.contains("BBRProfile"),
            "turbo field={field}"
        );
    }

    #[test]
    fn fill_client_disable_chrome_parrot_true_and_false() {
        for (yaml_val, want) in [(true, true), (false, false)] {
            let y = parse_client_yaml(&format!(
                "server: 127.0.0.1:1\nauth: x\nquic: {{ disableChromeParrot: {yaml_val} }}\n"
            ))
            .unwrap();
            let app = match fill_client(&y) {
                Ok(app) => app,
                Err(e) => {
                    let s = format!("{e:?}");
                    assert!(!s.contains("not implemented"), "{s}");
                    panic!("disableChromeParrot {yaml_val} must fill, got {e:?}");
                }
            };
            assert_eq!(
                app.core.quic.disable_chrome_parrot, want,
                "disableChromeParrot {yaml_val}"
            );
        }
    }

    #[test]
    fn official_server_deserializes() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:18443
tls: { cert: test.crt, key: test.key }
auth: { type: password, password: test }
acl: { inline: "direct(*)\n" }
"#,
        )
        .unwrap();
        assert_eq!(y.listen.as_deref(), Some("127.0.0.1:18443"));
    }

    #[test]
    fn disable_udp_accepts_official_casing() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
disableUDP: true
"#,
        )
        .unwrap();
        assert_eq!(y.disable_udp, Some(true));
    }

    #[test]
    fn fill_server_bbr_profiles() {
        let dir = std::env::temp_dir().join(format!("hy-bbr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
            .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for profile in ["conservative", "aggressive"] {
            let y = parse_server_yaml(&format!(
                r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
congestion: {{ type: bbr, bbrProfile: {} }}
"#,
                cert.display(),
                key.display(),
                profile
            ))
            .unwrap();
            let app = rt
                .block_on(fill_server(&y))
                .unwrap_or_else(|e| panic!("bbrProfile {profile}: {e:?}"));
            assert_eq!(app.core.congestion.ty, "bbr");
            assert_eq!(app.core.congestion.bbr_profile, profile);
        }
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
congestion: {{ type: bbr, bbrProfile: turbo }}
"#,
            cert.display(),
            key.display()
        ))
        .unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, .. }) => {
                assert!(
                    field.contains("bbrProfile") || field.contains("BBRProfile"),
                    "turbo field={field}"
                );
            }
            other => panic!(
                "expected Config for turbo, got {}",
                match &other {
                    Ok(_) => "Ok(ServerApp)".into(),
                    Err(e) => format!("Err({e})"),
                }
            ),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn client_field(extra: &str) -> &'static str {
        let y = parse_client_yaml(&format!("server: 127.0.0.1:1\nauth: x\n{extra}\n")).unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, .. }) => field,
            other => panic!("expected Config, got ok-or-other-err"),
        }
    }

    #[test]
    fn fill_tun_empty_name() {
        assert_eq!(client_field("tun: { name: \"\" }"), "tun.name");
        assert_eq!(client_field("tun: {}"), "tun.name");
    }

    #[test]
    fn fill_tun_defaults() {
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntun: { name: hy0 }\n").unwrap();
        let app = fill_client(&y).expect("tun: { name: hy0 } should fill");
        let t = app.tun.expect("tun present");
        assert_eq!(t.name, "hy0");
        assert_eq!(t.mtu, 1500);
        assert_eq!(t.timeout, Duration::from_secs(300));
        assert_eq!(t.ipv4, "100.100.100.101/30");
        assert_eq!(
            t.ipv6.as_deref(),
            Some("2001::ffff:ffff:ffff:fff1/126")
        );
        assert!(!t.apply_exclude);
    }

    #[test]
    fn merge_tun_exclude_sets_apply_and_cidrs() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n  route:\n    ipv4Exclude: [1.1.1.1/32]\n",
        )
        .unwrap();
        let mut app = fill_client(&y).unwrap();
        let cidrs = [(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 0, 0)),
            16u8,
        )];
        merge_tun_exclude(&mut app.tun, &cidrs);
        let t = app.tun.as_ref().unwrap();
        assert!(t.apply_exclude);
        let r = t.route.as_ref().unwrap();
        assert!(r.ipv4_exclude.iter().any(|s| s == "1.1.1.1/32"));
        assert!(r.ipv4_exclude.iter().any(|s| s == "192.168.0.0/16"));
        let got = crate::inbound::tun_plan::linux_ipv4_install_list(
            &r.ipv4,
            &r.ipv4_exclude,
            true,
        )
        .unwrap();
        assert!(!got.iter().any(|s| s == "0.0.0.0/0"));
    }

    #[cfg(feature = "client-route")]
    fn host_covered_by_linux_list(got: &[String], host: std::net::Ipv4Addr) -> bool {
        got.iter().any(|s| {
            let (a, bits) = crate::inbound::tun_plan::parse_v4_prefix(s).unwrap();
            let mask = if bits == 0 { 0 } else { !0u32 << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(host) & mask)
        })
    }

    #[test]
    fn fill_only_apply_exclude_false_omitted_or_present() {
        for extra in [
            "",
            "  route: {}\n",
            "  route:\n    ipv4Exclude: [10.0.0.0/8]\n",
        ] {
            let y = parse_client_yaml(&format!(
                "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n{extra}"
            ))
            .unwrap();
            let app = fill_client(&y).expect("fill");
            let t = app.tun.expect("tun");
            assert!(
                !t.apply_exclude,
                "--no-client-route / fill only must leave apply_exclude false (extra={extra:?})"
            );
            if extra.is_empty() {
                assert!(t.route.is_none(), "omitted route must stay None");
            } else {
                let r = t.route.as_ref().expect("route present");
                let got = crate::inbound::tun_plan::linux_ipv4_install_list(
                    &r.ipv4,
                    &r.ipv4_exclude,
                    t.apply_exclude,
                )
                .unwrap();
                assert_eq!(got, vec!["0.0.0.0/0".to_string()]);
            }
        }
    }

    #[cfg(feature = "client-route")]
    #[test]
    fn merge_bypass_tun_into_omitted_and_empty_route() {
        let router = hy_route::compile(
            "[General]\nbypass-tun = 10.0.0.0/8\nskip-proxy = localhost, 192.168.0.0/16\n[Rule]\nFINAL,PROXY\n",
            None,
        )
        .unwrap();
        let cidrs = router.tun_exclude_cidrs();
        assert!(cidrs.iter().any(|(ip, p)| {
            *ip == std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)) && *p == 8
        }));
        for yaml in [
            "server: 127.0.0.1:1\nauth: x\ntun: { name: hy0 }\n",
            "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n  route: {}\n",
        ] {
            let y = parse_client_yaml(yaml).unwrap();
            let mut app = fill_client(&y).unwrap();
            merge_tun_exclude(&mut app.tun, &cidrs);
            let t = app.tun.as_ref().unwrap();
            assert!(t.apply_exclude, "routing ON must apply exclude ({yaml})");
            let r = t.route.as_ref().expect("default route when omitted");
            assert!(r.ipv4_exclude.iter().any(|s| s == "10.0.0.0/8"));
            assert!(r.ipv4_exclude.iter().any(|s| s == "192.168.0.0/16"));
            let got = crate::inbound::tun_plan::linux_ipv4_install_list(
                &r.ipv4,
                &r.ipv4_exclude,
                t.apply_exclude,
            )
            .unwrap();
            assert!(!got.is_empty());
            assert!(
                !got.iter().any(|s| s == "0.0.0.0/0" || s == "10.0.0.0/8"),
                "install list must subtract bypass, got {got:?}"
            );
            assert!(
                !host_covered_by_linux_list(&got, std::net::Ipv4Addr::new(10, 1, 2, 3)),
                "10.1.2.3 must not fall in any installed prefix: {got:?}"
            );
            assert!(
                !host_covered_by_linux_list(&got, std::net::Ipv4Addr::new(192, 168, 1, 1)),
                "skip-proxy 192.168.0.0/16 must be subtracted: {got:?}"
            );
        }
    }

    #[test]
    fn parse_client_route_file_yaml() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\nroute:\n  file: /etc/hy/sr_cnip.conf\n",
        )
        .unwrap();
        assert_eq!(
            y.route.as_ref().and_then(|r| r.file.as_deref()),
            Some("/etc/hy/sr_cnip.conf")
        );
        fill_client(&y).expect("route.file is optional and must not fail fill");
    }

    #[test]
    fn fill_tun_custom_timeout_and_ipv4() {
        let y = parse_client_yaml(
            r#"
server: 127.0.0.1:1
auth: x
tun:
  name: hy0
  timeout: 60s
  address:
    ipv4: 10.0.0.2/24
"#,
        )
        .unwrap();
        let app = fill_client(&y).expect("custom tun should fill");
        let t = app.tun.expect("tun");
        assert_eq!(t.timeout, Duration::from_secs(60));
        assert_eq!(t.ipv4, "10.0.0.2/24");
    }

    #[test]
    fn fill_tun_bad_ipv4() {
        assert_eq!(
            client_field("tun:\n  name: hy0\n  address:\n    ipv4: not-an-ip\n"),
            "tun.address.ipv4"
        );
    }

    #[test]
    fn fill_accepts_hop() {
        let y = parse_client_yaml("server: 1.1.1.1:443,444\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("hop server should succeed");
        assert_eq!(app.core.server_addr.unwrap().port(), 443);
        assert!(app.core.conn_factory.is_some());
    }

    #[test]
    fn fill_accepts_ipv6_hop() {
        let y = parse_client_yaml("server: \"[::1]:443,444\"\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("ipv6 hop should fill");
        assert_eq!(app.core.server_addr.unwrap(), "[::1]:443".parse().unwrap());
        assert!(app.core.conn_factory.is_some());
    }

    #[test]
    fn fill_client_domain_no_hop() {
        let y = parse_client_yaml("server: localhost:443\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("localhost should fill");
        let addr = app.core.server_addr.expect("SocketAddr after fill");
        assert_eq!(addr.port(), 443);
        assert!(app.core.conn_factory.is_none());
    }

    #[test]
    fn fill_client_domain_hop() {
        let y = parse_client_yaml("server: localhost:443,444\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("localhost hop should fill");
        assert_eq!(app.core.server_addr.unwrap().port(), 443);
        assert!(app.core.conn_factory.is_some());
    }

    #[test]
    fn fill_client_bad_server_name() {
        let y = parse_client_yaml("server: no-such-host.invalid:443\nauth: x\n").unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, .. }) => assert_eq!(field, "ServerAddr"),
            Ok(_) => panic!("expected Config ServerAddr, got Ok"),
            Err(e) => panic!("expected Config ServerAddr, got Err({e})"),
        }
    }

    #[test]
    fn fill_client_sni_empty_uses_original_host() {
        let y = parse_client_yaml("server: localhost:443\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("fill");
        assert_eq!(app.core.tls.server_name, "localhost");
    }

    #[test]
    fn fill_client_sni_set_is_kept() {
        let y = parse_client_yaml("server: localhost:443\nauth: x\ntls:\n  sni: example.com\n")
            .unwrap();
        let app = fill_client(&y).expect("fill");
        assert_eq!(app.core.tls.server_name, "example.com");
    }

    #[test]
    fn fill_hop_interval_ok() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:443,444\nauth: x\ntransport:\n  udp:\n    hopInterval: 30s\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("hopInterval should succeed");
        assert!(app.core.conn_factory.is_some());
    }

    #[test]
    fn tc_cfg_03_client_rejects() {
        // gecko is implemented (P5.B2); must not reject as unimplemented.
        // hopInterval is implemented (P5.B1); must not reject.
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntransport:\n  udp:\n    hopInterval: 30s\n")
            .unwrap();
        fill_client(&y).expect("hopInterval alone should fill");
        assert_eq!(client_field("realm: {}"), "realm");
        match fill_client(
            &parse_client_yaml("server: 127.0.0.1:1\nauth: x\nrealm: {}\n").unwrap(),
        ) {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "realm");
                assert!(
                    !reason.contains("not implemented"),
                    "reason={reason}"
                );
            }
            other => panic!(
                "expected realm URL missing Config, got {}",
                match &other {
                    Ok(_) => "Ok".into(),
                    Err(e) => format!("Err({e})"),
                }
            ),
        }
        // realm URL + realm yaml must not reject as "not implemented"
        let y = parse_client_yaml(
            "server: realm://t@127.0.0.1:9/id\nauth: x\nrealm: { stunTimeout: 5s }\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("realm URL should fill");
        assert!(app.core.conn_factory.is_some());
        assert!(app.core.server_addr_slot.is_some());
        // mimic is implemented (P5.E4); disabled/empty must fill, not "not implemented".
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\nmimic: {}\n").unwrap();
        fill_client(&y).expect("mimic: {} should fill");
        // tun is implemented (P5.D3); must fill, not reject as unimplemented.
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntun: { name: hy0 }\n").unwrap();
        fill_client(&y).expect("tun: { name: hy0 } should fill");
        // tcpTProxy / udpTProxy empty listen is a config error, not "not implemented".
        for extra in ["tcpTProxy: {}", "udpTProxy: {}"] {
            let y = parse_client_yaml(&format!("server: 127.0.0.1:1\nauth: x\n{extra}\n")).unwrap();
            match fill_client(&y) {
                Err(Error::Config { field, reason }) => {
                    assert!(
                        field.starts_with("tcpTProxy") || field.starts_with("udpTProxy"),
                        "field={field} reason={reason}"
                    );
                    assert!(
                        !reason.contains("not implemented"),
                        "field={field} reason={reason}"
                    );
                }
                _ => panic!("expected empty-listen Config for {extra}"),
            }
        }
        // tcpRedirect empty listen is a config error, not "not implemented".
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntcpRedirect: {}\n").unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.starts_with("tcpRedirect"),
                    "field={field} reason={reason}"
                );
                assert!(
                    !reason.contains("not implemented"),
                    "field={field} reason={reason}"
                );
            }
            _ => panic!("expected empty-listen Config"),
        }
        assert_eq!(client_field("tls: { ech: {} }"), "tls.ech");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fill_tcp_tproxy_listen_ok() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\ntcpTProxy:\n  listen: 127.0.0.1:0\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("tcpTProxy listen should fill");
        assert!(app.tcp_tproxy.is_some());
        assert_eq!(
            app.tcp_tproxy.as_ref().unwrap().listen.as_deref(),
            Some("127.0.0.1:0")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fill_udp_tproxy_listen_and_timeout() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\nudpTProxy:\n  listen: 127.0.0.1:0\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("udpTProxy listen should fill");
        let u = app.udp_tproxy.as_ref().expect("udp_tproxy");
        assert_eq!(u.listen, "127.0.0.1:0");
        assert_eq!(u.timeout, Duration::from_secs(60));

        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\nudpTProxy:\n  listen: 127.0.0.1:0\n  timeout: 30s\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("udpTProxy timeout should fill");
        assert_eq!(
            app.udp_tproxy.as_ref().unwrap().timeout,
            Duration::from_secs(30)
        );
    }

    #[test]
    fn fill_tcp_tproxy_empty_listen() {
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntcpTProxy: {}\n").unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.starts_with("tcpTProxy"),
                    "field={field} reason={reason}"
                );
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(field, "tcpTProxy.listen");
                    assert!(reason.contains("empty"), "{reason}");
                }
                #[cfg(not(target_os = "linux"))]
                {
                    assert_eq!(field, "tcpTProxy");
                    assert!(reason.contains("not supported"), "{reason}");
                }
            }
            _ => panic!("expected Config"),
        }
    }

    #[test]
    fn fill_udp_tproxy_empty_listen() {
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\nudpTProxy: {}\n").unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.starts_with("udpTProxy"),
                    "field={field} reason={reason}"
                );
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(field, "udpTProxy.listen");
                    assert!(reason.contains("empty"), "{reason}");
                }
                #[cfg(not(target_os = "linux"))]
                {
                    assert_eq!(field, "udpTProxy");
                    assert!(reason.contains("not supported"), "{reason}");
                }
            }
            _ => panic!("expected Config"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fill_tcp_redirect_listen_ok() {
        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\ntcpRedirect:\n  listen: 127.0.0.1:0\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("tcpRedirect listen should fill");
        assert!(app.tcp_redirect.is_some());
        assert_eq!(
            app.tcp_redirect.as_ref().unwrap().listen.as_deref(),
            Some("127.0.0.1:0")
        );
    }

    #[test]
    fn fill_tcp_redirect_empty_listen() {
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntcpRedirect: {}\n").unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, reason }) => {
                assert!(
                    field.starts_with("tcpRedirect"),
                    "field={field} reason={reason}"
                );
                #[cfg(target_os = "linux")]
                {
                    assert_eq!(field, "tcpRedirect.listen");
                    assert!(reason.contains("empty"), "{reason}");
                }
                #[cfg(not(target_os = "linux"))]
                {
                    assert_eq!(field, "tcpRedirect");
                    assert!(reason.contains("not supported"), "{reason}");
                }
            }
            _ => panic!("expected Config"),
        }
    }

    #[test]
    fn fill_gecko_client_and_server() {
        let y = parse_client_yaml(
            r#"
server: 127.0.0.1:18443
auth: x
obfs:
  type: gecko
  gecko:
    password: secret
"#,
        )
        .unwrap();
        let app = fill_client(&y).expect("gecko client should fill");
        assert!(app.core.conn_factory.is_some());

        let dir = std::env::temp_dir().join(format!("hy-gecko-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n").unwrap();
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
obfs:
  type: gecko
  gecko:
    password: secret
"#,
            cert.display(),
            key.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt.block_on(fill_server(&y)).expect("gecko server should fill");
        assert!(app.core.conn.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fill_gecko_invalid_minmax() {
        assert_eq!(
            client_field(
                "obfs:\n  type: gecko\n  gecko:\n    password: secret\n    minPacketSize: 100\n    maxPacketSize: 50\n"
            ),
            "obfs.gecko"
        );
    }

    fn server_field(extra: &str) -> String {
        let y = parse_server_yaml(&format!(
            "listen: 127.0.0.1:0\ntls: {{ cert: t.crt, key: t.key }}\nauth: {{ type: password, password: test }}\n{extra}\n"
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, reason }) => format!("{field}:{reason}"),
            other => panic!(
                "expected Config for extra={extra:?}, got {}",
                match &other {
                    Ok(_) => "Ok(ServerApp)".into(),
                    Err(e) => format!("Err({e})"),
                }
            ),
        }
    }

    #[test]
    fn tc_cfg_04_server_rejects() {
        // Helper also sets tls → mutual exclusion with acme.
        let acme = server_field("acme: {}");
        assert!(acme.starts_with("tls:"), "{acme}");
        assert!(acme.contains("cannot set both"), "{acme}");
        let ech = server_field("ech: {}");
        assert!(ech.starts_with("ech:"), "{ech}");
        let y = parse_server_yaml(
            "listen: 127.0.0.1:0\ntls: { cert: t.crt, key: t.key, ech: true }\nauth: { type: password, password: test }\n",
        )
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "tls.ech", "{field}:{reason}");
                assert!(reason.contains("not implemented"), "{reason}");
            }
            other => panic!("expected tls.ech reject, got {}", match &other { Ok(_) => "Ok".into(), Err(e) => format!("Err({e})") }),
        }
        let y = parse_server_yaml(
            "listen: 127.0.0.1:0\ntls: { cert: t.crt, key: t.key, ech: { key: dummy } }\nauth: { type: password, password: test }\n",
        )
        .unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, .. }) => assert_eq!(field, "tls.ech"),
            other => panic!("expected tls.ech.key reject, got {}", match &other { Ok(_) => "Ok".into(), Err(e) => format!("Err({e})") }),
        }
        // sniff.enable / resolver doh|https are implemented (P5.A1/A2) — must not reject as unimplemented.
        // P5.A3: socks5/http outbounds are implemented; bare type without addr/url may error on empty field.
        let s5 = server_field("outbounds:\n  - name: p\n    type: socks5");
        assert!(!s5.contains("not implemented"), "{s5}");
        assert!(s5.starts_with("outbounds.socks5.addr:"), "{s5}");
        let http = server_field("outbounds:\n  - name: p\n    type: http");
        assert!(!http.contains("not implemented"), "{http}");
        assert!(http.starts_with("outbounds.http.url:"), "{http}");
        let mf = server_field("masquerade: { type: file }");
        assert!(!mf.contains("not implemented"), "{mf}");
        assert!(mf.starts_with("masquerade.file.dir:"), "{mf}");
        let mp = server_field("masquerade: { type: proxy }");
        assert!(!mp.contains("not implemented"), "{mp}");
        assert!(mp.starts_with("masquerade.proxy.url:"), "{mp}");
        let lh = server_field("masquerade: { listenHTTP: ':80' }");
        assert!(!lh.contains("not implemented"), "{lh}");
        let lhs = server_field("masquerade: { listenHTTPS: ':443' }");
        assert!(!lhs.contains("not implemented"), "{lhs}");
        let realm = server_field("realm: {}");
        assert!(realm.starts_with("realm:"), "{realm}");
        assert!(!realm.contains("not implemented"), "{realm}");
        // mimic is implemented (P5.E4); fill of empty/disabled is covered in mimic.rs.
        // enabled without path still errors on mimic.path *before* TLS file reads.
        let mimic = server_field("mimic: { enabled: true }");
        assert!(
            mimic.contains("path") && !mimic.contains("not implemented"),
            "{mimic}"
        );
    }

    #[test]
    fn fill_client_realm_url_wires_factory() {
        let y = parse_client_yaml(
            "server: realm://t@127.0.0.1:9/id\nauth: x\nrealm: { stunTimeout: 1s, punchTimeout: 1s }\n",
        )
        .unwrap();
        let app = fill_client(&y).expect("realm URL should fill without STUN");
        assert!(app.core.conn_factory.is_some());
        assert!(app.core.server_addr_slot.is_some());
        assert_eq!(app.core.tls.server_name, "127.0.0.1");
    }

    fn server_field_no_tls(extra: &str) -> String {
        let y = parse_server_yaml(&format!(
            "listen: 127.0.0.1:0\nauth: {{ type: password, password: test }}\n{extra}\n"
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, reason }) => format!("{field}:{reason}"),
            other => panic!(
                "expected Config for extra={extra:?}, got {}",
                match &other {
                    Ok(_) => "Ok(ServerApp)".into(),
                    Err(e) => format!("Err({e})"),
                }
            ),
        }
    }

    #[test]
    fn acme_mutual_exclusion_and_validation() {
        // both tls + acme
        let both = server_field(
            "acme:\n  domains: [example.com]\n  email: a@b.c\n  type: http\n",
        );
        assert!(both.starts_with("tls:"), "{both}");
        assert!(both.contains("cannot set both"), "{both}");

        // neither
        let neither = server_field_no_tls("");
        assert!(neither.starts_with("tls:"), "{neither}");
        assert!(neither.contains("must set either"), "{neither}");

        // dns type
        let dns = server_field_no_tls(
            "acme:\n  domains: [example.com]\n  email: a@b.c\n  type: dns\n  dns: { name: cloudflare, config: { cloudflare_api_token: x } }\n",
        );
        assert!(
            dns.starts_with("acme.dns:") || dns.contains("unimplemented"),
            "{dns}"
        );

        // empty domains
        let empty = server_field_no_tls("acme:\n  domains: []\n  email: a@b.c\n  type: http\n");
        assert!(empty.starts_with("acme.domains:"), "{empty}");
        assert!(empty.contains("empty domains"), "{empty}");

        let missing = server_field_no_tls("acme:\n  email: a@b.c\n  type: http\n");
        assert!(missing.starts_with("acme.domains:"), "{missing}");
        assert!(missing.contains("empty domains"), "{missing}");
    }

    #[test]
    fn acme_cache_first_fill() {
        let dir = std::env::temp_dir().join(format!(
            "hy-acme-fill-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_bytes =
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let key_bytes = b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n";
        std::fs::write(dir.join("cert.pem"), cert_bytes).unwrap();
        std::fs::write(dir.join("key.pem"), key_bytes).unwrap();

        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
auth: {{ type: password, password: test }}
acme:
  domains: [example.com]
  email: a@b.c
  type: http
  dir: {}
"#,
            dir.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt.block_on(fill_server(&y)).expect("acme cache fill");
        assert_eq!(app.core.tls.cert_pem, cert_bytes);
        assert_eq!(app.core.tls.key_pem, key_bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolver_udp_yaml_deserializes() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
resolver:
  type: udp
  udp: { addr: "8.8.8.8:53", timeout: 5s }
"#,
        )
        .unwrap();
        let r = y.resolver.as_ref().unwrap();
        assert_eq!(r.ty.as_deref(), Some("udp"));
        assert_eq!(r.udp.as_ref().unwrap().addr.as_deref(), Some("8.8.8.8:53"));
        assert_eq!(r.udp.as_ref().unwrap().timeout.as_deref(), Some("5s"));
    }

    #[test]
    fn resolver_https_doh_fill_not_unimplemented() {
        let dir = std::env::temp_dir().join(format!("hy-res-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n").unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (ty, extra) in [
            ("https", "https: { addr: \"1.1.1.1/dns-query\", sni: cloudflare-dns.com, insecure: true }"),
            ("doh", "https: { addr: \"https://1.1.1.1/dns-query\", insecure: true }"),
            ("udp", "udp: { addr: \"8.8.8.8:53\" }"),
        ] {
            let y = parse_server_yaml(&format!(
                "listen: 127.0.0.1:0\ntls: {{ cert: {}, key: {} }}\nauth: {{ type: password, password: test }}\nresolver:\n  type: {ty}\n  {extra}\n",
                cert.display(),
                key.display()
            ))
            .unwrap();
            let app = rt.block_on(fill_server(&y)).unwrap_or_else(|e| panic!("type {ty}: {e:?}"));
            assert!(app.core.outbound.is_some());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn traffic_stats_deserializes() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
trafficStats: { listen: 127.0.0.1:19999, secret: s3cret }
"#,
        )
        .unwrap();
        let ts = y.traffic_stats.unwrap();
        assert_eq!(ts.listen.as_deref(), Some("127.0.0.1:19999"));
        assert_eq!(ts.secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn official_yaml_deserializes() {
        let server = include_str!("/workspace/hysteria/app/cmd/server_test.yaml");
        let y = parse_server_yaml(server).expect("official server_test.yaml");
        let inline = y.acl.as_ref().and_then(|a| a.inline.as_deref()).unwrap_or("");
        assert!(inline.contains("lmao(ok)"), "{inline}");
        assert!(inline.contains("kek(cringe,boba,tea)"), "{inline}");
        let acl = y.acl.as_ref().expect("acl");
        assert_eq!(acl.geoip.as_deref(), Some("some.dat"));
        assert_eq!(acl.geosite.as_deref(), Some("some_site.dat"));
        assert_eq!(acl.geo_update_interval.as_deref(), Some("168h"));
        let client = include_str!("/workspace/hysteria/app/cmd/client_test.yaml");
        let c = parse_client_yaml(client).expect("official client_test.yaml");
        assert_eq!(c.lazy, Some(true));
        let m = c.mimic.expect("official client mimic block");
        assert_eq!(m.enabled, Some(true));
        assert_eq!(m.xdp_mode.as_deref(), Some("skb"));
        assert_eq!(m.path.as_deref(), Some("/usr/bin/mimic"));
        assert_eq!(
            m.extra_args.as_deref(),
            Some(["--padding".to_string(), "random".to_string()].as_slice())
        );
    }

    #[test]
    fn acl_inline_sequence() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
acl:
  inline:
    - lmao(ok)
    - kek(cringe,boba,tea)
"#,
        )
        .unwrap();
        let inline = y.acl.unwrap().inline.unwrap();
        assert_eq!(inline, "lmao(ok)
kek(cringe,boba,tea)");
    }

    #[test]
    fn tls_client_ca_and_cert_deserialize() {
        let s = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key, clientCA: client-ca.crt }
auth: { type: password, password: test }
"#,
        )
        .unwrap();
        assert_eq!(s.tls.unwrap().client_ca.as_deref(), Some("client-ca.crt"));
        let c = parse_client_yaml(
            r#"
server: 127.0.0.1:1
auth: x
tls:
  insecure: true
  clientCertificate: client.crt
  clientKey: client.key
"#,
        )
        .unwrap();
        let t = c.tls.unwrap();
        assert_eq!(t.client_certificate.as_deref(), Some("client.crt"));
        assert_eq!(t.client_key.as_deref(), Some("client.key"));
    }

    #[test]
    fn fill_keeps_lazy() {
        let y = parse_client_yaml("server: 127.0.0.1:1
auth: x
lazy: true
").unwrap();
        let app = fill_client(&y).unwrap();
        assert!(app.lazy);
    }

    #[test]
    fn masq_string_builds_handler() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
masquerade:
  type: string
  string:
    content: aint nothin here
    headers:
      content-type: text/plain
    statusCode: 418
"#,
        )
        .unwrap();
        let m = y.masquerade.as_ref().unwrap();
        assert_eq!(m.ty.as_deref(), Some("string"));
        let s = m.string.as_ref().unwrap();
        assert_eq!(s.content.as_deref(), Some("aint nothin here"));
        assert_eq!(s.status_code, Some(418));
        let h = StringMasq::new(
            s.status_code.or(s.status).unwrap_or(0),
            s.headers
                .as_ref()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            s.content.clone().unwrap_or_default().into_bytes(),
        );
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let r = rt.block_on(hy_core::server::MasqHandler::handle(&h, "GET", "x", "/"));
        assert_eq!(r.status, 418);
        assert_eq!(r.body.as_ref(), b"aint nothin here");
    }

    #[test]
    fn masq_yaml_file_proxy_listen_http_force_https() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
masquerade:
  type: file
  file:
    dir: /var/www
  proxy:
    url: https://example.com
    rewriteHost: true
    xForwarded: true
    insecure: true
  listenHTTP: 127.0.0.1:8080
  listenHTTPS: 127.0.0.1:8443
  forceHTTPS: true
"#,
        )
        .unwrap();
        let m = y.masquerade.as_ref().unwrap();
        assert_eq!(m.ty.as_deref(), Some("file"));
        assert_eq!(m.file.as_ref().unwrap().dir.as_deref(), Some("/var/www"));
        let p = m.proxy.as_ref().unwrap();
        assert_eq!(p.url.as_deref(), Some("https://example.com"));
        assert_eq!(p.rewrite_host, Some(true));
        assert_eq!(p.x_forwarded, Some(true));
        assert_eq!(p.insecure, Some(true));
        assert_eq!(m.listen_http.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(m.listen_https.as_deref(), Some("127.0.0.1:8443"));
        assert_eq!(m.force_https, Some(true));
    }

    #[tokio::test]
    async fn fill_file_masq_and_listen_http_alt_svc() {
        let dir = std::env::temp_dir().join(format!("hy-masq-fill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"fill-body").unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        // Minimal placeholders — fill only reads bytes; listenHTTP does not need valid TLS.
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
            .unwrap();

        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
masquerade:
  type: file
  file:
    dir: {}
  listenHTTP: 127.0.0.1:0
"#,
            cert.display(),
            key.display(),
            dir.display()
        ))
        .unwrap();
        let app = fill_server(&y).await.expect("fill_server masq file");
        assert!(app.core.masq_handler.is_some());
        let masq = app.masq_tcp.expect("masq_tcp");
        let http_addr = app.masq_listen_http.expect("listenHTTP");
        let bound = masq.listen_http(http_addr).await.unwrap();

        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        let text = String::from_utf8_lossy(&resp);
        assert!(text.contains("fill-body"), "{text}");
        assert!(text.contains("h3=\":"), "{text}");
        assert!(text.contains("ma=2592000"), "{text}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn speed_test_true_wraps_outbound() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
speedTest: true
"#,
        )
        .unwrap();
        assert_eq!(y.speed_test, Some(true));
        let ob = build_outbound(&y).unwrap();
        let mut stream = ob.tcp("@SpeedTest:0").await.unwrap();
        let req = [0x01u8, 0x00, 0x00, 0x00, 0x40];
        assert_eq!(stream.write(&req).await.unwrap(), 5);
        let mut hdr = [0u8; 5];
        let mut off = 0;
        while off < 5 {
            let n = stream.read(&mut hdr[off..]).await.unwrap();
            assert!(n > 0);
            off += n;
        }
        assert_eq!(hdr[0], 0);
        assert_eq!(&hdr[3..], b"OK");
        let mut data = [0u8; 64];
        off = 0;
        while off < 64 {
            let n = stream.read(&mut data[off..]).await.unwrap();
            assert!(n > 0);
            off += n;
        }
    }

    #[tokio::test]
    async fn speed_test_absent_does_not_intercept() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
"#,
        )
        .unwrap();
        assert!(y.speed_test.is_none() || y.speed_test == Some(false));
        let ob = build_outbound(&y).unwrap();
        // Without SpeedtestHandler, @SpeedTest goes to Direct and fails to resolve/dial.
        let err = match ob.tcp("@SpeedTest:0").await {
            Err(e) => e,
            Ok(_) => panic!("expected dial failure without speedTest"),
        };
        match err {
            Error::Dial(s) => assert!(!s.contains("tcp only"), "{s}"),
            other => panic!("expected Dial, got {other:?}"),
        }
    }

    #[test]
    fn sniff_yaml_deserializes() {
        let y = parse_server_yaml(
            r#"
listen: 127.0.0.1:1
tls: { cert: t.crt, key: t.key }
auth: { type: password, password: test }
sniff:
  enable: true
  timeout: 1s
  rewriteDomain: true
  tcpPorts: 80,443,1000-2000
  udpPorts: 443
"#,
        )
        .unwrap();
        let s = y.sniff.unwrap();
        assert_eq!(s.enable, Some(true));
        assert_eq!(s.timeout.as_deref(), Some("1s"));
        assert_eq!(s.rewrite_domain, Some(true));
        assert_eq!(s.tcp_ports.as_deref(), Some("80,443,1000-2000"));
        assert_eq!(s.udp_ports.as_deref(), Some("443"));
    }

    #[test]
    fn sniff_enable_fill_sets_request_hook() {
        let dir = std::env::temp_dir().join(format!("hy-sniff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n").unwrap();
        let y = parse_server_yaml(&format!(
            "listen: 127.0.0.1:0\ntls: {{ cert: {}, key: {} }}\nauth: {{ type: password, password: test }}\nsniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: true\n  tcpPorts: 80,443\n",
            cert.display(),
            key.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt.block_on(fill_server(&y)).expect("fill_server with sniff");
        assert!(app.core.request_hook.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outbounds_socks5_http_fill_succeeds() {
        let dir = std::env::temp_dir().join(format!("hy-ob-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n").unwrap();
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
outbounds:
  - name: p
    type: socks5
    socks5: {{ addr: "127.0.0.1:1080" }}
  - name: h
    type: http
    http: {{ url: "http://127.0.0.1:8080" }}
"#,
            cert.display(),
            key.display()
        ))
        .unwrap();
        assert_eq!(y.outbounds.as_ref().unwrap().len(), 2);
        assert_eq!(
            y.outbounds.as_ref().unwrap()[0]
                .socks5
                .as_ref()
                .unwrap()
                .addr
                .as_deref(),
            Some("127.0.0.1:1080")
        );
        assert_eq!(
            y.outbounds.as_ref().unwrap()[1]
                .http
                .as_ref()
                .unwrap()
                .url
                .as_deref(),
            Some("http://127.0.0.1:8080")
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt
            .block_on(fill_server(&y))
            .unwrap_or_else(|e| panic!("fill socks5/http: {e:?}"));
        assert!(app.core.outbound.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn dummy_tls_dir(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "hy-geo-fill-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("t.crt");
        let key = dir.join("t.key");
        std::fs::write(&cert, b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
            .unwrap();
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n")
            .unwrap();
        (dir, cert, key)
    }

    #[test]
    fn fill_server_acl_no_geo_rules() {
        let (dir, cert, key) = dummy_tls_dir("nogeo");
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
acl:
  inline: "direct(*)\n"
  geoUpdateInterval: 168h
"#,
            cert.display(),
            key.display()
        ))
        .unwrap();
        assert_eq!(
            y.acl.as_ref().unwrap().geo_update_interval.as_deref(),
            Some("168h")
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt
            .block_on(fill_server(&y))
            .unwrap_or_else(|e| panic!("fill no geo: {e:?}"));
        assert!(app.core.outbound.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fill_server_acl_explicit_bad_geo_path() {
        let (dir, cert, key) = dummy_tls_dir("badgeo");
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
acl:
  inline: "reject(geoip:cn)\n"
  geoip: /no/such/hy-geoip-missing.dat
"#,
            cert.display(),
            key.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        match rt.block_on(fill_server(&y)) {
            Err(Error::Config { field, reason }) => {
                assert_eq!(field, "acl");
                assert!(!reason.is_empty(), "{reason}");
            }
            Ok(_) => panic!("expected acl config error, got success"),
            Err(e) => panic!("expected acl config error, got {e:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fill_server_acl_explicit_good_dat() {
        let (dir, cert, key) = dummy_tls_dir("goodgeo");
        let dat = dir.join("geoip.dat");
        std::fs::write(&dat, crate::geoloader::tiny_geoip_dat()).unwrap();
        let y = parse_server_yaml(&format!(
            r#"
listen: 127.0.0.1:0
tls: {{ cert: {}, key: {} }}
auth: {{ type: password, password: test }}
acl:
  inline: "reject(geoip:cn)\ndirect(*)\n"
  geoip: {}
"#,
            cert.display(),
            key.display(),
            dat.display()
        ))
        .unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let app = rt
            .block_on(fill_server(&y))
            .unwrap_or_else(|e| panic!("fill good geo: {e:?}"));
        assert!(app.core.outbound.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
