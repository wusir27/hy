//! Official camelCase YAML. Parse is loose; fill rejects v1-unimplemented keys.

use crate::acme::{self, AcmeYaml};
use crate::bps::parse_bps;
use crate::listen::{parse_listen, parse_server};
use hy_core::client::{self as core_client};
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
use hy_extras::masq::{FileMasq, MasqTcpServer, NotFoundMasq, ProxyMasq, StringMasq};
use hy_extras::sniff::{parse_port_union, Sniffer};
use hy_extras::trafficlogger::TrafficStats;
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
    pub realm: Option<serde_yaml::Value>,
    pub mimic: Option<serde_yaml::Value>,
    pub tun: Option<serde_yaml::Value>,
    #[serde(rename = "tcpTProxy")]
    pub tcp_tproxy: Option<serde_yaml::Value>,
    #[serde(rename = "udpTProxy")]
    pub udp_tproxy: Option<serde_yaml::Value>,
    pub tcp_redirect: Option<serde_yaml::Value>,
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
    pub realm: Option<serde_yaml::Value>,
    pub mimic: Option<serde_yaml::Value>,
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
    pub lazy: bool,
}

pub fn fill_client(y: &ClientYaml) -> Result<ClientApp, Error> {
    if y.tun.is_some() {
        return Err(Error::config("tun", "not implemented"));
    }
    if y.realm.is_some() {
        return Err(Error::config("realm", "not implemented"));
    }
    if y.mimic.is_some() {
        return Err(Error::config("mimic", "not implemented"));
    }
    if y.tcp_tproxy.is_some() {
        return Err(Error::config("tcpTProxy", "not implemented"));
    }
    if y.udp_tproxy.is_some() {
        return Err(Error::config("udpTProxy", "not implemented"));
    }
    if y.tcp_redirect.is_some() {
        return Err(Error::config("tcpRedirect", "not implemented"));
    }
    if let Some(t) = &y.tls {
        if t.ech.is_some() {
            return Err(Error::config("tls.ech", "not implemented"));
        }
    }
    let hop_interval = hop_interval_from_transport(y.transport.as_ref())?;

    let server = y.server.as_deref().ok_or_else(|| Error::config("Server", "must be set"))?;
    let parsed = parse_server(server)?;

    let mut cfg = core_client::Config::default();
    cfg.server_addr = Some(parsed.addr);
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
    cfg.fast_open = y.fast_open.unwrap_or(false);

    let mut salamander_psk: Option<Vec<u8>> = None;
    let mut gecko_opts: Option<(Vec<u8>, usize, usize)> = None;
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
            // Apply defaults then validate (same rules as ObfsGecko::new).
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

    if let Some((psk, min, max)) = gecko_opts {
        let mut fac = GeckoFactory::new(psk, min, max);
        if let Some(ports) = parsed.hop_ports {
            fac = fac.with_hop(ports, hop_interval);
        }
        cfg.conn_factory = Some(Arc::new(fac));
    } else if let Some(ports) = parsed.hop_ports {
        let mut fac = UdpHopFactory::new(ports, hop_interval);
        if let Some(psk) = salamander_psk.take() {
            fac = fac.with_salamander(psk);
        }
        cfg.conn_factory = Some(Arc::new(fac));
    } else if let Some(psk) = salamander_psk {
        cfg.conn_factory = Some(Arc::new(SalamanderFactory { psk }));
    }

    Ok(ClientApp {
        core: cfg,
        socks5: y.socks5.clone(),
        http: y.http.clone(),
        tcp_fwd: y.tcp_forwarding.clone().unwrap_or_default(),
        udp_fwd: y.udp_forwarding.clone().unwrap_or_default(),
        lazy: y.lazy.unwrap_or(false),
    })
}

/// YAML hop interval (production ≥5s). Missing → 30s/30s.
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

struct SalamanderFactory {
    psk: Vec<u8>,
}

#[async_trait::async_trait]
impl hy_core::io::ConnFactory for SalamanderFactory {
    async fn open(&self, server: std::net::SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let inner = StdUdpFactory.open(server).await?;
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
    if y.realm.is_some() {
        return Err(Error::config("realm", "not implemented"));
    }
    if y.mimic.is_some() {
        return Err(Error::config("mimic", "not implemented"));
    }
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
    let bind = parse_listen(listen, "listen")?;
    let mut io: Arc<dyn DatagramIo> = Arc::new(StdUdp::bind(bind).await.map_err(Error::Io)?);
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

    Ok(ServerApp {
        core: cfg,
        traffic,
        masq_tcp,
        masq_listen_http,
        masq_listen_https,
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
        let rules = CompiledRuleSet::compile(&text).map_err(|e| Error::config("acl", e.to_string()))?;
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

    fn client_field(extra: &str) -> &'static str {
        let y = parse_client_yaml(&format!("server: 127.0.0.1:1\nauth: x\n{extra}\n")).unwrap();
        match fill_client(&y) {
            Err(Error::Config { field, .. }) => field,
            other => panic!("expected Config, got ok-or-other-err"),
        }
    }

    #[test]
    fn fill_rejects_tun() {
        assert_eq!(client_field("tun: { name: hy0 }"), "tun");
    }

    #[test]
    fn fill_accepts_hop() {
        let y = parse_client_yaml("server: 1.1.1.1:443,444\nauth: x\n").unwrap();
        let app = fill_client(&y).expect("hop server should succeed");
        assert_eq!(app.core.server_addr.unwrap().port(), 443);
        assert!(app.core.conn_factory.is_some());
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
        assert_eq!(client_field("mimic: {}"), "mimic");
        assert_eq!(client_field("tun: { name: hy0 }"), "tun");
        assert_eq!(client_field("tcpTProxy: {}"), "tcpTProxy");
        assert_eq!(client_field("udpTProxy: {}"), "udpTProxy");
        assert_eq!(client_field("tcpRedirect: {}"), "tcpRedirect");
        assert_eq!(client_field("tls: { ech: {} }"), "tls.ech");
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
        let mimic = server_field("mimic: {}");
        assert!(mimic.starts_with("mimic:"), "{mimic}");
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
        let client = include_str!("/workspace/hysteria/app/cmd/client_test.yaml");
        let c = parse_client_yaml(client).expect("official client_test.yaml");
        assert_eq!(c.lazy, Some(true));
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
}
