mod acme;
mod bps;
mod config;
mod geoloader;
mod inbound;
mod listen;
#[cfg(feature = "client-route")]
mod marked_udp;
mod mimic;
mod policy_route;
mod route_glue;

use clap::{Parser, Subcommand};
use config::{fill_client, fill_server, parse_client_yaml, parse_server_yaml};
use hy_core::client::{self, Client};
use hy_core::server;
use hy_core::Error;
use route_glue::{FlowDial, PassthroughDial};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "hy", about = "Hysteria 2 (Rust)")]
struct Cli {
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Client {
        /// Disable client routing (passthrough to the main server).
        #[arg(long = "no-client-route")]
        no_client_route: bool,
        /// Local Shadowrocket-style rules file.
        #[arg(long = "route", value_name = "PATH")]
        route: Option<PathBuf>,
        /// GeoIP database for `--route` (default: cwd geoip.dat / geoloader).
        #[arg(long = "route-geoip", value_name = "PATH")]
        route_geoip: Option<PathBuf>,
        /// Linux DIRECT / QUIC `SO_MARK` (hex, default 0x162). Ignored on non-Linux.
        #[arg(long = "route-fwmark", value_name = "HEX")]
        route_fwmark: Option<String>,
        /// Comma-separated DoH URLs and `ip` / `ip:53`. Wins over conf `dns-server`.
        #[arg(long = "route-dns", value_name = "LIST")]
        route_dns: Option<String>,
        /// Do not intercept TUN dest port 53 (no stub).
        #[arg(long = "route-no-hijack-dns")]
        route_no_hijack_dns: bool,
        /// Do not peek TCP 443 ClientHello SNI (default: peek when routing is on).
        #[arg(long = "route-no-sniff")]
        route_no_sniff: bool,
        /// Do not answer TUN ICMP echo (default: reply when routing is on).
        #[arg(long = "route-no-icmp-reply")]
        route_no_icmp_reply: bool,
    },
    Server,
    Version,
}

#[tokio::main]
async fn main() {
    let level = std::env::var("HYSTERIA_LOG_LEVEL").unwrap_or_else(|_| "info".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_writer(std::io::stderr)
        .try_init();

    let cli = Cli::parse();
    let r = match cli.cmd {
        Some(Cmd::Version) => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(Cmd::Server) => run_server(cli.config.as_ref()).await,
        Some(Cmd::Client {
            no_client_route,
            route,
            route_geoip,
            route_fwmark,
            route_dns,
            route_no_hijack_dns,
            route_no_sniff,
            route_no_icmp_reply,
        }) => {
            run_client(
                cli.config.as_ref(),
                no_client_route,
                route.as_ref(),
                route_geoip.as_ref(),
                route_fwmark.as_deref(),
                route_dns.as_deref(),
                route_no_hijack_dns,
                route_no_sniff,
                route_no_icmp_reply,
            )
            .await
        }
        None => {
            run_client(
                cli.config.as_ref(),
                false,
                None,
                None,
                None,
                None,
                false,
                false,
                false,
            )
            .await
        }
    };
    if let Err(e) = r {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn read_cfg(path: Option<&PathBuf>) -> Result<String, Error> {
    let p = path.ok_or_else(|| Error::config("config", "missing -c"))?;
    std::fs::read_to_string(p).map_err(|e| Error::config("config", e.to_string()))
}

async fn shutdown_signal() -> Result<(), Error> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(Error::Io)?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r.map_err(Error::Io)?,
            _ = term.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(Error::Io)
    }
}

/// `--no-client-route` wins. If `--route` is also set, warn then still disable.
/// Command line `--route` wins over `route.file` in client.yaml.
fn resolve_route_file(
    no_client_route: bool,
    route: Option<&Path>,
    yaml_file: Option<&str>,
) -> Option<PathBuf> {
    if no_client_route {
        if route.is_some() {
            tracing::warn!("--route ignored because --no-client-route is set");
        }
        tracing::info!("client-route disabled by flag");
        return None;
    }
    if let Some(p) = route {
        return Some(p.to_path_buf());
    }
    yaml_file
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

#[cfg(feature = "client-route")]
fn load_route_geoip(explicit: Option<&Path>) -> Result<hy_extras::acl::GeoIpMap, Error> {
    use hy_extras::acl::{load_geoip_file, GeoLoader};
    if let Some(p) = explicit {
        return load_geoip_file(p).map_err(|e| Error::config("route-geoip", e));
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let default_path = cwd.join(geoloader::GEOIP_FILENAME);
    if default_path.is_file() {
        if let Ok(m) = load_geoip_file(&default_path) {
            return Ok(m);
        }
    }
    let loader = geoloader::AppGeoLoader::new(
        None,
        None,
        Duration::ZERO,
        Arc::new(geoloader::DefaultHttp),
        cwd,
    );
    loader
        .load_geoip()
        .map_err(|e| Error::config("route-geoip", e))
}

#[cfg(feature = "client-route")]
struct PreparedRoute {
    router: hy_route::Router,
    direct: hy_route::DirectDialer,
    dns_cache: std::sync::Arc<hy_route::dns::DnsCache>,
    dns: Option<std::sync::Arc<hy_route::dns::DnsStub>>,
    sni_peek: bool,
    icmp_reply: bool,
}

/// Punch stub upstream IPv4 `/32`s on Darwin TUN only. Linux uses fwmark.
#[cfg(feature = "client-route")]
fn merge_darwin_stub_tun_exclude(
    tun: &mut Option<config::TunConfig>,
    cidrs: &[(std::net::IpAddr, u8)],
    is_darwin: bool,
) {
    if !is_darwin || cidrs.is_empty() {
        return;
    }
    config::merge_tun_exclude(tun, cidrs);
    let punched: Vec<String> = cidrs
        .iter()
        .map(|(ip, pfx)| format!("{ip}/{pfx}"))
        .collect();
    tracing::info!(
        excludes = %punched.join(","),
        magnet = hy_route::darwin_dns::MAGNET_DNS,
        "darwin stub DNS TUN exclude"
    );
}

/// Resolve route file, compile, inject marked QUIC factory + policy routing.
/// Must run before `connect_reconnectable`.
#[cfg(feature = "client-route")]
fn prepare_client_route(
    app: &mut config::ClientApp,
    no_client_route: bool,
    route: Option<&Path>,
    route_geoip: Option<&Path>,
    yaml_file: Option<&str>,
    route_fwmark: Option<&str>,
    route_dns: Option<&str>,
    route_no_hijack_dns: bool,
    route_no_sniff: bool,
    route_no_icmp_reply: bool,
    darwin_a_only: bool,
) -> Result<Option<PreparedRoute>, Error> {
    let Some(path) = resolve_route_file(no_client_route, route, yaml_file) else {
        return Ok(None);
    };
    let geo = load_route_geoip(route_geoip)?;
    let router = hy_route::compile_file(&path, Some(&geo))
        .map_err(|e| Error::config("route", e.to_string()))?;
    tracing::info!(path = %path.display(), "client-route enabled");

    let fwmark = crate::policy_route::parse_fwmark(route_fwmark)
        .map_err(|e| Error::config("route-fwmark", e))?;
    let direct =
        hy_route::DirectDialer::new(fwmark).map_err(|e| Error::config("route", e.to_string()))?;

    let marked = std::sync::Arc::new(crate::marked_udp::MarkedUdpFactory::new(direct.clone()));
    let kind = crate::marked_udp::mark_kind_from_app(app);
    crate::marked_udp::inject_marked_udp(&mut app.core, marked, kind);

    let dns_cache = std::sync::Arc::new(hy_route::dns::DnsCache::new());
    let mut stub_excl: Vec<(std::net::IpAddr, u8)> = Vec::new();
    let dns = if route_no_hijack_dns {
        None
    } else {
        let specs =
            hy_route::dns::resolve_server_list(route_dns, router.dns_servers(), darwin_a_only)
                .map_err(|e| Error::config("route-dns", e.to_string()))?;
        let (upstreams, excl) = hy_route::dns::build_upstreams_with_exclude(&specs, direct.clone())
            .map_err(|e| Error::config("route-dns", e.to_string()))?;
        stub_excl = excl;
        Some(std::sync::Arc::new(
            hy_route::dns::DnsStub::new(std::sync::Arc::clone(&dns_cache), upstreams)
                .with_aaaa_nodata(darwin_a_only),
        ))
    };

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = crate::policy_route::install_linux_policy_routing(fwmark) {
            tracing::error!("{e}");
            eprintln!("{e}");
            return Err(Error::config("route", e.to_string()));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fwmark;
    }

    config::merge_tun_exclude(&mut app.tun, &router.tun_exclude_cidrs());
    // Darwin: punch stub DoH/plain IPv4 /32s so DirectDialer IP_BOUND_IF can reach them.
    // Linux already has fwmark; do not add these CIDRs.
    merge_darwin_stub_tun_exclude(&mut app.tun, &stub_excl, cfg!(target_os = "macos"));
    Ok(Some(PreparedRoute {
        router,
        direct,
        dns_cache,
        dns,
        sni_peek: !route_no_sniff,
        icmp_reply: !route_no_icmp_reply,
    }))
}

fn build_flow_dial(
    client: Arc<dyn Client>,
    #[cfg(feature = "client-route")] prepared: Option<PreparedRoute>,
) -> Arc<dyn FlowDial> {
    #[cfg(not(feature = "client-route"))]
    {
        return Arc::new(PassthroughDial { client });
    }
    #[cfg(feature = "client-route")]
    {
        match prepared {
            Some(PreparedRoute {
                router,
                direct,
                dns_cache,
                dns: _,
                sni_peek: _,
                icmp_reply: _,
            }) => Arc::new(route_glue::RouteDial {
                router,
                client,
                direct,
                dns_cache,
            }),
            None => Arc::new(PassthroughDial { client }),
        }
    }
}

/// :53 stub + optional Darwin `networksetup` NIC. No route file still hijacks on Darwin a-only.
/// Does not enable decide / DIRECT / ICMP / fwmark (FlowDial stays passthrough when `prepared` is None).
#[cfg(feature = "client-route")]
fn tun_dns_hijack(
    prepared: Option<&PreparedRoute>,
    darwin_a_only: bool,
    route_no_hijack_dns: bool,
    route_dns: Option<&str>,
) -> Result<(Option<Arc<dyn inbound::tun::DnsAnswerer>>, Option<String>), Error> {
    if !hy_route::dns::want_tun_dns_stub(prepared.is_some(), route_no_hijack_dns, darwin_a_only) {
        return Ok((None, None));
    }
    if let Some(p) = prepared {
        let iface = if darwin_a_only {
            p.direct.iface().map(|s| s.to_string())
        } else {
            None
        };
        let dns = p
            .dns
            .clone()
            .map(|s| s as Arc<dyn inbound::tun::DnsAnswerer>);
        return Ok((dns, iface));
    }
    let direct = hy_route::DirectDialer::new(hy_route::DEFAULT_FWMARK)
        .map_err(|e| Error::config("tun", e.to_string()))?;
    let iface = direct.iface().map(|s| s.to_string());
    let stub = hy_route::dns::build_dns_stub(
        std::sync::Arc::new(hy_route::dns::DnsCache::new()),
        route_dns,
        &[],
        direct,
        true,
    )
    .map_err(|e| Error::config("route-dns", e.to_string()))?;
    Ok((Some(Arc::new(stub)), iface))
}

async fn run_client(
    path: Option<&PathBuf>,
    no_client_route: bool,
    route: Option<&PathBuf>,
    route_geoip: Option<&PathBuf>,
    route_fwmark: Option<&str>,
    route_dns: Option<&str>,
    route_no_hijack_dns: bool,
    route_no_sniff: bool,
    route_no_icmp_reply: bool,
) -> Result<(), Error> {
    let y = parse_client_yaml(&read_cfg(path)?)?;
    let mut app = fill_client(&y)?;
    let _mimic = app.start()?;
    let lazy = app.lazy;
    let yaml_route = y.route.as_ref().and_then(|r| r.file.as_deref());

    #[cfg(feature = "client-route")]
    let darwin_a_only = hy_route::dns::darwin_a_only_mode(
        cfg!(target_os = "macos"),
        app.tun.is_some(),
        app.tun.as_ref().and_then(|t| t.ipv6.as_ref()).is_some(),
    );
    #[cfg(not(feature = "client-route"))]
    let darwin_a_only = false;
    let _ = darwin_a_only;

    #[cfg(feature = "client-route")]
    let prepared = prepare_client_route(
        &mut app,
        no_client_route,
        route.map(|p| p.as_path()),
        route_geoip.map(|p| p.as_path()),
        yaml_route,
        route_fwmark,
        route_dns,
        route_no_hijack_dns,
        route_no_sniff,
        route_no_icmp_reply,
        darwin_a_only,
    )?;
    #[cfg(not(feature = "client-route"))]
    {
        let _ = (
            no_client_route,
            route,
            route_geoip,
            yaml_route,
            route_fwmark,
            route_dns,
            route_no_hijack_dns,
            route_no_sniff,
            route_no_icmp_reply,
        );
        let _ = resolve_route_file(no_client_route, route.map(|p| p.as_path()), yaml_route);
    }

    let cli = client::connect_reconnectable(app.core, lazy).await?;
    if lazy {
        tracing::info!("lazy: connect on first inbound");
    } else {
        tracing::info!("connected");
    }
    #[cfg(feature = "client-route")]
    let (dns_hijack, darwin_dns_device) = tun_dns_hijack(
        prepared.as_ref(),
        darwin_a_only,
        route_no_hijack_dns,
        route_dns,
    )?;
    #[cfg(not(feature = "client-route"))]
    let dns_hijack: Option<Arc<dyn inbound::tun::DnsAnswerer>> = None;
    #[cfg(not(feature = "client-route"))]
    let darwin_dns_device: Option<String> = None;
    #[cfg(feature = "client-route")]
    let sni_peek = prepared.as_ref().map(|p| p.sni_peek).unwrap_or(false);
    #[cfg(not(feature = "client-route"))]
    let sni_peek = false;
    #[cfg(feature = "client-route")]
    let icmp_reply = prepared.as_ref().map(|p| p.icmp_reply).unwrap_or(false);
    #[cfg(not(feature = "client-route"))]
    let icmp_reply = false;
    #[cfg(feature = "client-route")]
    let dial = build_flow_dial(Arc::clone(&cli), prepared);
    #[cfg(not(feature = "client-route"))]
    let dial = build_flow_dial(Arc::clone(&cli));
    let mut tasks = Vec::new();
    if let Some(s) = app.socks5.take() {
        let c = Arc::clone(&dial);
        tasks.push(tokio::spawn(
            async move { inbound::socks5::run(&s, c).await },
        ));
    }
    if let Some(h) = app.http.take() {
        let c = Arc::clone(&dial);
        tasks.push(tokio::spawn(async move { inbound::http::run(&h, c).await }));
    }
    for f in app.tcp_fwd {
        let c = Arc::clone(&cli);
        let listen = f.listen.unwrap_or_default();
        let remote = f.remote.unwrap_or_default();
        tasks.push(tokio::spawn(async move {
            inbound::forward::run_tcp(&listen, &remote, c).await
        }));
    }
    for f in app.udp_fwd {
        let c = Arc::clone(&cli);
        let listen = f.listen.unwrap_or_default();
        let remote = f.remote.unwrap_or_default();
        let to = f
            .timeout
            .as_deref()
            .and_then(|s| s.strip_suffix('s')?.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(60));
        tasks.push(tokio::spawn(async move {
            inbound::forward::run_udp(&listen, &remote, to, c).await
        }));
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = app.tcp_redirect.take() {
        let listen = r.listen.unwrap_or_default();
        let c = Arc::clone(&cli);
        tasks.push(tokio::spawn(async move {
            inbound::redirect::run(&listen, c).await
        }));
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = app.tcp_tproxy.take() {
        let listen = r.listen.unwrap_or_default();
        let c = Arc::clone(&cli);
        tasks.push(tokio::spawn(async move {
            inbound::tproxy_tcp::run(&listen, c).await
        }));
    }
    #[cfg(target_os = "linux")]
    if let Some(r) = app.udp_tproxy.take() {
        let listen = r.listen;
        let timeout = r.timeout;
        let c = Arc::clone(&cli);
        tasks.push(tokio::spawn(async move {
            inbound::tproxy_udp::run(&listen, timeout, c).await
        }));
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(t) = app.tun.take() {
        let c = Arc::clone(&dial);
        let dns = dns_hijack;
        #[cfg(target_os = "macos")]
        {
            let iface = darwin_dns_device;
            tasks.push(tokio::spawn(async move {
                inbound::tun::run(t, c, dns, sni_peek, icmp_reply, iface).await
            }));
        }
        #[cfg(target_os = "linux")]
        {
            let _ = darwin_dns_device;
            tasks.push(tokio::spawn(async move {
                inbound::tun::run(t, c, dns, sni_peek, icmp_reply).await
            }));
        }
    } else {
        let _ = dns_hijack;
        let _ = sni_peek;
        let _ = icmp_reply;
        let _ = darwin_dns_device;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = dns_hijack;
        let _ = sni_peek;
        let _ = icmp_reply;
        let _ = darwin_dns_device;
    }
    if tasks.is_empty() {
        tracing::warn!("no inbound configured");
        shutdown_signal().await?;
        return cli.close().await;
    }
    tokio::select! {
        r = futures_select(&mut tasks) => {
            let _ = cli.close().await;
            r.0
        }
        _ = shutdown_signal() => {
            tracing::info!("SIGINT, closing client");
            for t in &tasks {
                t.abort();
            }
            cli.close().await
        }
    }
}

async fn run_server(path: Option<&PathBuf>) -> Result<(), Error> {
    let y = parse_server_yaml(&read_cfg(path)?)?;
    let mut app = fill_server(&y).await?;
    let _mimic = app.start()?;
    app.core.fill()?;
    if let Some((addr, ts)) = app.traffic.clone() {
        tracing::info!("trafficStats listen {addr}");
        tokio::spawn(async move {
            if let Err(e) = ts.serve(addr).await {
                tracing::error!("trafficStats: {e}");
            }
        });
    }
    if let Some(masq) = app.masq_tcp.clone() {
        if let Some(addr) = app.masq_listen_http {
            tracing::info!("masquerade listenHTTP {addr}");
            let m = Arc::clone(&masq);
            tokio::spawn(async move {
                if let Err(e) = m.listen_http(addr).await {
                    tracing::error!("masquerade listenHTTP: {e}");
                }
            });
        }
        if let Some(addr) = app.masq_listen_https {
            tracing::info!("masquerade listenHTTPS {addr}");
            let m = Arc::clone(&masq);
            tokio::spawn(async move {
                if let Err(e) = m.listen_https(addr).await {
                    tracing::error!("masquerade listenHTTPS: {e}");
                }
            });
        }
    }
    let srv = server::serve(app.core).await?;
    tracing::info!("server listening");
    tokio::select! {
        r = srv.serve() => r,
        _ = shutdown_signal() => srv.close().await,
    }
}

async fn futures_select(
    tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) -> (
    Result<(), Error>,
    usize,
    Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) {
    if tasks.is_empty() {
        return (Ok(()), 0, Vec::new());
    }
    futures_select_inner(tasks).await
}

async fn futures_select_inner(
    tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) -> (
    Result<(), Error>,
    usize,
    Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) {
    let r = futures_next(tasks).await;
    (r, 0, Vec::new())
}

async fn futures_next(
    tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) -> Result<(), Error> {
    let (idx, res) = {
        let (res, idx, _rest) = select_all_join(tasks).await;
        (idx, res)
    };
    let _ = idx;
    match res {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(Error::Closed(Some(e.to_string()))),
    }
}

async fn select_all_join(
    tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) -> (Result<Result<(), Error>, tokio::task::JoinError>, usize, ()) {
    loop {
        for (i, t) in tasks.iter_mut().enumerate() {
            if t.is_finished() {
                return (t.await, i, ());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    #[test]
    fn client_accepts_no_client_route() {
        let c = Cli::try_parse_from(["hy", "client", "--no-client-route", "-c", "client.yaml"])
            .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                no_client_route,
                route,
                route_geoip,
                route_fwmark,
                route_dns,
                route_no_hijack_dns,
                route_no_sniff,
                route_no_icmp_reply,
            }) => {
                assert!(no_client_route);
                assert!(route.is_none());
                assert!(route_geoip.is_none());
                assert!(route_fwmark.is_none());
                assert!(route_dns.is_none());
                assert!(!route_no_hijack_dns);
                assert!(!route_no_sniff);
                assert!(!route_no_icmp_reply);
            }
            other => panic!("expected Client, got {other:?}"),
        }
        assert_eq!(
            c.config.as_deref(),
            Some(std::path::Path::new("client.yaml"))
        );
    }

    #[test]
    fn client_accepts_route_path() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "--route",
            "/tmp/sr_cnip.conf",
            "-c",
            "client.yaml",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                no_client_route,
                route,
                route_geoip,
                route_fwmark,
                route_dns,
                route_no_hijack_dns,
                route_no_sniff,
                route_no_icmp_reply,
            }) => {
                assert!(!no_client_route);
                assert_eq!(
                    route.as_deref(),
                    Some(std::path::Path::new("/tmp/sr_cnip.conf"))
                );
                assert!(route_geoip.is_none());
                assert!(route_fwmark.is_none());
                assert!(route_dns.is_none());
                assert!(!route_no_hijack_dns);
                assert!(!route_no_sniff);
                assert!(!route_no_icmp_reply);
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn client_accepts_no_client_route_and_route_together() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--no-client-route",
            "--route",
            "rules.conf",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                no_client_route,
                route,
                route_geoip,
                route_fwmark,
                route_dns,
                route_no_hijack_dns,
                route_no_sniff,
                route_no_icmp_reply,
            }) => {
                assert!(no_client_route);
                assert_eq!(route.as_deref(), Some(std::path::Path::new("rules.conf")));
                assert!(route_geoip.is_none());
                assert!(route_fwmark.is_none());
                assert!(route_dns.is_none());
                assert!(!route_no_hijack_dns);
                assert!(!route_no_sniff);
                assert!(!route_no_icmp_reply);
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn client_accepts_route_geoip() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--route",
            "r.conf",
            "--route-geoip",
            "/tmp/geoip.dat",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client { route_geoip, .. }) => {
                assert_eq!(
                    route_geoip.as_deref(),
                    Some(std::path::Path::new("/tmp/geoip.dat"))
                );
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn resolve_route_file_cli_wins_over_yaml() {
        let p = resolve_route_file(false, Some(Path::new("/cli.conf")), Some("/yaml.conf"));
        assert_eq!(p.as_deref(), Some(Path::new("/cli.conf")));
        let p = resolve_route_file(false, None, Some("/yaml.conf"));
        assert_eq!(p.as_deref(), Some(Path::new("/yaml.conf")));
        let p = resolve_route_file(false, None, None);
        assert!(p.is_none());
    }

    #[test]
    fn no_client_route_and_route_warns_then_disables() {
        struct Make(Arc<Mutex<Vec<u8>>>);
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Make {
            type Writer = Writer;
            fn make_writer(&'a self) -> Self::Writer {
                Writer(self.0.clone())
            }
        }
        impl Write for Writer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(Make(buf.clone()))
            .finish();
        let chosen = tracing::subscriber::with_default(subscriber, || {
            resolve_route_file(true, Some(Path::new("rules.conf")), Some("/yaml.conf"))
        });
        assert!(chosen.is_none(), "must still disable routing");
        let logs = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("--route ignored because --no-client-route is set"),
            "{logs}"
        );
        assert!(logs.contains("client-route disabled by flag"), "{logs}");
    }

    #[cfg(feature = "client-route")]
    #[test]
    fn load_route_geoip_explicit_fixture_no_download() {
        let dir = std::env::temp_dir().join(format!(
            "hy-app-geoip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("geoip.dat");
        std::fs::write(&p, crate::geoloader::tiny_geoip_dat()).unwrap();
        let m = load_route_geoip(Some(&p)).unwrap();
        assert!(m.contains_key("cn"), "fixture country must be present");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_accepts_route_fwmark() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--route-fwmark",
            "0x162",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client { route_fwmark, .. }) => {
                assert_eq!(route_fwmark.as_deref(), Some("0x162"));
            }
            other => panic!("expected Client, got {other:?}"),
        }
        assert_eq!(
            crate::policy_route::parse_fwmark(Some("0x162")).unwrap(),
            0x162
        );
    }

    #[test]
    fn client_accepts_route_dns_and_no_hijack() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--route-dns",
            "https://dns.google/dns-query,1.1.1.1",
            "--route-no-hijack-dns",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                route_dns,
                route_no_hijack_dns,
                route_no_sniff,
                ..
            }) => {
                assert_eq!(
                    route_dns.as_deref(),
                    Some("https://dns.google/dns-query,1.1.1.1")
                );
                assert!(route_no_hijack_dns);
                assert!(!route_no_sniff);
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn client_accepts_route_no_sniff() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--route",
            "r.conf",
            "--route-no-sniff",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                route_no_sniff,
                route,
                ..
            }) => {
                assert!(route_no_sniff);
                assert_eq!(route.as_deref(), Some(std::path::Path::new("r.conf")));
            }
            other => panic!("expected Client, got {other:?}"),
        }
        let c = Cli::try_parse_from(["hy", "client", "-c", "client.yaml"]).unwrap();
        match c.cmd {
            Some(Cmd::Client { route_no_sniff, .. }) => {
                assert!(!route_no_sniff, "peek ON by default (flag absent)");
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn client_accepts_route_no_icmp_reply() {
        let c = Cli::try_parse_from([
            "hy",
            "client",
            "-c",
            "client.yaml",
            "--route",
            "r.conf",
            "--route-no-icmp-reply",
        ])
        .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                route_no_icmp_reply,
                route,
                ..
            }) => {
                assert!(route_no_icmp_reply);
                assert_eq!(route.as_deref(), Some(std::path::Path::new("r.conf")));
            }
            other => panic!("expected Client, got {other:?}"),
        }
        let c = Cli::try_parse_from(["hy", "client", "-c", "client.yaml"]).unwrap();
        match c.cmd {
            Some(Cmd::Client {
                route_no_icmp_reply,
                ..
            }) => {
                assert!(
                    !route_no_icmp_reply,
                    "echo reply ON by default when routing is on (flag absent)"
                );
            }
            other => panic!("expected Client, got {other:?}"),
        }
    }

    #[test]
    fn no_client_route_no_mark_no_exclude_install() {
        assert!(
            resolve_route_file(true, Some(Path::new("r.conf")), None).is_none(),
            "--no-client-route must not enable routing"
        );
        for yaml in [
            "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n  route:\n    ipv4Exclude: [10.0.0.0/8]\n",
            "server: 127.0.0.1:1\nauth: x\ntun: { name: hy0 }\n",
        ] {
            let y = parse_client_yaml(yaml).unwrap();
            let app = fill_client(&y).unwrap();
            let t = app.tun.expect("tun");
            assert!(
                !t.apply_exclude,
                "--no-client-route / fill must leave exclude ignored"
            );
            if let Some(route) = t.route.as_ref() {
                let got = crate::inbound::tun_plan::linux_ipv4_install_list(
                    &route.ipv4,
                    &route.ipv4_exclude,
                    t.apply_exclude,
                )
                .unwrap();
                assert_eq!(got, vec!["0.0.0.0/0".to_string()]);
            } else {
                assert!(t.route.is_none());
            }
            assert!(app.core.conn_factory.is_none());
        }
    }

    #[cfg(feature = "client-route")]
    #[test]
    fn darwin_without_route_constructs_stub_linux_does_not() {
        let y = parse_client_yaml("server: 127.0.0.1:1\nauth: x\ntun: { name: hy0 }\n").unwrap();
        let app = fill_client(&y).unwrap();
        let tun = app.tun.as_ref().expect("tun");
        let linux = hy_route::dns::darwin_a_only_mode(false, true, tun.ipv6.is_some());
        assert!(
            !hy_route::dns::want_tun_dns_stub(false, false, linux),
            "Linux without a route file must not hijack :53"
        );
        let darwin = hy_route::dns::darwin_a_only_mode(true, true, false);
        assert!(
            hy_route::dns::want_tun_dns_stub(false, false, darwin),
            "Darwin TUN without address.ipv6 must hijack :53 without a route file"
        );
        assert!(!hy_route::dns::want_tun_dns_stub(
            false,
            false,
            hy_route::dns::darwin_a_only_mode(true, true, true)
        ));

        let (dns, iface) = tun_dns_hijack(None, false, false, None).unwrap();
        assert!(dns.is_none(), "Linux: no stub without route file");
        assert!(iface.is_none());

        let (dns, _iface) = tun_dns_hijack(None, true, false, None).unwrap();
        assert!(
            dns.is_some(),
            "Darwin a-only constructs :53 stub without route"
        );

        let (dns, _) = tun_dns_hijack(None, true, true, None).unwrap();
        assert!(dns.is_none(), "--route-no-hijack-dns");
    }

    #[cfg(feature = "client-route")]
    fn pin_ali_dohpub(host: &str, _port: u16) -> Result<std::net::IpAddr, hy_route::Error> {
        use std::net::{IpAddr, Ipv4Addr};
        Ok(IpAddr::V4(if host.contains("alidns") {
            Ipv4Addr::new(223, 5, 5, 5)
        } else {
            Ipv4Addr::new(1, 12, 0, 1)
        }))
    }

    #[cfg(feature = "client-route")]
    #[test]
    fn darwin_stub_exclude_ali_dohpub_not_magnet() {
        use std::net::{IpAddr, Ipv4Addr};
        let specs = [
            hy_route::dns::ResolverSpec::Doh {
                url: "https://dns.alidns.com/dns-query".into(),
            },
            hy_route::dns::ResolverSpec::Doh {
                url: "https://doh.pub/dns-query".into(),
            },
        ];
        let cidrs = hy_route::dns::stub_upstream_exclude_cidrs(&specs, pin_ali_dohpub);
        assert!(cidrs.contains(&(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), 32)));
        assert!(cidrs.contains(&(IpAddr::V4(Ipv4Addr::new(1, 12, 0, 1)), 32)));
        assert!(!cidrs.contains(&(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 32)));
        assert_eq!(hy_route::darwin_dns::MAGNET_DNS, "1.1.1.1");

        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n  route: {}\n",
        )
        .unwrap();
        let mut app = fill_client(&y).unwrap();
        merge_darwin_stub_tun_exclude(&mut app.tun, &cidrs, false);
        let linux = app.tun.as_ref().unwrap();
        assert!(
            linux
                .route
                .as_ref()
                .map(|r| r.ipv4_exclude.is_empty())
                .unwrap_or(true),
            "Linux must not punch stub /32s"
        );
        assert!(!linux.apply_exclude);

        merge_darwin_stub_tun_exclude(&mut app.tun, &cidrs, true);
        let t = app.tun.as_ref().unwrap();
        assert!(t.apply_exclude);
        let r = t.route.as_ref().unwrap();
        assert!(r.ipv4_exclude.iter().any(|s| s == "223.5.5.5/32"));
        assert!(r.ipv4_exclude.iter().any(|s| s == "1.12.0.1/32"));
        assert!(
            !r.ipv4_exclude.iter().any(|s| s == "1.1.1.1/32"),
            "magnet must stay inside TUN: {:?}",
            r.ipv4_exclude
        );
        let got = crate::inbound::tun_plan::darwin_ipv4_install_list(&r.ipv4, &r.ipv4_exclude)
            .unwrap();
        let covers = |host: Ipv4Addr| {
            got.iter().any(|(a, bits)| {
                let mask = if *bits == 0 { 0 } else { !0u32 << (32 - bits) };
                (u32::from(*a) & mask) == (u32::from(host) & mask)
            })
        };
        assert!(!covers(Ipv4Addr::new(223, 5, 5, 5)), "Ali DoH must be a hole: {got:?}");
        assert!(!covers(Ipv4Addr::new(1, 12, 0, 1)), "doh.pub must be a hole: {got:?}");
        assert!(covers(Ipv4Addr::new(1, 1, 1, 1)), "magnet 1.1.1.1 must still enter utun: {got:?}");
    }

    #[cfg(feature = "client-route")]
    #[test]
    fn darwin_stub_exclude_rewritten_magnet_doh_is_ali() {
        use std::net::{IpAddr, Ipv4Addr};
        let specs = [hy_route::dns::ResolverSpec::Doh {
            url: "https://1.1.1.1/dns-query".into(),
        }];
        let cidrs = hy_route::dns::stub_upstream_exclude_cidrs(&specs, |_, _| {
            Err(hy_route::Error::Dns("must not lookup".into()))
        });
        assert!(cidrs.contains(&(IpAddr::V4(hy_route::dns::ALI_DOH_ANYCAST), 32)));
        assert!(!cidrs.contains(&(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 32)));
        assert_eq!(hy_route::darwin_dns::MAGNET_DNS, "1.1.1.1");

        let y = parse_client_yaml(
            "server: 127.0.0.1:1\nauth: x\ntun:\n  name: hy0\n  route: {}\n",
        )
        .unwrap();
        let mut app = fill_client(&y).unwrap();
        merge_darwin_stub_tun_exclude(&mut app.tun, &cidrs, true);
        let r = app.tun.as_ref().unwrap().route.as_ref().unwrap();
        assert!(r.ipv4_exclude.iter().any(|s| s == "223.5.5.5/32"));
        assert!(!r.ipv4_exclude.iter().any(|s| s == "1.1.1.1/32"));
    }

    #[test]
    fn hy_version_still_0_0_2() {
        assert_eq!(env!("CARGO_PKG_VERSION"), "0.0.2");
    }
}
