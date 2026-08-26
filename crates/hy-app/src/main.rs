mod acme;
mod bps;
mod config;
mod geoloader;
mod inbound;
mod listen;
mod mimic;
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
        }) => run_client(
            cli.config.as_ref(),
            no_client_route,
            route.as_ref(),
            route_geoip.as_ref(),
        )
        .await,
        None => run_client(cli.config.as_ref(), false, None, None).await,
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

fn build_flow_dial(
    client: Arc<dyn Client>,
    no_client_route: bool,
    route: Option<&Path>,
    route_geoip: Option<&Path>,
    yaml_file: Option<&str>,
) -> Result<Arc<dyn FlowDial>, Error> {
    let route_file = resolve_route_file(no_client_route, route, yaml_file);
    #[cfg(not(feature = "client-route"))]
    {
        let _ = (route_file, route_geoip);
        return Ok(Arc::new(PassthroughDial { client }));
    }
    #[cfg(feature = "client-route")]
    {
        let Some(path) = route_file else {
            return Ok(Arc::new(PassthroughDial { client }));
        };
        let geo = load_route_geoip(route_geoip)?;
        let router = hy_route::compile_file(&path, Some(&geo))
            .map_err(|e| Error::config("route", e.to_string()))?;
        tracing::info!(path = %path.display(), "client-route enabled");
        Ok(Arc::new(route_glue::RouteDial { router, client }))
    }
}

async fn run_client(
    path: Option<&PathBuf>,
    no_client_route: bool,
    route: Option<&PathBuf>,
    route_geoip: Option<&PathBuf>,
) -> Result<(), Error> {
    let y = parse_client_yaml(&read_cfg(path)?)?;
    let mut app = fill_client(&y)?;
    let _mimic = app.start()?;
    let lazy = app.lazy;
    let cli = client::connect_reconnectable(app.core, lazy).await?;
    if lazy {
        tracing::info!("lazy: connect on first inbound");
    } else {
        tracing::info!("connected");
    }
    let yaml_route = y.route.as_ref().and_then(|r| r.file.as_deref());
    let dial = build_flow_dial(
        Arc::clone(&cli),
        no_client_route,
        route.map(|p| p.as_path()),
        route_geoip.map(|p| p.as_path()),
        yaml_route,
    )?;
    let mut tasks = Vec::new();
    if let Some(s) = app.socks5.take() {
        let c = Arc::clone(&dial);
        tasks.push(tokio::spawn(async move { inbound::socks5::run(&s, c).await }));
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
        tasks.push(tokio::spawn(async move { inbound::tun::run(t, c).await }));
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
) -> (Result<(), Error>, usize, Vec<tokio::task::JoinHandle<Result<(), Error>>>) {
    if tasks.is_empty() {
        return (Ok(()), 0, Vec::new());
    }
    futures_select_inner(tasks).await
}

async fn futures_select_inner(
    tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>,
) -> (Result<(), Error>, usize, Vec<tokio::task::JoinHandle<Result<(), Error>>>) {
    let r = futures_next(tasks).await;
    (r, 0, Vec::new())
}

async fn futures_next(tasks: &mut Vec<tokio::task::JoinHandle<Result<(), Error>>>) -> Result<(), Error> {
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
) -> (
    Result<Result<(), Error>, tokio::task::JoinError>,
    usize,
    (),
) {
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
        let c = Cli::try_parse_from(["hy", "client", "--no-client-route", "-c", "client.yaml"]).unwrap();
        match c.cmd {
            Some(Cmd::Client {
                no_client_route,
                route,
                route_geoip,
            }) => {
                assert!(no_client_route);
                assert!(route.is_none());
                assert!(route_geoip.is_none());
            }
            other => panic!("expected Client, got {other:?}"),
        }
        assert_eq!(c.config.as_deref(), Some(std::path::Path::new("client.yaml")));
    }

    #[test]
    fn client_accepts_route_path() {
        let c = Cli::try_parse_from(["hy", "client", "--route", "/tmp/sr_cnip.conf", "-c", "client.yaml"])
            .unwrap();
        match c.cmd {
            Some(Cmd::Client {
                no_client_route,
                route,
                route_geoip,
            }) => {
                assert!(!no_client_route);
                assert_eq!(route.as_deref(), Some(std::path::Path::new("/tmp/sr_cnip.conf")));
                assert!(route_geoip.is_none());
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
            }) => {
                assert!(no_client_route);
                assert_eq!(route.as_deref(), Some(std::path::Path::new("rules.conf")));
                assert!(route_geoip.is_none());
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
        let p = resolve_route_file(
            false,
            Some(Path::new("/cli.conf")),
            Some("/yaml.conf"),
        );
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
}

