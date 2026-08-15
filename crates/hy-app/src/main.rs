mod acme;
mod bps;
mod config;
mod inbound;
mod listen;

use clap::{Parser, Subcommand};
use config::{fill_client, fill_server, parse_client_yaml, parse_server_yaml};
use hy_core::client;
use hy_core::server;
use hy_core::Error;
use std::path::PathBuf;
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
    Client,
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
        Some(Cmd::Client) | None => run_client(cli.config.as_ref()).await,
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

async fn run_client(path: Option<&PathBuf>) -> Result<(), Error> {
    let y = parse_client_yaml(&read_cfg(path)?)?;
    let mut app = fill_client(&y)?;
    let lazy = app.lazy;
    let cli = client::connect_reconnectable(app.core, lazy).await?;
    if lazy {
        tracing::info!("lazy: connect on first inbound");
    } else {
        tracing::info!("connected");
    }
    let mut tasks = Vec::new();
    if let Some(s) = app.socks5.take() {
        let c = Arc::clone(&cli);
        tasks.push(tokio::spawn(async move { inbound::socks5::run(&s, c).await }));
    }
    if let Some(h) = app.http.take() {
        let c = Arc::clone(&cli);
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
    #[cfg(target_os = "linux")]
    if let Some(t) = app.tun.take() {
        let c = Arc::clone(&cli);
        tasks.push(tokio::spawn(async move { inbound::tun::run(t, c).await }));
    }
    if tasks.is_empty() {
        tracing::warn!("no inbound configured");
        tokio::signal::ctrl_c().await.map_err(Error::Io)?;
        return cli.close().await;
    }
    tokio::select! {
        r = futures_select(&mut tasks) => {
            let _ = cli.close().await;
            r.0
        }
        _ = tokio::signal::ctrl_c() => {
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
        _ = tokio::signal::ctrl_c() => srv.close().await,
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
