//! Connect to a running hy-core server and print HandshakeInfo + optional UDP echo.

use hy_core::client::{self, Config, TlsConfig};
use std::env;

#[tokio::main]
async fn main() {
    let server: std::net::SocketAddr = env::var("HY_SERVER")
        .unwrap_or_else(|_| "127.0.0.1:18443".into())
        .parse()
        .expect("HY_SERVER");
    let auth = env::var("HY_AUTH").unwrap_or_else(|_| "test".into());
    let dest = env::var("HY_UECHO").ok();
    let mut c = Config::default();
    c.server_addr = Some(server);
    c.auth = auth;
    c.tls = TlsConfig {
        server_name: "localhost".into(),
        insecure_skip_verify: true,
        ..Default::default()
    };
    c.bandwidth.max_tx = env::var("HY_MAX_TX").ok().and_then(|s| s.parse().ok()).unwrap_or(12_500_000);
    c.bandwidth.max_rx = env::var("HY_MAX_RX").ok().and_then(|s| s.parse().ok()).unwrap_or(12_500_000);

    match client::connect(c).await {
        Ok((cli, info)) => {
            println!("OK udp_enabled={} tx={} server={}", info.udp_enabled, info.tx, info.server_addr);
            if let Some(dest) = dest {
                match cli.udp().await {
                    Ok(mut s) => {
                        let payload: Vec<u8> = (0..2500u32).map(|i| (i % 256) as u8).collect();
                        if let Err(e) = s.send(&payload, &dest).await {
                            println!("UDP_SEND_ERR {e}");
                        } else {
                            match tokio::time::timeout(std::time::Duration::from_secs(5), s.receive()).await {
                                Ok(Ok((got, addr))) => {
                                    println!("UDP_RECV len={} match={} addr={}", got.len(), got == payload, addr);
                                }
                                Ok(Err(e)) => println!("UDP_RECV_ERR {e}"),
                                Err(_) => println!("UDP_RECV_TIMEOUT"),
                            }
                        }
                        let _ = s.close().await;
                    }
                    Err(e) => println!("UDP_OPEN_ERR {e}"),
                }
            }
            let _ = cli.close().await;
        }
        Err(e) => {
            println!("CONNECT_ERR {e}");
            std::process::exit(2);
        }
    }
}
