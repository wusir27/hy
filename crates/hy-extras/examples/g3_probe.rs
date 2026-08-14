//! Connect and optionally TCP/UDP echo. HY_SERVER HY_AUTH HY_OBFS HY_ECHO HY_UECHO HY_REJECT

use async_trait::async_trait;
use hy_core::client::{self, Config, TlsConfig};
use hy_core::io::{ConnFactory, DatagramIo, StdUdp};
use hy_core::Error;
use hy_extras::obfs::ObfsSalamander;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

struct SalFactory {
    psk: Vec<u8>,
}

#[async_trait]
impl ConnFactory for SalFactory {
    async fn open(&self, _server: SocketAddr) -> Result<Arc<dyn DatagramIo>, Error> {
        let std = StdUdp::bind("0.0.0.0:0".parse().unwrap())
            .await
            .map_err(Error::Io)?;
        Ok(Arc::new(ObfsSalamander::new(Arc::new(std), &self.psk)?))
    }
}

#[tokio::main]
async fn main() {
    if env::args().any(|a| a == "--psk-short") {
        match ObfsSalamander::new(
            Arc::new(StdUdp::bind("127.0.0.1:0".parse().unwrap()).await.unwrap()),
            b"ab",
        ) {
            Err(e) => {
                println!("PSK_SHORT {e}");
                return;
            }
            Ok(_) => {
                println!("PSK_SHORT_ACCEPTED");
                std::process::exit(2);
            }
        }
    }

    let server: SocketAddr = env::var("HY_SERVER")
        .unwrap_or_else(|_| "127.0.0.1:18443".into())
        .parse()
        .unwrap();
    let auth = env::var("HY_AUTH").unwrap_or_else(|_| "test".into());
    let mut c = Config::default();
    c.server_addr = Some(server);
    c.auth = auth;
    let insecure = env::var("HY_INSECURE").unwrap_or_else(|_| "1".into()) != "0";
    let ca_pem = env::var("HY_CA")
        .ok()
        .map(|p| std::fs::read(p).expect("read ca"))
        .unwrap_or_default();
    c.tls = TlsConfig {
        server_name: env::var("HY_SNI").unwrap_or_else(|_| "localhost".into()),
        insecure_skip_verify: insecure,
        ca_pem,
        ..Default::default()
    };
    c.bandwidth.max_tx = 12_500_000;
    c.bandwidth.max_rx = 12_500_000;
    if let Ok(psk) = env::var("HY_OBFS") {
        if !psk.is_empty() {
            c.conn_factory = Some(Arc::new(SalFactory {
                psk: psk.into_bytes(),
            }));
        }
    }

    match client::connect(c).await {
        Ok((cli, info)) => {
            println!(
                "OK udp_enabled={} tx={} server={}",
                info.udp_enabled, info.tx, info.server_addr
            );
            if let Ok(dest) = env::var("HY_ECHO") {
                match cli.tcp(&dest).await {
                    Ok(mut t) => {
                        t.write(b"hello").await.unwrap();
                        let mut out = [0u8; 5];
                        let mut n = 0;
                        while n < 5 {
                            n += t.read(&mut out[n..]).await.unwrap();
                        }
                        println!("TCP {}", if &out == b"hello" { "MATCH" } else { "MISMATCH" });
                        let _ = t.close().await;
                    }
                    Err(e) => println!("TCP_ERR {e}"),
                }
            }
            if let Ok(dest) = env::var("HY_REJECT") {
                match cli.tcp(&dest).await {
                    Ok(_) => println!("REJECT_OPENED"),
                    Err(e) => println!("REJECT_ERR {e}"),
                }
            }
            if let Ok(dest) = env::var("HY_UECHO") {
                match cli.udp().await {
                    Ok(mut s) => {
                        let payload: Vec<u8> = (0..1400u32).map(|i| (i % 256) as u8).collect();
                        s.send(&payload, &dest).await.unwrap();
                        match tokio::time::timeout(std::time::Duration::from_secs(5), s.receive())
                            .await
                        {
                            Ok(Ok((got, _))) => {
                                println!(
                                    "UDP len={} {}",
                                    got.len(),
                                    if got == payload { "MATCH" } else { "MISMATCH" }
                                )
                            }
                            Ok(Err(e)) => println!("UDP_ERR {e}"),
                            Err(_) => println!("UDP_TIMEOUT"),
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
