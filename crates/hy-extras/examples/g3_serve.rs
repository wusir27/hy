//! G3 harness: hy-core server + extras (salamander / auth / ACL) + TCP/UDP echo.
//!
//! HY_LISTEN HY_OBFS HY_AUTH=password|userpass|http|command
//! HY_PASSWORD HY_HTTP_URL HY_CMD HY_ACL

use hy_core::io::{DatagramIo, StdUdp};
use hy_core::server::{self, Config as ServerConfig, TlsConfig};
use hy_extras::acl::CompiledRuleSet;
use hy_extras::auth::{CommandAuth, HttpAuth, Password, UserPass};
use hy_extras::obfs::ObfsSalamander;
use hy_extras::outbounds::{AclEngine, Adapter, Direct, DirectMode, PluggableOutbound, SystemResolver};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[tokio::main]
async fn main() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = certified.cert.pem().into_bytes();
    let key_pem = certified.key_pair.serialize_pem().into_bytes();

    let echo = TcpListener::bind("127.0.0.1:0").await.expect("tcp echo");
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let reject_echo = TcpListener::bind("127.0.0.1:0").await.expect("reject echo");
    let reject_addr = reject_echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = reject_echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let _ = sock.read(&mut buf).await;
            });
        }
    });

    let uecho = UdpSocket::bind("127.0.0.1:0").await.expect("udp echo");
    let uecho_addr = uecho.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match uecho.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let _ = uecho.send_to(&buf[..n], peer).await;
        }
    });

    let listen: std::net::SocketAddr = std::env::var("HY_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:18443".parse().unwrap());
    let password = std::env::var("HY_PASSWORD").unwrap_or_else(|_| "test".into());
    let auth_mode = std::env::var("HY_AUTH").unwrap_or_else(|_| "password".into());
    let obfs = std::env::var("HY_OBFS").ok().filter(|s| !s.is_empty());

    let udp = StdUdp::bind(listen).await.expect("udp bind");
    let server_addr = udp.local_addr().unwrap();
    let io: Arc<dyn DatagramIo> = if let Some(ref psk) = obfs {
        Arc::new(ObfsSalamander::new(Arc::new(udp), psk.as_bytes()).expect("obfs psk"))
    } else {
        Arc::new(udp)
    };

    let authenticator: Arc<dyn hy_core::server::Authenticator> = match auth_mode.as_str() {
        "userpass" => Arc::new(UserPass::new([(
            "alice".into(),
            password.clone(),
        )])),
        "http" => Arc::new(HttpAuth {
            url: std::env::var("HY_HTTP_URL").expect("HY_HTTP_URL"),
            insecure: true,
        }),
        "command" => Arc::new(CommandAuth::new(std::env::var("HY_CMD").expect("HY_CMD"))),
        _ => Arc::new(Password(password.clone())),
    };

    let acl_text = std::env::var("HY_ACL").unwrap_or_default();
    let outbound: Arc<dyn hy_core::server::Outbound> = if acl_text.is_empty() {
        let rules = CompiledRuleSet::compile(&format!(
            "reject(127.0.0.1, tcp/{})\ndirect(*)\n",
            reject_addr.port()
        ))
        .expect("acl");
        let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
        table.insert("direct".into(), Arc::new(Direct::new(DirectMode::Auto)));
        table.insert("default".into(), Arc::new(Direct::new(DirectMode::Auto)));
        let eng = Arc::new(AclEngine::new(rules, table));
        Arc::new(Adapter(Arc::new(SystemResolver { next: eng })))
    } else {
        let rules = CompiledRuleSet::compile(&acl_text).expect("acl env");
        let mut table: HashMap<String, Arc<dyn PluggableOutbound>> = HashMap::new();
        table.insert("direct".into(), Arc::new(Direct::new(DirectMode::Auto)));
        table.insert("default".into(), Arc::new(Direct::new(DirectMode::Auto)));
        let eng = Arc::new(AclEngine::new(rules, table));
        Arc::new(Adapter(Arc::new(SystemResolver { next: eng })))
    };

    let mut scfg = ServerConfig {
        tls: TlsConfig { cert_pem: cert_pem.clone(), key_pem, ..Default::default() },
        conn: Some(io),
        authenticator: Some(authenticator),
        outbound: Some(outbound),
        disable_udp: false,
        bandwidth: hy_core::server::BandwidthConfig {
            max_tx: 12_500_000,
            max_rx: 12_500_000,
            disable_loss_compensation: false,
        },
        ..Default::default()
    };
    scfg.fill().expect("fill");
    let server = server::serve(scfg).await.expect("serve");
    let server2 = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = server2.serve().await;
    });

    println!("SERVER={server_addr}");
    println!("ECHO={echo_addr}");
    println!("REJECT={reject_addr}");
    println!("UECHO={uecho_addr}");
    println!("AUTH_MODE={auth_mode}");
    println!("OBFS={}", obfs.as_deref().unwrap_or(""));
    if let Ok(path) = std::env::var("HY_CERT_OUT") {
        std::fs::write(&path, &cert_pem).expect("write cert");
        println!("CERT_OUT={path}");
    }
    println!("ready");
    std::future::pending::<()>().await;
}
