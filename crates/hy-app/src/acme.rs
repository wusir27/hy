//! ACME certificate obtain (P5.C2): HTTP-01 / TLS-ALPN-01.
//!
//! Cache-first: if `{dir}/cert.pem`+`key.pem` (or `{dir}/{first-domain}/…`) exist, load them
//! without contacting a CA. Live issue uses `instant-acme` for Let's Encrypt; DNS-01 is out of scope.

use hy_core::Error;
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const ACME_DIR_ENV: &str = "HYSTERIA_ACME_DIR";
const WELL_KNOWN: &str = "/.well-known/acme-challenge/";

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeYaml {
    pub domains: Option<Vec<String>>,
    pub email: Option<String>,
    pub ca: Option<String>,
    pub listen_host: Option<String>,
    pub dir: Option<String>,
    #[serde(rename = "type")]
    pub ty: Option<String>,
    pub http: Option<AcmeHttpYaml>,
    pub tls: Option<AcmeTlsYaml>,
    pub dns: Option<AcmeDnsYaml>,
    pub disable_http: Option<bool>,
    #[serde(rename = "disableTLSALPN")]
    pub disable_tls_alpn: Option<bool>,
    #[serde(rename = "altHTTPPort")]
    pub alt_http_port: Option<u16>,
    #[serde(rename = "altTLSALPNPort")]
    pub alt_tls_alpn_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeHttpYaml {
    pub alt_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AcmeTlsYaml {
    pub alt_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AcmeDnsYaml {
    pub name: Option<String>,
    pub config: Option<HashMap<String, String>>,
}

/// Validate ACME YAML (domains / type / ca). Does not contact the network.
pub fn validate(acme: &AcmeYaml) -> Result<(), Error> {
    let domains = acme.domains.as_deref().unwrap_or(&[]);
    if domains.is_empty() || domains.iter().all(|d| d.trim().is_empty()) {
        return Err(Error::config("acme.domains", "empty domains"));
    }
    let ty = acme.ty.as_deref().unwrap_or("").to_ascii_lowercase();
    match ty.as_str() {
        "http" | "tls" | "" => {}
        "dns" => {
            // YAML is parsed (including dns.name/config); DNS-01 providers are P5.C2b.
            let _ = &acme.dns;
            return Err(Error::config("acme.dns", "unimplemented"));
        }
        _ => return Err(Error::config("acme.type", "unsupported ACME type")),
    }
    let ca = acme.ca.as_deref().unwrap_or("").to_ascii_lowercase();
    match ca.as_str() {
        "letsencrypt" | "le" | "" | "zerossl" | "zero" => {}
        _ => return Err(Error::config("acme.ca", "unsupported CA")),
    }
    Ok(())
}

fn data_dir(acme: &AcmeYaml) -> PathBuf {
    if let Some(d) = acme.dir.as_deref().filter(|s| !s.is_empty()) {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var(ACME_DIR_ENV) {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    PathBuf::from("acme")
}

fn load_pem_pair(cert: &Path, key: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
    let cert_pem = std::fs::read(cert).ok()?;
    let key_pem = std::fs::read(key).ok()?;
    if cert_pem.is_empty() || key_pem.is_empty() {
        return None;
    }
    Some((cert_pem, key_pem))
}

fn try_cache(dir: &Path, domains: &[String]) -> Option<(Vec<u8>, Vec<u8>)> {
    if let Some(pair) = load_pem_pair(&dir.join("cert.pem"), &dir.join("key.pem")) {
        return Some(pair);
    }
    if let Some(first) = domains.first() {
        let sub = dir.join(first);
        if let Some(pair) = load_pem_pair(&sub.join("cert.pem"), &sub.join("key.pem")) {
            return Some(pair);
        }
    }
    None
}

fn persist_cache(dir: &Path, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), Error> {
    std::fs::create_dir_all(dir).map_err(|e| Error::config("acme.dir", e.to_string()))?;
    std::fs::write(dir.join("cert.pem"), cert_pem)
        .map_err(|e| Error::config("acme.dir", e.to_string()))?;
    std::fs::write(dir.join("key.pem"), key_pem)
        .map_err(|e| Error::config("acme.dir", e.to_string()))?;
    Ok(())
}

fn listen_host(acme: &AcmeYaml) -> &str {
    let h = acme.listen_host.as_deref().unwrap_or("");
    if h.is_empty() {
        "0.0.0.0"
    } else {
        h
    }
}

#[derive(Clone, Copy)]
enum ChallengePlan {
    Http { port: u16 },
    Tls { port: u16 },
    Legacy {
        http_port: Option<u16>,
        tls_port: Option<u16>,
    },
}

fn challenge_plan(acme: &AcmeYaml) -> ChallengePlan {
    let ty = acme.ty.as_deref().unwrap_or("").to_ascii_lowercase();
    match ty.as_str() {
        "http" => {
            let p = acme.http.as_ref().and_then(|h| h.alt_port).unwrap_or(0);
            ChallengePlan::Http {
                port: if p == 0 { 80 } else { p },
            }
        }
        "tls" => {
            let p = acme.tls.as_ref().and_then(|t| t.alt_port).unwrap_or(0);
            ChallengePlan::Tls {
                port: if p == 0 { 443 } else { p },
            }
        }
        _ => {
            // Legacy: type empty
            let http_port = if acme.disable_http.unwrap_or(false) {
                None
            } else {
                let p = acme.alt_http_port.unwrap_or(0);
                Some(if p == 0 { 80 } else { p })
            };
            let tls_port = if acme.disable_tls_alpn.unwrap_or(false) {
                None
            } else {
                let p = acme.alt_tls_alpn_port.unwrap_or(0);
                Some(if p == 0 { 443 } else { p })
            };
            ChallengePlan::Legacy { http_port, tls_port }
        }
    }
}

fn ca_directory(acme: &AcmeYaml) -> Result<&'static str, Error> {
    let ca = acme.ca.as_deref().unwrap_or("").to_ascii_lowercase();
    match ca.as_str() {
        "letsencrypt" | "le" | "" => Ok(instant_acme::LetsEncrypt::Production.url()),
        "zerossl" | "zero" => Err(Error::config(
            "acme.ca",
            "ZeroSSL requires network EAB credentials; place cert.pem/key.pem in the ACME dir or use letsencrypt",
        )),
        _ => Err(Error::config("acme.ca", "unsupported CA")),
    }
}

/// Obtain certificate PEM bytes `(cert_pem, key_pem)`.
///
/// Cache-first: non-empty `{dir}/cert.pem` + `key.pem` (or domain subdirectory) skip the CA.
pub async fn obtain(acme: &AcmeYaml) -> Result<(Vec<u8>, Vec<u8>), Error> {
    validate(acme)?;
    let domains = acme.domains.as_ref().unwrap();
    let dir = data_dir(acme);
    if let Some(pair) = try_cache(&dir, domains) {
        return Ok(pair);
    }
    obtain_live(acme, &dir, domains)
        .await
        .map_err(|e| match e {
            Error::Config { field, reason } if field.starts_with("acme.") => {
                Error::Config { field, reason }
            }
            other => Error::config("acme.domains", other.to_string()),
        })
}

async fn obtain_live(
    acme: &AcmeYaml,
    dir: &Path,
    domains: &[String],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let directory_url = ca_directory(acme)?.to_owned();
    let plan = challenge_plan(acme);
    let host = listen_host(acme);

    let http_tokens: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    let tls_material: Arc<RwLock<Option<Arc<ServerConfig>>>> = Arc::new(RwLock::new(None));
    let mut guards: Vec<JoinHandle<()>> = Vec::new();

    let want_http = matches!(
        plan,
        ChallengePlan::Http { .. } | ChallengePlan::Legacy { http_port: Some(_), .. }
    );
    let want_tls = matches!(
        plan,
        ChallengePlan::Tls { .. } | ChallengePlan::Legacy { tls_port: Some(_), .. }
    );

    if want_http {
        let port = match plan {
            ChallengePlan::Http { port } => port,
            ChallengePlan::Legacy {
                http_port: Some(p), ..
            } => p,
            _ => 80,
        };
        let (addr, handle) = start_http01_responder(host, port, Arc::clone(&http_tokens)).await?;
        tracing::info!(%addr, "ACME HTTP-01 challenge listener");
        guards.push(handle);
    }
    if want_tls {
        let port = match plan {
            ChallengePlan::Tls { port } => port,
            ChallengePlan::Legacy {
                tls_port: Some(p), ..
            } => p,
            _ => 443,
        };
        let (addr, handle) = start_tls_alpn_responder(host, port, Arc::clone(&tls_material)).await?;
        tracing::info!(%addr, "ACME TLS-ALPN-01 challenge listener");
        guards.push(handle);
    }
    if !want_http && !want_tls {
        return Err(Error::config(
            "acme.type",
            "no ACME challenge enabled (both HTTP and TLS-ALPN disabled)",
        ));
    }

    let _guard = AbortOnDrop(guards);

    let email = acme.email.as_deref().unwrap_or("");
    let contact: Vec<String> = if email.is_empty() {
        Vec::new()
    } else {
        vec![format!("mailto:{email}")]
    };
    let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

    let (account, _creds) = instant_acme::Account::builder()
        .map_err(|e| Error::config("acme.domains", e.to_string()))?
        .create(
            &instant_acme::NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;

    let identifiers: Vec<instant_acme::Identifier> = domains
        .iter()
        .map(|d| instant_acme::Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&identifiers))
        .await
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;

    // Prefer HTTP-01 when enabled (including legacy with both); else TLS-ALPN-01.
    let use_http = match plan {
        ChallengePlan::Http { .. } => true,
        ChallengePlan::Tls { .. } => false,
        ChallengePlan::Legacy { http_port, tls_port } => {
            http_port.is_some() || tls_port.is_none()
        }
    };

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result.map_err(|e| Error::config("acme.domains", e.to_string()))?;
        match authz.status {
            instant_acme::AuthorizationStatus::Pending => {}
            instant_acme::AuthorizationStatus::Valid => continue,
            other => {
                return Err(Error::config(
                    "acme.domains",
                    format!("authorization status {other:?}"),
                ));
            }
        }

        let prefer = if use_http {
            instant_acme::ChallengeType::Http01
        } else {
            instant_acme::ChallengeType::TlsAlpn01
        };
        let mut challenge = authz.challenge(prefer).ok_or_else(|| {
            Error::config(
                "acme.domains",
                if use_http {
                    "no HTTP-01 challenge offered by CA"
                } else {
                    "no TLS-ALPN-01 challenge offered by CA"
                },
            )
        })?;

        let key_auth = challenge.key_authorization();
        if use_http {
            http_tokens
                .write()
                .await
                .insert(challenge.token.clone(), key_auth.as_str().to_owned());
        } else {
            let cfg = build_tls_alpn_config(&challenge.identifier().to_string(), &key_auth)?;
            *tls_material.write().await = Some(cfg);
        }

        challenge
            .set_ready()
            .await
            .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    }

    let status = order
        .poll_ready(&instant_acme::RetryPolicy::default())
        .await
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    if status != instant_acme::OrderStatus::Ready {
        return Err(Error::config(
            "acme.domains",
            format!("unexpected order status {status:?}"),
        ));
    }

    let private_key_pem = order
        .finalize()
        .await
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    let cert_chain_pem = order
        .poll_certificate(&instant_acme::RetryPolicy::default())
        .await
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;

    let cert_pem = cert_chain_pem.into_bytes();
    let key_pem = private_key_pem.into_bytes();
    persist_cache(dir, &cert_pem, &key_pem)?;
    Ok((cert_pem, key_pem))
}

fn build_tls_alpn_config(
    domain: &str,
    key_auth: &instant_acme::KeyAuthorization,
) -> Result<Arc<ServerConfig>, Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let digest = key_auth.digest();
    let mut params = CertificateParams::new(vec![domain.to_owned()])
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest.as_ref()));
    let key_pair = KeyPair::generate().map_err(|e| Error::config("acme.domains", e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| Error::config("acme.domains", e.to_string()))?;
    cfg.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    Ok(Arc::new(cfg))
}

struct AbortOnDrop(Vec<JoinHandle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Bind an HTTP-01 challenge responder. Returns the bound address and a task handle.
///
/// Serves `GET /.well-known/acme-challenge/{token}` → key authorization body; unknown → 404.
pub async fn start_http01_responder(
    host: &str,
    port: u16,
    challenges: Arc<RwLock<HashMap<String, String>>>,
) -> Result<(SocketAddr, JoinHandle<()>), Error> {
    let listener = TcpListener::bind((host, port))
        .await
        .map_err(|e| Error::config("acme.http", e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::config("acme.http", e.to_string()))?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let challenges = Arc::clone(&challenges);
            tokio::spawn(async move {
                let _ = handle_http01(stream, challenges).await;
            });
        }
    });
    Ok((addr, handle))
}

async fn handle_http01(
    mut stream: TcpStream,
    challenges: Arc<RwLock<HashMap<String, String>>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            let method = parts.next()?;
            let path = parts.next()?;
            if method.eq_ignore_ascii_case("GET") {
                Some(path.to_owned())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let body = if let Some(token) = path.strip_prefix(WELL_KNOWN) {
        let token = token.split('?').next().unwrap_or(token);
        challenges.read().await.get(token).cloned()
    } else {
        None
    };

    let resp = match body {
        Some(b) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            b.len(),
            b
        ),
        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_owned(),
    };
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn start_tls_alpn_responder(
    host: &str,
    port: u16,
    material: Arc<RwLock<Option<Arc<ServerConfig>>>>,
) -> Result<(SocketAddr, JoinHandle<()>), Error> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = TcpListener::bind((host, port))
        .await
        .map_err(|e| Error::config("acme.tls", e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::config("acme.tls", e.to_string()))?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let material = Arc::clone(&material);
            tokio::spawn(async move {
                let cfg = {
                    let guard = material.read().await;
                    guard.clone()
                };
                let Some(cfg) = cfg else {
                    return;
                };
                let acceptor = TlsAcceptor::from(cfg);
                let _ = acceptor.accept(stream).await;
            });
        }
    });
    Ok((addr, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http01_responder_serves_keyauth_and_404() {
        let mut map = HashMap::new();
        map.insert("good-token".into(), "key-authorization-value".into());
        let challenges = Arc::new(RwLock::new(map));
        let (addr, handle) = start_http01_responder("127.0.0.1", 0, Arc::clone(&challenges))
            .await
            .expect("bind http01");

        let body = http_get(addr, "/.well-known/acme-challenge/good-token").await;
        assert!(body.contains("200"), "{body}");
        assert!(body.contains("key-authorization-value"), "{body}");

        let miss = http_get(addr, "/.well-known/acme-challenge/missing").await;
        assert!(miss.contains("404"), "{miss}");

        handle.abort();
    }

    async fn http_get(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[test]
    fn validate_rejects_empty_domains_and_dns() {
        let empty = AcmeYaml {
            domains: Some(vec![]),
            ..Default::default()
        };
        let e = validate(&empty).unwrap_err();
        match e {
            Error::Config { field, reason } => {
                assert_eq!(field, "acme.domains");
                assert!(reason.contains("empty"), "{reason}");
            }
            other => panic!("{other:?}"),
        }

        let dns = AcmeYaml {
            domains: Some(vec!["example.com".into()]),
            ty: Some("dns".into()),
            ..Default::default()
        };
        let e = validate(&dns).unwrap_err();
        match e {
            Error::Config { field, reason } => {
                assert_eq!(field, "acme.dns");
                assert!(reason.contains("unimplemented"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn cache_first_skips_ca() {
        let dir = std::env::temp_dir().join(format!(
            "hy-acme-cache-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = b"-----BEGIN CERTIFICATE-----\nCACHE\n-----END CERTIFICATE-----\n";
        let key = b"-----BEGIN PRIVATE KEY-----\nCACHE\n-----END PRIVATE KEY-----\n";
        std::fs::write(dir.join("cert.pem"), cert).unwrap();
        std::fs::write(dir.join("key.pem"), key).unwrap();

        let acme = AcmeYaml {
            domains: Some(vec!["example.com".into()]),
            email: Some("a@b.c".into()),
            ty: Some("http".into()),
            dir: Some(dir.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let (c, k) = obtain(&acme).await.expect("cache obtain");
        assert_eq!(c, cert);
        assert_eq!(k, key);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
