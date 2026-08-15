//! `masquerade.type: file` — static directory; reject `..` path components.

use async_trait::async_trait;
use bytes::Bytes;
use hy_core::server::{MasqHandler, MasqResponse};
use std::path::{Component, Path, PathBuf};

pub struct FileMasq {
    pub root: PathBuf,
}

impl FileMasq {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl MasqHandler for FileMasq {
    async fn handle(&self, method: &str, _host: &str, path: &str) -> MasqResponse {
        if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
            return MasqResponse {
                status: 405,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: Bytes::from_static(b"method not allowed"),
            };
        }
        let mapped = match map_under_root(&self.root, path) {
            Ok(p) => p,
            Err(status) => {
                return MasqResponse {
                    status,
                    headers: vec![],
                    body: Bytes::new(),
                };
            }
        };
        let file_path = if mapped.is_dir() {
            let index = mapped.join("index.html");
            if index.is_file() {
                index
            } else {
                return MasqResponse {
                    status: 404,
                    headers: vec![],
                    body: Bytes::new(),
                };
            }
        } else if mapped.is_file() {
            mapped
        } else {
            return MasqResponse {
                status: 404,
                headers: vec![],
                body: Bytes::new(),
            };
        };
        let body = match std::fs::read(&file_path) {
            Ok(b) => b,
            Err(_) => {
                return MasqResponse {
                    status: 404,
                    headers: vec![],
                    body: Bytes::new(),
                };
            }
        };
        let ctype = content_type(&file_path);
        MasqResponse {
            status: 200,
            headers: vec![("content-type".into(), ctype.into())],
            body: Bytes::from(body),
        }
    }
}

/// Map URL path onto `root`. Any `..` component → 403. Does not escape root.
fn map_under_root(root: &Path, url_path: &str) -> Result<PathBuf, u16> {
    let path = url_path.split('?').next().unwrap_or(url_path);
    let path = path.split('#').next().unwrap_or(path);
    let mut out = PathBuf::new();
    for comp in Path::new(path).components() {
        match comp {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {}
            Component::ParentDir => return Err(403),
        }
    }
    let full = root.join(&out);
    // Defense in depth: reject if cleaned path escapes root (symlinks aside).
    if let (Ok(root_c), Ok(full_c)) = (root.canonicalize(), full.canonicalize()) {
        if !full_c.starts_with(&root_c) {
            return Err(403);
        }
        return Ok(full_c);
    }
    // File may not exist yet — still ensure lexical containment.
    let root_abs = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(root)
    };
    let full_abs = root_abs.join(&out);
    Ok(full_abs)
}

fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html",
        "txt" | "text" => "text/plain",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn serves_temp_file_and_rejects_dotdot() {
        let dir = std::env::temp_dir().join(format!("hy-filemasq-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let outside = std::env::temp_dir().join(format!("hy-filemasq-secret-{}", std::process::id()));
        fs::write(&outside, b"SECRET").unwrap();
        fs::write(dir.join("name.html"), b"<h1>ok</h1>").unwrap();

        let m = FileMasq::new(&dir);
        let r = m.handle("GET", "h", "/name.html").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body.as_ref(), b"<h1>ok</h1>");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("content-type") && v == "text/html"));

        let bad = m.handle("GET", "h", "/../hy-filemasq-secret-dummy").await;
        assert!(bad.status == 403 || bad.status == 404, "status={}", bad.status);
        assert_ne!(bad.body.as_ref(), b"SECRET");

        // Explicit .. component
        let bad2 = m.handle("GET", "h", "/a/../../etc/passwd").await;
        assert!(bad2.status == 403 || bad2.status == 404);

        // Path that would resolve outside if .. were allowed
        let escape = format!("../{}", outside.file_name().unwrap().to_string_lossy());
        let bad3 = m.handle("GET", "h", &format!("/{escape}")).await;
        assert!(bad3.status == 403 || bad3.status == 404);
        assert_ne!(bad3.body.as_ref(), b"SECRET");

        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_file(&outside);
    }

    #[tokio::test]
    async fn directory_index_html() {
        let dir = std::env::temp_dir().join(format!("hy-filemasq-idx-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), b"idx").unwrap();
        let m = FileMasq::new(&dir);
        let r = m.handle("GET", "", "/").await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body.as_ref(), b"idx");
        let _ = fs::remove_dir_all(&dir);
    }
}
