//! Official `app/internal/utils/geoloader.go`: on-demand GeoIP/GeoSite with auto-download.

use hy_core::Error;
use hy_extras::acl::{
    load_geoip_file, load_geosite_file, GeoIpMap, GeoLoader, GeoSiteMap,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const GEOIP_FILENAME: &str = "geoip.dat";
pub const GEOSITE_FILENAME: &str = "geosite.dat";
pub const GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
pub const GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
pub const GEO_DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(7 * 24 * 3600);
const GEO_DL_TMP_PREFIX: &str = ".hysteria-geoloader.dlpart.";

static DL_SEQ: AtomicU64 = AtomicU64::new(1);

pub trait GeoHttp: Send + Sync {
    fn get(&self, url: &str) -> Result<Vec<u8>, String>;
}

pub struct DefaultHttp;

impl GeoHttp for DefaultHttp {
    fn get(&self, url: &str) -> Result<Vec<u8>, String> {
        let resp = ureq::get(url).call().map_err(|e| e.to_string())?;
        let mut v = Vec::new();
        resp.into_reader()
            .read_to_end(&mut v)
            .map_err(|e| e.to_string())?;
        Ok(v)
    }
}

/// Go-style duration: `ms`, `s`, `m`, `h` (and concatenations like `1h30m`).
pub fn parse_go_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total = Duration::ZERO;
    let mut saw = false;
    while i < bytes.len() {
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            return Err(format!("bad duration {s}"));
        }
        let n: u64 = s[num_start..i]
            .parse()
            .map_err(|_| format!("bad duration {s}"))?;
        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = &s[unit_start..i];
        let add = match unit {
            "ns" => Duration::from_nanos(n),
            "us" | "µs" | "μs" => Duration::from_micros(n),
            "ms" => Duration::from_millis(n),
            "s" => Duration::from_secs(n),
            "m" => Duration::from_secs(n.saturating_mul(60)),
            "h" => Duration::from_secs(n.saturating_mul(3600)),
            _ => return Err(format!("bad duration {s}")),
        };
        total = total.checked_add(add).ok_or_else(|| format!("bad duration {s}"))?;
        saw = true;
    }
    if !saw || i != bytes.len() {
        return Err(format!("bad duration {s}"));
    }
    Ok(total)
}

pub struct AppGeoLoader {
    geoip_filename: String,
    geosite_filename: String,
    update_interval: Duration,
    http: Arc<dyn GeoHttp>,
    base_dir: PathBuf,
    geoip_map: Mutex<Option<GeoIpMap>>,
    geosite_map: Mutex<Option<GeoSiteMap>>,
}

impl AppGeoLoader {
    pub fn new(
        geoip: Option<String>,
        geosite: Option<String>,
        update_interval: Duration,
        http: Arc<dyn GeoHttp>,
        base_dir: PathBuf,
    ) -> Self {
        Self {
            geoip_filename: geoip.unwrap_or_default(),
            geosite_filename: geosite.unwrap_or_default(),
            update_interval,
            http,
            base_dir,
            geoip_map: Mutex::new(None),
            geosite_map: Mutex::new(None),
        }
    }

    fn resolve(&self, name: &str) -> PathBuf {
        let p = Path::new(name);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base_dir.join(p)
        }
    }

    fn interval(&self) -> Duration {
        if self.update_interval.is_zero() {
            GEO_DEFAULT_UPDATE_INTERVAL
        } else {
            self.update_interval
        }
    }

    fn should_download(&self, path: &Path) -> bool {
        let info = match std::fs::metadata(path) {
            Err(_) => return true,
            Ok(m) => m,
        };
        if info.len() == 0 {
            return true;
        }
        let dt = info
            .modified()
            .ok()
            .and_then(|m| m.elapsed().ok())
            .unwrap_or(Duration::from_secs(u64::MAX));
        dt > self.interval()
    }

    fn download_and_check(
        &self,
        dest: &Path,
        url: &str,
        check: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<(), String> {
        let body = self.http.get(url)?;
        let tmp = self.base_dir.join(format!(
            "{GEO_DL_TMP_PREFIX}{}-{}",
            std::process::id(),
            DL_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        if let Err(e) = std::fs::write(&tmp, &body) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e.to_string());
        }
        if let Err(e) = check(&tmp) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("integrity check failed: {e}"));
        }
        if let Err(e) = std::fs::rename(&tmp, dest) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("rename failed: {e}"));
        }
        Ok(())
    }

    fn load_geoip_uncached(&self) -> Result<GeoIpMap, String> {
        let auto = self.geoip_filename.is_empty();
        let filename = if auto {
            GEOIP_FILENAME.to_string()
        } else {
            self.geoip_filename.clone()
        };
        let path = self.resolve(&filename);
        if auto {
            if !self.should_download(&path) {
                if let Ok(m) = load_geoip_file(&path) {
                    return Ok(m);
                }
            }
            let err = self.download_and_check(&path, GEOIP_URL, |p| {
                load_geoip_file(p).map(|_| ())
            });
            if let Err(e) = err {
                if !path.exists() {
                    return Err(e);
                }
            }
        }
        load_geoip_file(&path)
    }

    fn load_geosite_uncached(&self) -> Result<GeoSiteMap, String> {
        let auto = self.geosite_filename.is_empty();
        let filename = if auto {
            GEOSITE_FILENAME.to_string()
        } else {
            self.geosite_filename.clone()
        };
        let path = self.resolve(&filename);
        if auto {
            if !self.should_download(&path) {
                if let Ok(m) = load_geosite_file(&path) {
                    return Ok(m);
                }
            }
            let err = self.download_and_check(&path, GEOSITE_URL, |p| {
                load_geosite_file(p).map(|_| ())
            });
            if let Err(e) = err {
                if !path.exists() {
                    return Err(e);
                }
            }
        }
        load_geosite_file(&path)
    }
}

impl GeoLoader for AppGeoLoader {
    fn load_geoip(&self) -> Result<GeoIpMap, String> {
        {
            let g = self.geoip_map.lock().unwrap();
            if let Some(m) = g.as_ref() {
                return Ok(m.clone());
            }
        }
        let m = self.load_geoip_uncached()?;
        *self.geoip_map.lock().unwrap() = Some(m.clone());
        Ok(m)
    }

    fn load_geosite(&self) -> Result<GeoSiteMap, String> {
        {
            let g = self.geosite_map.lock().unwrap();
            if let Some(m) = g.as_ref() {
                return Ok(m.clone());
            }
        }
        let m = self.load_geosite_uncached()?;
        *self.geosite_map.lock().unwrap() = Some(m.clone());
        Ok(m)
    }
}

pub fn geo_interval_from_yaml(s: Option<&str>) -> Result<Duration, Error> {
    match s {
        None | Some("") => Ok(Duration::ZERO),
        Some(t) => parse_go_duration(t).map_err(|e| Error::config("acl.geoUpdateInterval", e)),
    }
}

pub fn tiny_geoip_dat() -> Vec<u8> {
    use hy_extras::acl::v2geo::{encode_geoip_list, Cidr, GeoIp, GeoIpList};
    encode_geoip_list(&GeoIpList {
        entry: vec![GeoIp {
            country_code: "CN".into(),
            cidr: vec![Cidr {
                ip: vec![1, 2, 3, 0],
                prefix: 24,
            }],
            inverse_match: false,
        }],
    })
}

pub fn tiny_geosite_dat() -> Vec<u8> {
    use hy_extras::acl::v2geo::{
        encode_geosite_list, Domain, GeoSite, GeoSiteList, DOMAIN_TYPE_FULL,
    };
    encode_geosite_list(&GeoSiteList {
        entry: vec![GeoSite {
            country_code: "GOOGLE".into(),
            domain: vec![Domain {
                r#type: DOMAIN_TYPE_FULL,
                value: "accounts.google.com".into(),
                attribute: vec![],
            }],
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hy_extras::acl::{CompiledRuleSet, Proto};
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    struct FakeHttp {
        /// url → body or error
        map: HashMap<String, Result<Vec<u8>, String>>,
        called: StdMutex<Vec<String>>,
    }

    impl FakeHttp {
        fn new(pairs: Vec<(&str, Result<Vec<u8>, String>)>) -> Arc<Self> {
            Arc::new(Self {
                map: pairs
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                called: StdMutex::new(Vec::new()),
            })
        }
    }

    impl GeoHttp for FakeHttp {
        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.called.lock().unwrap().push(url.to_string());
            match self.map.get(url) {
                Some(Ok(b)) => Ok(b.clone()),
                Some(Err(e)) => Err(e.clone()),
                None => Err(format!("unexpected url {url}")),
            }
        }
    }

    struct PanicHttp;
    impl GeoHttp for PanicHttp {
        fn get(&self, _url: &str) -> Result<Vec<u8>, String> {
            panic!("HTTP should not be called");
        }
    }

    fn tmp_dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "hy-geoloader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                ^ u128::from(DL_SEQ.fetch_add(1, Ordering::Relaxed))
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn parse_168h_is_seven_days() {
        assert_eq!(parse_go_duration("168h").unwrap(), Duration::from_secs(168 * 3600));
        assert_eq!(
            parse_go_duration("168h").unwrap(),
            GEO_DEFAULT_UPDATE_INTERVAL
        );
        assert_eq!(parse_go_duration("0s").unwrap(), Duration::ZERO);
        assert!(parse_go_duration("5x").is_err());
    }

    #[test]
    fn no_geo_rules_no_download() {
        let dir = tmp_dir();
        let http = Arc::new(PanicHttp);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http, dir.clone());
        CompiledRuleSet::compile_with("direct(*)\n", Some(&loader)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_bad_path_compile_fails() {
        let dir = tmp_dir();
        let http = Arc::new(PanicHttp);
        let loader = AppGeoLoader::new(
            Some("/no/such/hy-geoip-missing.dat".into()),
            None,
            Duration::ZERO,
            http,
            dir.clone(),
        );
        let e = CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&loader)).unwrap_err();
        assert_eq!(e.line, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_missing_file_downloads_and_writes() {
        let dir = tmp_dir();
        let dat = tiny_geoip_dat();
        let http = FakeHttp::new(vec![(GEOIP_URL, Ok(dat.clone()))]);
        let loader = AppGeoLoader::new(
            None,
            None,
            Duration::ZERO,
            http.clone(),
            dir.clone(),
        );
        let rs =
            CompiledRuleSet::compile_with("reject(geoip:cn)\ndirect(*)\n", Some(&loader)).unwrap();
        assert_eq!(http.called.lock().unwrap().as_slice(), &[GEOIP_URL]);
        let on_disk = std::fs::read(dir.join(GEOIP_FILENAME)).unwrap();
        assert_eq!(on_disk, dat);
        let h = rs.match_info(
            "x",
            Some("1.2.3.4".parse().unwrap()),
            None,
            Proto::Tcp,
            80,
        );
        assert_eq!(h.outbound, "reject");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_download_fail_uses_old_file() {
        let dir = tmp_dir();
        let path = dir.join(GEOIP_FILENAME);
        std::fs::write(&path, tiny_geoip_dat()).unwrap();
        // expire mtime so auto would download
        let old = std::time::SystemTime::now() - Duration::from_secs(8 * 24 * 3600);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let http = FakeHttp::new(vec![(GEOIP_URL, Err("offline".into()))]);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http.clone(), dir.clone());
        let rs =
            CompiledRuleSet::compile_with("reject(geoip:cn)\ndirect(*)\n", Some(&loader)).unwrap();
        assert_eq!(http.called.lock().unwrap().as_slice(), &[GEOIP_URL]);
        let h = rs.match_info(
            "x",
            Some("1.2.3.9".parse().unwrap()),
            None,
            Proto::Tcp,
            1,
        );
        assert_eq!(h.outbound, "reject");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_download_fail_no_file_fails() {
        let dir = tmp_dir();
        let http = FakeHttp::new(vec![(GEOIP_URL, Err("offline".into()))]);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http, dir.clone());
        let e = CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&loader)).unwrap_err();
        assert_eq!(e.line, 1);
        assert!(!e.msg.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_fresh_file_skips_http() {
        let dir = tmp_dir();
        std::fs::write(dir.join(GEOIP_FILENAME), tiny_geoip_dat()).unwrap();
        let http = Arc::new(PanicHttp);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http, dir.clone());
        CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&loader)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn explicit_path_never_downloads() {
        let dir = tmp_dir();
        let p = dir.join("mine.dat");
        std::fs::write(&p, tiny_geoip_dat()).unwrap();
        let http = Arc::new(PanicHttp);
        let loader = AppGeoLoader::new(
            Some(p.to_string_lossy().into()),
            None,
            Duration::ZERO,
            http,
            dir.clone(),
        );
        CompiledRuleSet::compile_with("reject(geoip:cn)\n", Some(&loader)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_geosite_missing_file_downloads() {
        let dir = tmp_dir();
        let dat = tiny_geosite_dat();
        let http = FakeHttp::new(vec![(GEOSITE_URL, Ok(dat.clone()))]);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http.clone(), dir.clone());
        let rs = CompiledRuleSet::compile_with("direct(geosite:google)\nreject(*)\n", Some(&loader))
            .unwrap();
        assert_eq!(http.called.lock().unwrap().as_slice(), &[GEOSITE_URL]);
        assert_eq!(
            rs.match_host("accounts.google.com", Proto::Tcp, 443).outbound,
            "direct"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn caches_after_first_load() {
        let dir = tmp_dir();
        let http = FakeHttp::new(vec![(GEOIP_URL, Ok(tiny_geoip_dat()))]);
        let loader = AppGeoLoader::new(None, None, Duration::ZERO, http.clone(), dir.clone());
        loader.load_geoip().unwrap();
        loader.load_geoip().unwrap();
        assert_eq!(http.called.lock().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
