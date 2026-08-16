//! V2Ray GeoIP / GeoSite protobuf (official `v2geo.proto`), no protoc.

use prost::Message;
use std::collections::HashMap;
use std::path::Path;

pub type GeoIpMap = HashMap<String, GeoIp>;
pub type GeoSiteMap = HashMap<String, GeoSite>;

pub const DOMAIN_TYPE_PLAIN: i32 = 0;
pub const DOMAIN_TYPE_REGEX: i32 = 1;
pub const DOMAIN_TYPE_ROOT_DOMAIN: i32 = 2;
pub const DOMAIN_TYPE_FULL: i32 = 3;

#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    #[prost(int32, tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<domain::Attribute>,
}

pub mod domain {
    use prost::Message;

    #[derive(Clone, PartialEq, Message)]
    pub struct Attribute {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(oneof = "attribute::TypedValue", tags = "2, 3")]
        pub typed_value: Option<attribute::TypedValue>,
    }

    pub mod attribute {
        use prost::Oneof;

        #[derive(Clone, PartialEq, Oneof)]
        pub enum TypedValue {
            #[prost(bool, tag = "2")]
            BoolValue(bool),
            #[prost(int64, tag = "3")]
            IntValue(i64),
        }
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub inverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

pub fn load_geoip_bytes(buf: &[u8]) -> Result<GeoIpMap, String> {
    let list = GeoIpList::decode(buf).map_err(|e| e.to_string())?;
    let mut m = GeoIpMap::new();
    for entry in list.entry {
        m.insert(entry.country_code.to_ascii_lowercase(), entry);
    }
    Ok(m)
}

pub fn load_geosite_bytes(buf: &[u8]) -> Result<GeoSiteMap, String> {
    let list = GeoSiteList::decode(buf).map_err(|e| e.to_string())?;
    let mut m = GeoSiteMap::new();
    for entry in list.entry {
        m.insert(entry.country_code.to_ascii_lowercase(), entry);
    }
    Ok(m)
}

pub fn load_geoip_file(path: impl AsRef<Path>) -> Result<GeoIpMap, String> {
    let bs = std::fs::read(path.as_ref()).map_err(|e| e.to_string())?;
    load_geoip_bytes(&bs)
}

pub fn load_geosite_file(path: impl AsRef<Path>) -> Result<GeoSiteMap, String> {
    let bs = std::fs::read(path.as_ref()).map_err(|e| e.to_string())?;
    load_geosite_bytes(&bs)
}

pub fn encode_geoip_list(list: &GeoIpList) -> Vec<u8> {
    list.encode_to_vec()
}

pub fn encode_geosite_list(list: &GeoSiteList) -> Vec<u8> {
    list.encode_to_vec()
}

/// On-disk GeoIP/GeoSite helper. Compile never calls a method unless a matching rule appears.
#[derive(Debug, Clone, Default)]
pub struct FileGeoLoader {
    pub geoip: Option<std::path::PathBuf>,
    pub geosite: Option<std::path::PathBuf>,
}

impl super::GeoLoader for FileGeoLoader {
    fn load_geoip(&self) -> Result<GeoIpMap, String> {
        let p = self
            .geoip
            .as_ref()
            .ok_or_else(|| "geoip path not set".to_string())?;
        load_geoip_file(p)
    }

    fn load_geosite(&self) -> Result<GeoSiteMap, String> {
        let p = self
            .geosite
            .as_ref()
            .ok_or_else(|| "geosite path not set".to_string())?;
        load_geosite_file(p)
    }
}

/// In-memory maps for tests and custom loaders.
#[derive(Clone, Default)]
pub struct MemoryGeoLoader {
    pub geoip: GeoIpMap,
    pub geosite: GeoSiteMap,
}

impl super::GeoLoader for MemoryGeoLoader {
    fn load_geoip(&self) -> Result<GeoIpMap, String> {
        Ok(self.geoip.clone())
    }
    fn load_geosite(&self) -> Result<GeoSiteMap, String> {
        Ok(self.geosite.clone())
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use prost::Message;

    #[test]
    fn roundtrip_lowercase_keys() {
        let list = GeoIpList {
            entry: vec![GeoIp {
                country_code: "CN".into(),
                cidr: vec![Cidr {
                    ip: vec![1, 2, 3, 0],
                    prefix: 24,
                }],
                inverse_match: false,
            }],
        };
        let m = load_geoip_bytes(&list.encode_to_vec()).unwrap();
        assert!(m.contains_key("cn"));
        assert!(!m.contains_key("CN"));
        assert_eq!(m["cn"].country_code, "CN");
        assert_eq!(m["cn"].cidr[0].ip, vec![1, 2, 3, 0]);
    }
}
