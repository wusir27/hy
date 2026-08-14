//! Pluggable policy layer. Depends only on `hy-core` interfaces.
//!
//! Pipeline order (must stay): Speedtest → Resolver → ACL → Outbound.

pub mod auth;

pub mod obfs;

pub mod acl;

pub mod outbounds;

pub mod sniff {}
pub mod masq;
pub mod realm {}
pub mod udphop {}
pub mod trafficlogger;
