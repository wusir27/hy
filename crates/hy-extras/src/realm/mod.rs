//! Hysteria Realms NAT traversal (P5.E1).
//!
//! Punch wire + HTTP signaling align with official `extras/realm`.
//! This crate does **not** ship a realm signaling server.
//!
//! `portMapping` YAML is accepted by the app layer but apply is a no-op this
//! gate (official UPnP/NAT-PMP is heavy).

mod addr;
mod client;
mod factory;
mod punch;
mod punch_conn;
mod punch_engine;
mod stun;

pub use addr::{is_realm_url, parse_addr, Addr, ErrInvalidAddr, ErrInvalidScheme};
pub use client::{
    ConnectRequest, ConnectResponse, ErrorResponse, HeartbeatRequest, HeartbeatResponse,
    PunchEvent, RealmClient, StatusError, PUNCH_NONCE_SIZE, PUNCH_OBFS_KEY_SIZE,
};
pub use factory::{
    open_server_realm, try_parse_realm_url, PeerSlot, RealmFactory, RealmOptions,
    DEFAULT_STUN_SERVERS,
};
pub use punch::{
    decode_punch_packet, encode_punch_packet, new_punch_metadata, PunchMetadata, PunchPacket,
    PunchPacketType, ErrInvalidPunchPacket, MAX_PUNCH_PADDING,
};
pub use punch_conn::{ErrInvalidPunchAttempt, PunchPacketConn, PunchPacketEvent};
pub use punch_engine::{
    candidate_punch_addrs, expand_symmetric_nat_candidates, punch, punch_via_events, PunchConfig,
    PunchResult, DEFAULT_PUNCH_TIMEOUT, ErrInvalidPunchConfig, ErrPunchTimeout,
};
pub use stun::{
    discover, is_stun_message, parse_stun_binding_response, AddrFamily, STUNConfig,
    DEFAULT_STUN_TIMEOUT, ErrInvalidSTUNConfig,
};

#[cfg(test)]
mod integration_tests;
