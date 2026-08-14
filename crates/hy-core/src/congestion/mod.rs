//! Congestion selection and Brutal math. QUIC Controller is behind `transport`.

use crate::error::Error;
use std::time::Duration;

#[cfg(feature = "transport")]
mod brutal;

#[cfg(feature = "transport")]
pub use brutal::{apply_cc_mode, SwitchableController, SwitchableFactory};

pub const TYPE_BBR: &str = "bbr";
pub const TYPE_RENO: &str = "reno";

pub const BBR_STANDARD: &str = "standard";
pub const BBR_CONSERVATIVE: &str = "conservative";
pub const BBR_AGGRESSIVE: &str = "aggressive";

pub const ACK_RATE_FLOOR: f64 = 0.8;
pub const BRUTAL_MIN_SAMPLES: u64 = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionType {
    Bbr,
    Reno,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BbrProfile {
    Standard,
    Conservative,
    Aggressive,
}

pub fn normalize_type(s: &str) -> Result<CongestionType, Error> {
    match s.to_ascii_lowercase().as_str() {
        "" | TYPE_BBR => Ok(CongestionType::Bbr),
        TYPE_RENO => Ok(CongestionType::Reno),
        other => Err(Error::config(
            "CongestionConfig.Type",
            format!("unsupported congestion type {other:?}"),
        )),
    }
}

pub fn normalize_bbr_profile(s: &str) -> Result<BbrProfile, Error> {
    match s.to_ascii_lowercase().as_str() {
        "" | BBR_STANDARD => Ok(BbrProfile::Standard),
        BBR_CONSERVATIVE => Ok(BbrProfile::Conservative),
        BBR_AGGRESSIVE => Ok(BbrProfile::Aggressive),
        other => Err(Error::config(
            "CongestionConfig.BBRProfile",
            format!("unsupported bbr profile {other:?}"),
        )),
    }
}

// v1: all BBR profiles map to quinn's stock BBR; profile-specific tuning is TODO.

/// `actual_tx = min(a, b)` treating 0 as unlimited/unknown.
pub fn min_bandwidth(a: u64, b: u64) -> u64 {
    match (a, b) {
        (0, x) | (x, 0) => x,
        (a, b) => a.min(b),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcChoice {
    Brutal { bps: u64 },
    Configured,
}

/// Server send rate (client downlink). See report §3.2.
pub fn server_send_cc(ignore_client_bw: bool, server_max_tx: u64, client_max_rx: u64) -> CcChoice {
    if ignore_client_bw {
        return CcChoice::Configured;
    }
    let actual = min_bandwidth(server_max_tx, client_max_rx);
    if actual > 0 {
        CcChoice::Brutal { bps: actual }
    } else {
        CcChoice::Configured
    }
}

/// Client send rate (server uplink). `server_rx_auto` is `Hysteria-CC-RX: auto`.
pub fn client_send_cc(server_rx_auto: bool, server_max_rx: u64, client_max_tx: u64) -> CcChoice {
    if server_rx_auto {
        return CcChoice::Configured;
    }
    let actual = min_bandwidth(server_max_rx, client_max_tx);
    if actual > 0 {
        CcChoice::Brutal { bps: actual }
    } else {
        CcChoice::Configured
    }
}

/// Brutal ack-rate compensation. Samples < 50 → 1.0; else clamp to ≥ 0.8.
pub fn brutal_ack_rate(acked: u64, lost: u64, disable_loss_comp: bool) -> f64 {
    if disable_loss_comp {
        return 1.0;
    }
    let samples = acked + lost;
    if samples < BRUTAL_MIN_SAMPLES {
        return 1.0;
    }
    let rate = acked as f64 / samples as f64;
    rate.max(ACK_RATE_FLOOR)
}

/// `pacing_rate = bps / ackRate`, `cwnd = bps * smoothedRTT * 2 / ackRate`
/// (cwnd floor = max_datagram; RTT<=0 → 10240).
pub fn brutal_pacing_and_cwnd(
    bps: u64,
    ack_rate: f64,
    smoothed_rtt: Duration,
    max_datagram: u64,
) -> (u64, u64) {
    let rate = if ack_rate > 0.0 { ack_rate } else { 1.0 };
    let pacing = (bps as f64 / rate) as u64;
    let cwnd = if smoothed_rtt.is_zero() {
        10240
    } else {
        let bytes = (bps as f64) * smoothed_rtt.as_secs_f64() * 2.0 / rate;
        (bytes as u64).max(max_datagram)
    };
    (pacing, cwnd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        assert_eq!(normalize_type("").unwrap(), CongestionType::Bbr);
        assert_eq!(normalize_type("BBR").unwrap(), CongestionType::Bbr);
        assert_eq!(normalize_type("reno").unwrap(), CongestionType::Reno);
        assert!(normalize_type("cubic").is_err());
        assert_eq!(normalize_bbr_profile("").unwrap(), BbrProfile::Standard);
        assert_eq!(
            normalize_bbr_profile("conservative").unwrap(),
            BbrProfile::Conservative
        );
    }

    #[test]
    fn bandwidth_and_cc() {
        assert_eq!(min_bandwidth(0, 100), 100);
        assert_eq!(min_bandwidth(50, 100), 50);
        assert_eq!(
            server_send_cc(true, 1_000_000, 500_000),
            CcChoice::Configured
        );
        assert_eq!(
            server_send_cc(false, 1_000_000, 500_000),
            CcChoice::Brutal { bps: 500_000 }
        );
        assert_eq!(server_send_cc(false, 0, 0), CcChoice::Configured);
        assert_eq!(
            client_send_cc(true, 1_000_000, 500_000),
            CcChoice::Configured
        );
        assert_eq!(
            client_send_cc(false, 1_000_000, 500_000),
            CcChoice::Brutal { bps: 500_000 }
        );
    }

    #[test]
    fn brutal_ack_floor() {
        assert_eq!(brutal_ack_rate(10, 10, false), 1.0); // < 50 samples
        assert!((brutal_ack_rate(40, 10, false) - 0.8).abs() < 1e-9);
        assert!((brutal_ack_rate(10, 40, false) - 0.8).abs() < 1e-9); // 0.2 → 0.8
        assert_eq!(brutal_ack_rate(10, 40, true), 1.0);
    }

    #[test]
    fn brutal_formula() {
        let (p, c) = brutal_pacing_and_cwnd(1_000_000, 1.0, Duration::from_millis(0), 1200);
        assert_eq!(p, 1_000_000);
        assert_eq!(c, 10240);
        let (p, c) = brutal_pacing_and_cwnd(800_000, 0.8, Duration::from_millis(100), 1200);
        assert_eq!(p, 1_000_000);
        // 800000 * 0.1 * 2 / 0.8 = 200000
        assert_eq!(c, 200_000);
    }
}
