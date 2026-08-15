//! Brutal + SwitchableController implementing `quinn_proto::congestion::Controller`.
//!
//! Math comes only from [`super::brutal_ack_rate`] / [`super::brutal_pacing_and_cwnd`].

use super::{brutal_ack_rate, brutal_pacing_and_cwnd, CcChoice, CongestionType};
use quinn_proto::congestion::{
    Bbr, BbrConfig, Controller, ControllerFactory, ControllerMetrics, NewReno, NewRenoConfig,
};
use quinn_proto::RttEstimator;
use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PKT_INFO_SLOTS: usize = 5;

/// Shared switchable CC. Handshake starts as BBR; [`Self::set_mode`] after HTTP 233.
pub struct SwitchableController {
    inner: Arc<Mutex<SwitchableInner>>,
}

struct SwitchableInner {
    mode: Mode,
    configured: CongestionType,
    disable_loss_comp: bool,
    max_datagram: u64,
}

enum Mode {
    Bbr(Bbr),
    Reno(NewReno),
    Brutal(Brutal),
}

/// Factory for endpoints: always builds Switchable starting in BBR.
#[derive(Debug, Clone)]
pub struct SwitchableFactory {
    pub configured: CongestionType,
    pub disable_loss_comp: bool,
}

impl Default for SwitchableFactory {
    fn default() -> Self {
        Self {
            configured: CongestionType::Bbr,
            disable_loss_comp: false,
        }
    }
}

impl SwitchableController {
    fn new_bbr(configured: CongestionType, disable_loss_comp: bool, mtu: u16) -> Self {
        // Same stock quinn BBR for every bbrProfile. `BbrConfig` only has
        // `initial_window` (no highGain / STARTUP). We do NOT claim profile
        // differentiation (report §4.8: standard 2.885, conservative 2.25,
        // aggressive 3.0). Handshake stays BBR; `set_mode` after HTTP 233.
        let bbr = Bbr::new(Arc::new(BbrConfig::default()), mtu);
        Self {
            inner: Arc::new(Mutex::new(SwitchableInner {
                mode: Mode::Bbr(bbr),
                configured,
                disable_loss_comp,
                max_datagram: u64::from(mtu),
            })),
        }
    }

    /// Switch after auth 233. `Configured` → BBR or NewReno per factory prefs.
    pub fn set_mode(&self, choice: CcChoice) {
        let mut g = self.inner.lock().unwrap();
        let mtu = g.max_datagram as u16;
        match choice {
            CcChoice::Brutal { bps } => {
                let disable = g.disable_loss_comp;
                let max_datagram = g.max_datagram;
                g.mode = Mode::Brutal(Brutal::new(bps, disable, max_datagram));
            }
            CcChoice::Configured => match g.configured {
                CongestionType::Bbr => {
                    if !matches!(g.mode, Mode::Bbr(_)) {
                        g.mode = Mode::Bbr(Bbr::new(Arc::new(BbrConfig::default()), mtu));
                    }
                }
                CongestionType::Reno => {
                    g.mode = Mode::Reno(NewReno::new(
                        Arc::new(NewRenoConfig::default()),
                        Instant::now(),
                        mtu,
                    ));
                }
            },
        }
    }
}

/// Apply `set_mode` on the live connection controller (shared via `clone_box` Arc).
pub fn apply_cc_mode(conn: &quinn::Connection, choice: CcChoice) {
    let boxed = conn.congestion_state();
    if let Ok(cc) = boxed.into_any().downcast::<SwitchableController>() {
        cc.set_mode(choice);
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        let mut g = self.inner.lock().unwrap();
        match &mut g.mode {
            Mode::Bbr(c) => c.on_sent(now, bytes, last_packet_number),
            Mode::Reno(c) => c.on_sent(now, bytes, last_packet_number),
            Mode::Brutal(c) => c.on_sent(now, bytes, last_packet_number),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        let mut g = self.inner.lock().unwrap();
        match &mut g.mode {
            Mode::Bbr(c) => c.on_ack(now, sent, bytes, app_limited, rtt),
            Mode::Reno(c) => c.on_ack(now, sent, bytes, app_limited, rtt),
            Mode::Brutal(c) => c.on_ack(now, sent, bytes, app_limited, rtt),
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        let mut g = self.inner.lock().unwrap();
        match &mut g.mode {
            Mode::Bbr(c) => c.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked),
            Mode::Reno(c) => c.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked),
            Mode::Brutal(c) => c.on_end_acks(now, in_flight, app_limited, largest_packet_num_acked),
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let mut g = self.inner.lock().unwrap();
        match &mut g.mode {
            Mode::Bbr(c) => c.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes),
            Mode::Reno(c) => c.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes),
            Mode::Brutal(c) => {
                c.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes)
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        let mut g = self.inner.lock().unwrap();
        g.max_datagram = u64::from(new_mtu);
        match &mut g.mode {
            Mode::Bbr(c) => c.on_mtu_update(new_mtu),
            Mode::Reno(c) => c.on_mtu_update(new_mtu),
            Mode::Brutal(c) => c.on_mtu_update(new_mtu),
        }
    }

    fn window(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        match &g.mode {
            Mode::Bbr(c) => c.window(),
            Mode::Reno(c) => c.window(),
            Mode::Brutal(c) => c.window(),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let g = self.inner.lock().unwrap();
        match &g.mode {
            Mode::Bbr(c) => c.metrics(),
            Mode::Reno(c) => c.metrics(),
            Mode::Brutal(c) => c.metrics(),
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }

    fn initial_window(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        match &g.mode {
            Mode::Bbr(c) => c.initial_window(),
            Mode::Reno(c) => c.initial_window(),
            Mode::Brutal(c) => c.initial_window(),
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(SwitchableController::new_bbr(
            self.configured,
            self.disable_loss_comp,
            current_mtu,
        ))
    }
}

/// Brutal sender: 5×1s ack/loss slots → ackRate → cwnd via `brutal_pacing_and_cwnd`.
struct Brutal {
    bps: u64,
    ack_rate: f64,
    disable_loss_comp: bool,
    slots: [PktSlot; PKT_INFO_SLOTS],
    max_datagram: u64,
    smoothed_rtt: Duration,
    /// Epoch for slot timestamps (relative seconds).
    epoch: Instant,
    pacing_rate: u64,
}

#[derive(Clone, Copy, Default)]
struct PktSlot {
    ts: i64,
    ack: u64,
    loss: u64,
}

impl Brutal {
    fn new(bps: u64, disable_loss_comp: bool, max_datagram: u64) -> Self {
        Self {
            bps,
            ack_rate: 1.0,
            disable_loss_comp,
            slots: [PktSlot::default(); PKT_INFO_SLOTS],
            max_datagram: max_datagram.max(1),
            smoothed_rtt: Duration::ZERO,
            epoch: Instant::now(),
            pacing_rate: bps,
        }
    }

    fn now_ts(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.epoch).as_secs() as i64
    }

    fn record(&mut self, now: Instant, acked_pkts: u64, lost_pkts: u64) {
        let ts = self.now_ts(now);
        let slot = (ts.rem_euclid(PKT_INFO_SLOTS as i64)) as usize;
        if self.slots[slot].ts == ts {
            self.slots[slot].ack = self.slots[slot].ack.saturating_add(acked_pkts);
            self.slots[slot].loss = self.slots[slot].loss.saturating_add(lost_pkts);
        } else {
            self.slots[slot] = PktSlot {
                ts,
                ack: acked_pkts,
                loss: lost_pkts,
            };
        }
        self.refresh_ack_rate(ts);
        let (pacing, _) =
            brutal_pacing_and_cwnd(self.bps, self.ack_rate, self.smoothed_rtt, self.max_datagram);
        self.pacing_rate = pacing;
    }

    fn refresh_ack_rate(&mut self, current_ts: i64) {
        if self.disable_loss_comp {
            self.ack_rate = 1.0;
            return;
        }
        let min_ts = current_ts - PKT_INFO_SLOTS as i64;
        let mut ack = 0u64;
        let mut loss = 0u64;
        for s in &self.slots {
            if s.ts < min_ts {
                continue;
            }
            ack += s.ack;
            loss += s.loss;
        }
        self.ack_rate = brutal_ack_rate(ack, loss, false);
    }

    fn loss_packet_count(&self, lost_bytes: u64) -> u64 {
        if lost_bytes == 0 {
            return 1;
        }
        lost_bytes
            .div_ceil(self.max_datagram.max(1))
            .max(1)
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.smoothed_rtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        let n = self.loss_packet_count(lost_bytes);
        self.record(now, 0, n);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.max_datagram = u64::from(new_mtu).max(1);
    }

    fn window(&self) -> u64 {
        brutal_pacing_and_cwnd(self.bps, self.ack_rate, self.smoothed_rtt, self.max_datagram).1
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut m = ControllerMetrics::default();
        m.congestion_window = self.window();
        m.ssthresh = None;
        // bits/s, same convention as quinn BBR
        m.pacing_rate = Some(self.pacing_rate.saturating_mul(8));
        m
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bps: self.bps,
            ack_rate: self.ack_rate,
            disable_loss_comp: self.disable_loss_comp,
            slots: self.slots,
            max_datagram: self.max_datagram,
            smoothed_rtt: self.smoothed_rtt,
            epoch: self.epoch,
            pacing_rate: self.pacing_rate,
        })
    }

    fn initial_window(&self) -> u64 {
        brutal_pacing_and_cwnd(self.bps, 1.0, Duration::ZERO, self.max_datagram).1
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn_proto::congestion::Controller;

    #[test]
    fn brutal_window_matches_formula() {
        let mut b = Brutal::new(800_000, false, 1200);
        b.smoothed_rtt = Duration::from_millis(100);
        b.ack_rate = 0.8;
        let (_, expect) = brutal_pacing_and_cwnd(800_000, 0.8, Duration::from_millis(100), 1200);
        assert_eq!(Controller::window(&b), expect);
        assert_eq!(Controller::window(&b), 200_000);
    }

    #[test]
    fn brutal_ack_rate_floor_via_slots() {
        let mut b = Brutal::new(1_000_000, false, 1200);
        let now = b.epoch;
        // 10 ack + 40 loss in same second → 50 samples, rate 0.2 → floor 0.8
        b.record(now, 10, 40);
        assert!((b.ack_rate - 0.8).abs() < 1e-9);
        let mut b2 = Brutal::new(1_000_000, true, 1200);
        b2.record(now, 10, 40);
        assert_eq!(b2.ack_rate, 1.0);
    }

    #[test]
    fn switchable_set_mode_brutal() {
        let cc = SwitchableController::new_bbr(CongestionType::Bbr, false, 1200);
        cc.set_mode(CcChoice::Brutal { bps: 500_000 });
        let w = Controller::window(&cc);
        let expect = brutal_pacing_and_cwnd(500_000, 1.0, Duration::ZERO, 1200).1;
        assert_eq!(w, expect);
    }
}
