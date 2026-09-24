//! Adaptive bitrate control
//!
//! Two things move the encoder's rate, and they are not alike. The presets and
//! the relay floor are *policy*: a known ceiling the user or the link path
//! picks, computable from state alone. Loss response is a *controller*: it has
//! to watch the link over time, decide from ratios, and be able to walk the
//! rate back up again. [`LossCeiling`] is that controller; the live arbiter in
//! [`super::streamer`] owns both terms and pushes the result to the encoder.

use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Loss-driven bitrate ceiling — the input the controller here has always had
/// a hook for and never used (roadmap 2053).
///
/// QUIC already reacts to loss by shrinking its congestion window, but that
/// bounds the *transport*, not the encoder: the desktop keeps producing frames
/// at the configured rate, and the mismatch comes out as a backlog the
/// transport task trims — dropped frames. Cutting the encoder's rate is the
/// other half of the response, and the only way a lossy link gets a smoother
/// picture rather than a stalling one.
///
/// The signal is the send-side loss ratio over one arbiter tick, from the
/// transport's own cumulative counters: `ConnectionStats::lost_packets` over
/// `datagrams_sent`. Both stacks report those — quinn for the current path,
/// iroh summed across paths, where a ratio of summed counts is still the
/// ratio it was before the summing.
pub struct LossCeiling {
    configured: u32,
    ceiling: u32,
    prev_lost: u64,
    prev_sent: u64,
}

/// Under this many datagrams in one tick, a loss ratio is noise. A still
/// desktop sends almost nothing (damage-driven capture), and reacting to "1 of
/// 4 lost" would cut a healthy link to the floor.
const MIN_TICK_DATAGRAMS: u64 = 100;

/// Losing more than one percent of what we sent means the link is congested.
const LOSS_REDUCE_RATIO: f64 = 0.01;

/// Under a tenth of a percent, let the rate climb back. Between the two is a
/// deadband where holding still is the answer: without it, a link that is
/// neither good nor bad rebuilds the encoder every tick.
const LOSS_CLEAN_RATIO: f64 = 0.001;

/// Cut 20 % per congested tick, recover 10 % per clean one — asymmetric on
/// purpose, so a link that starts dropping is off the cliff in a couple of
/// seconds and the climb back is the slow, non-oscillating direction.
const REDUCE_FACTOR: f64 = 0.80;
const RECOVER_FACTOR: f64 = 1.10;

/// Not a tuning preference: below about a megabit the encoder is producing an
/// unusable picture, and what a link that starved needs next is fewer pixels,
/// not fewer bits per pixel. This controller does not change resolution
/// mid-session — the same honest axis scope as the HUD presets — so it stops
/// rather than silently degrade the image past the point of use.
const LOSS_BITRATE_FLOOR_BPS: u32 = 1_000_000;

impl LossCeiling {
    /// Start disengaged: a session begins at its configured rate and only
    /// measured loss moves it.
    pub fn new(configured_bps: u32) -> Self {
        Self {
            configured: configured_bps,
            ceiling: u32::MAX,
            prev_lost: 0,
            prev_sent: 0,
        }
    }

    /// Fold one tick of cumulative transport counters into the ceiling.
    /// Counters that go backwards yield a zero delta, which the sample floor
    /// turns into "no information" rather than a negative loss ratio.
    pub fn sample(&mut self, lost_packets: u64, datagrams_sent: u64) {
        let lost_delta = lost_packets.saturating_sub(self.prev_lost);
        let sent_delta = datagrams_sent.saturating_sub(self.prev_sent);
        self.prev_lost = lost_packets;
        self.prev_sent = datagrams_sent;
        self.ceiling = next_loss_ceiling(self.configured, self.ceiling, sent_delta, lost_delta);
    }

    /// The ceiling to fold into the arbiter's `min` chain. [`u32::MAX`] means
    /// loss has never moved the rate, so the term is inert.
    pub fn ceiling(&self) -> u32 {
        self.ceiling
    }
}

/// One tick of [`LossCeiling::sample`], as a pure function so every branch is
/// reachable without a connection. Reductions are measured against whatever is
/// already in force, never against `configured`, so a preset or relay clamp
/// that already cut the rate is a starting point rather than something this
/// term quietly overrides upward.
fn next_loss_ceiling(configured: u32, ceiling: u32, sent: u64, lost: u64) -> u32 {
    if sent < MIN_TICK_DATAGRAMS {
        return ceiling;
    }
    let ratio = lost as f64 / sent as f64;
    let base = ceiling.min(configured);
    if ratio > LOSS_REDUCE_RATIO {
        ((base as f64 * REDUCE_FACTOR) as u32)
            .max(LOSS_BITRATE_FLOOR_BPS)
            .min(configured)
    } else if ratio < LOSS_CLEAN_RATIO {
        if base >= configured {
            u32::MAX
        } else {
            let climbing = (base as f64 * RECOVER_FACTOR) as u32;
            if climbing >= configured {
                u32::MAX
            } else {
                climbing.max(LOSS_BITRATE_FLOOR_BPS)
            }
        }
    } else {
        ceiling
    }
}

/// Adaptive bitrate controller
pub struct AdaptiveBitrate {
    /// Current target bitrate in bits per second
    current_bitrate_bps: u32,
    /// Minimum allowed bitrate (prevents going too low)
    min_bitrate_bps: u32,
    /// Maximum allowed bitrate (caps bandwidth usage)
    max_bitrate_bps: u32,
    /// RTT threshold for bitrate reduction (high latency = congestion)
    rtt_threshold_ms: u128,
    /// How often to evaluate and adjust (milliseconds)
    evaluation_interval_ms: u64,
    /// Last evaluation timestamp
    last_evaluation: Instant,
    /// History of RTT measurements for smoothing
    rtt_history: Vec<u128>,
    /// Number of consecutive high-RTT readings before reducing bitrate
    congestion_threshold: u32,
    /// Consecutive high-RTT counter
    congestion_count: u32,
    /// Bitrate update channel
    bitrate_tx: Option<watch::Sender<u32>>,
}

impl AdaptiveBitrate {
    /// Create a new adaptive bitrate controller
    pub fn new(initial_bitrate_bps: u32, min_bitrate_bps: u32, max_bitrate_bps: u32) -> Self {
        Self {
            current_bitrate_bps: initial_bitrate_bps,
            min_bitrate_bps,
            max_bitrate_bps,
            rtt_threshold_ms: 150,        // Reduce bitrate if RTT > 150ms
            evaluation_interval_ms: 2000, // Check every 2 seconds
            last_evaluation: Instant::now(),
            rtt_history: Vec::with_capacity(10),
            congestion_threshold: 3, // 3 consecutive high RTT readings
            congestion_count: 0,
            bitrate_tx: None,
        }
    }

    /// Attach a watch sender for updating the encoder bitrate
    pub fn attach(&mut self, bitrate_tx: watch::Sender<u32>) {
        self.bitrate_tx = Some(bitrate_tx);
    }

    /// Set the RTT threshold for bitrate reduction
    pub fn set_rtt_threshold_ms(&mut self, threshold_ms: u128) {
        self.rtt_threshold_ms = threshold_ms;
    }

    /// Set the evaluation interval
    pub fn set_evaluation_interval_ms(&mut self, interval_ms: u64) {
        self.evaluation_interval_ms = interval_ms;
    }

    /// Update with the latest RTT measurement from QUIC connection stats
    pub fn update_rtt(&mut self, rtt_ms: u128) {
        // Add to history for smoothing
        self.rtt_history.push(rtt_ms);
        if self.rtt_history.len() > 10 {
            self.rtt_history.remove(0);
        }

        // Fast-path: if RTT is extremely high (> 500ms), reduce bitrate immediately
        if rtt_ms > 500 && self.current_bitrate_bps > self.min_bitrate_bps {
            let reduction = (self.current_bitrate_bps as f64 * 0.40) as u32; // Aggressive 40% reduction
            let new_bitrate = self
                .current_bitrate_bps
                .saturating_sub(reduction)
                .max(self.min_bitrate_bps);

            if new_bitrate != self.current_bitrate_bps {
                warn!(
                    "ABR FAST-PATH: Severe latency detected ({}ms), dropping bitrate to {} bps",
                    rtt_ms, new_bitrate
                );
                self.current_bitrate_bps = new_bitrate;
                self.send_bitrate_update();
                self.last_evaluation = Instant::now(); // Reset timer to avoid double-dip
                self.congestion_count = 0;
                return;
            }
        }

        // Check if it's time for regular evaluation
        if self.last_evaluation.elapsed() < Duration::from_millis(self.evaluation_interval_ms) {
            return;
        }

        self.last_evaluation = Instant::now();
        self.evaluate(rtt_ms);
    }

    /// Update with the latest packet loss count
    pub fn update_loss(&mut self, _lost_packets: u64) {
        // TODO: Implement loss-based bitrate reduction for improved internet streaming.
        // RustDesk uses loss as a primary indicator for congestion.
    }

    /// Evaluate current conditions and adjust bitrate
    fn evaluate(&mut self, current_rtt_ms: u128) {
        // Calculate smoothed RTT (average of recent history)
        let smoothed_rtt = if self.rtt_history.is_empty() {
            current_rtt_ms
        } else {
            self.rtt_history.iter().sum::<u128>() / self.rtt_history.len() as u128
        };

        if smoothed_rtt > self.rtt_threshold_ms {
            // Congestion detected
            self.congestion_count += 1;

            if self.congestion_count >= self.congestion_threshold {
                // Reduce bitrate by 25%
                let reduction = (self.current_bitrate_bps as f64 * 0.25) as u32;
                let new_bitrate = self.current_bitrate_bps.saturating_sub(reduction);
                let new_bitrate = new_bitrate.max(self.min_bitrate_bps);

                if new_bitrate != self.current_bitrate_bps {
                    info!(
                        "Adaptive bitrate: congestion detected (RTT={}ms, smoothed={}ms), reducing from {} to {} bps",
                        current_rtt_ms, smoothed_rtt, self.current_bitrate_bps, new_bitrate
                    );
                    self.current_bitrate_bps = new_bitrate;
                    self.send_bitrate_update();
                }

                // Reset congestion counter after adjustment
                self.congestion_count = 0;
            }
        } else {
            // Good conditions — gradually increase bitrate
            self.congestion_count = 0;

            // If RTT is well below threshold, try increasing by 10%
            if smoothed_rtt < self.rtt_threshold_ms / 2
                && self.current_bitrate_bps < self.max_bitrate_bps
            {
                let increase = (self.current_bitrate_bps as f64 * 0.10) as u32;
                let new_bitrate = self.current_bitrate_bps + increase;
                let new_bitrate = new_bitrate.min(self.max_bitrate_bps);

                if new_bitrate != self.current_bitrate_bps {
                    debug!(
                        "Adaptive bitrate: good conditions (RTT={}ms), increasing from {} to {} bps",
                        current_rtt_ms, self.current_bitrate_bps, new_bitrate
                    );
                    self.current_bitrate_bps = new_bitrate;
                    self.send_bitrate_update();
                }
            }
        }
    }

    /// Send the current bitrate to the encoder
    fn send_bitrate_update(&self) {
        if let Some(ref tx) = self.bitrate_tx
            && tx.send(self.current_bitrate_bps).is_err()
        {
            warn!("Bitrate receiver dropped, adaptive bitrate disabled");
        }
    }

    /// Get the current target bitrate
    pub fn current_bitrate_bps(&self) -> u32 {
        self.current_bitrate_bps
    }

    /// Get smoothed RTT estimate
    pub fn smoothed_rtt_ms(&self) -> Option<u128> {
        if self.rtt_history.is_empty() {
            None
        } else {
            Some(self.rtt_history.iter().sum::<u128>() / self.rtt_history.len() as u128)
        }
    }

    /// Reset the controller to initial state
    pub fn reset(&mut self) {
        self.current_bitrate_bps = self.min_bitrate_bps;
        self.rtt_history.clear();
        self.congestion_count = 0;
        self.last_evaluation = Instant::now();
    }
}

/// Profiles for different streaming scenarios
pub struct BitrateProfiles;

impl BitrateProfiles {
    /// LAN streaming — high bitrate, low latency tolerance
    pub fn lan_profile() -> AdaptiveBitrate {
        let mut ab = AdaptiveBitrate::new(8_000_000, 2_000_000, 20_000_000);
        ab.set_rtt_threshold_ms(100); // Aggressive reduction on LAN
        ab.set_evaluation_interval_ms(1000);
        ab
    }

    /// Internet streaming — moderate bitrate, higher tolerance
    pub fn internet_profile() -> AdaptiveBitrate {
        let mut ab = AdaptiveBitrate::new(4_000_000, 500_000, 10_000_000);
        ab.set_rtt_threshold_ms(200); // More tolerant on internet
        ab.set_evaluation_interval_ms(3000);
        ab
    }

    /// Low bandwidth profile — conservative bitrate
    pub fn low_bandwidth_profile() -> AdaptiveBitrate {
        let mut ab = AdaptiveBitrate::new(1_000_000, 200_000, 3_000_000);
        ab.set_rtt_threshold_ms(150);
        ab.set_evaluation_interval_ms(2000);
        ab
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_starts_disengaged() {
        let ceiling = LossCeiling::new(8_000_000);
        assert_eq!(
            ceiling.ceiling(),
            u32::MAX,
            "a session must begin at its configured rate, not a reduced one"
        );
    }

    #[test]
    fn a_congested_link_cuts_and_a_barely_lossy_one_is_left_alone() {
        // Counters are cumulative since the handshake, which is what `sample`
        // is fed; each call below therefore only raises them.
        let mut ceiling = LossCeiling::new(8_000_000);
        // A quiet tick: nothing sent, so nothing known.
        ceiling.sample(0, 0);
        assert_eq!(ceiling.ceiling(), u32::MAX, "an idle tick is not a signal");
        // 1 packet in 200 sits between the clean and congested thresholds —
        // the deadband, where the answer is to hold still.
        ceiling.sample(1, 200);
        assert_eq!(
            ceiling.ceiling(),
            u32::MAX,
            "0.5 % loss must not move the rate: got {}",
            ceiling.ceiling()
        );
        // Now it is congested: 20 lost in the next 200 sent.
        ceiling.sample(21, 400);
        assert_eq!(ceiling.ceiling(), 6_400_000, "20 % off the configured rate");
    }

    #[test]
    fn a_still_desktops_tiny_sample_cannot_cut_the_rate() {
        // Damage-driven capture sends almost nothing when nothing moves, and
        // one lost packet out of four is 25 % by ratio. Acting on that would
        // floor a healthy LAN link the moment the user stops moving windows.
        let mut ceiling = LossCeiling::new(8_000_000);
        ceiling.sample(1, 4);
        assert_eq!(ceiling.ceiling(), u32::MAX);
    }

    #[test]
    fn sustained_loss_stops_at_the_floor() {
        let mut ceiling = LossCeiling::new(8_000_000);
        for tick in 1..=40u64 {
            ceiling.sample(tick * 1_000, tick * 1_000);
        }
        assert_eq!(
            ceiling.ceiling(),
            LOSS_BITRATE_FLOOR_BPS,
            "the rate must stop where the picture stops being usable"
        );
    }

    #[test]
    fn a_configured_rate_below_the_floor_is_never_raised() {
        let mut ceiling = LossCeiling::new(500_000);
        ceiling.sample(1_000, 1_000);
        assert_eq!(
            ceiling.ceiling(),
            500_000,
            "the floor cannot out-run the user's setting"
        );
    }

    #[test]
    fn loss_recovers_stepwise_and_disengages_at_the_configured_rate() {
        let mut ceiling = LossCeiling::new(8_000_000);
        ceiling.sample(20, 200);
        let cut = ceiling.ceiling();
        assert_eq!(cut, 6_400_000);
        ceiling.sample(20, 400);
        assert_eq!(
            ceiling.ceiling(),
            (cut as f64 * 1.10) as u32,
            "recovery must be a step, not a jump back"
        );
        for tick in 1..=20u64 {
            ceiling.sample(20, 400 + tick * 200);
        }
        assert_eq!(
            ceiling.ceiling(),
            u32::MAX,
            "a fully recovered link must stop being a term at all"
        );
    }

    #[test]
    fn loss_reduces_from_whatever_is_already_in_force() {
        // A preset or relay clamp that already cut the rate is the starting
        // point, so the loss term can never push the encoder above a ceiling
        // the user or the path asked for.
        assert_eq!(
            next_loss_ceiling(8_000_000, 2_000_000, 1_000, 100),
            1_600_000
        );
        assert_eq!(
            next_loss_ceiling(8_000_000, u32::MAX, 1_000, 100),
            6_400_000
        );
    }

    #[test]
    fn counters_going_backwards_are_not_negative_loss() {
        // A transport that restarted its counters must not read as having
        // *un*-lost packets, and must not be mistaken for a clean link either
        // — the sample floor holds the ceiling where it was.
        let mut ceiling = LossCeiling::new(8_000_000);
        ceiling.sample(500, 1_000);
        let after_cut = ceiling.ceiling();
        assert!(after_cut < 8_000_000);
        ceiling.sample(0, 0);
        assert_eq!(
            ceiling.ceiling(),
            after_cut,
            "no information must mean no change"
        );
    }

    #[test]
    fn test_initial_bitrate() {
        let controller = AdaptiveBitrate::new(5_000_000, 1_000_000, 10_000_000);
        assert_eq!(controller.current_bitrate_bps(), 5_000_000);
    }

    #[test]
    fn test_congestion_reduces_bitrate() {
        let mut controller = AdaptiveBitrate::new(8_000_000, 1_000_000, 20_000_000);
        controller.set_rtt_threshold_ms(100);
        controller.set_evaluation_interval_ms(0); // Evaluate immediately

        // Simulate 3 consecutive high RTT readings
        for _ in 0..3 {
            controller.update_rtt(200); // Above threshold
        }

        // Bitrate should have been reduced by 25%
        assert!(
            controller.current_bitrate_bps() < 8_000_000,
            "Bitrate should decrease after congestion: got {}",
            controller.current_bitrate_bps()
        );
        // Should be 75% of original
        let expected = (8_000_000.0 * 0.75) as u32;
        assert_eq!(controller.current_bitrate_bps(), expected);
    }

    #[test]
    fn test_good_conditions_increase_bitrate() {
        let mut controller = AdaptiveBitrate::new(2_000_000, 500_000, 10_000_000);
        controller.set_rtt_threshold_ms(100);
        controller.set_evaluation_interval_ms(0);

        // Reset congestion counter and force evaluation timer old
        controller.congestion_count = 0;
        controller.last_evaluation = Instant::now() - Duration::from_secs(10);

        // Simulate good conditions (RTT well below threshold/2)
        for _ in 0..5 {
            controller.update_rtt(10); // Well below 50ms (threshold/2)
        }

        // Bitrate should have increased by 10% from the initial value
        // After 5 evaluations with good conditions, should be above initial
        assert!(
            controller.current_bitrate_bps() >= 2_000_000,
            "Bitrate should increase after good conditions: got {}",
            controller.current_bitrate_bps()
        );
    }

    #[test]
    fn test_bitrate_respects_bounds() {
        let mut controller = AdaptiveBitrate::new(500_000, 200_000, 1_000_000);
        controller.set_rtt_threshold_ms(100);
        controller.set_evaluation_interval_ms(0);

        // Force many congestion reductions
        for _ in 0..20 {
            controller.update_rtt(200);
            controller.congestion_count = 2; // Force immediate reduction
        }

        // Should not go below minimum
        assert!(
            controller.current_bitrate_bps() >= controller.min_bitrate_bps,
            "Bitrate should not go below minimum: got {}",
            controller.current_bitrate_bps()
        );
    }

    #[test]
    fn test_rtt_history_smoothing() {
        let mut controller = AdaptiveBitrate::new(5_000_000, 1_000_000, 10_000_000);

        // Add several RTT measurements
        for i in 0..15 {
            controller.update_rtt((100 + i * 10) as u128);
        }

        // History should be capped at 10
        assert!(controller.rtt_history.len() <= 10);

        // Smoothed RTT should be available
        assert!(controller.smoothed_rtt_ms().is_some());
    }

    #[test]
    fn test_reset() {
        let mut controller = AdaptiveBitrate::new(5_000_000, 1_000_000, 10_000_000);
        controller.update_rtt(200);
        controller.update_rtt(200);
        controller.update_rtt(200);

        controller.reset();

        assert_eq!(controller.current_bitrate_bps(), 1_000_000); // Reset to min
        assert!(controller.rtt_history.is_empty());
        assert_eq!(controller.congestion_count, 0);
    }

    #[test]
    fn test_bitrate_profiles() {
        let lan = BitrateProfiles::lan_profile();
        assert_eq!(lan.current_bitrate_bps(), 8_000_000);
        assert_eq!(lan.rtt_threshold_ms, 100);

        let internet = BitrateProfiles::internet_profile();
        assert_eq!(internet.current_bitrate_bps(), 4_000_000);
        assert_eq!(internet.rtt_threshold_ms, 200);

        let low = BitrateProfiles::low_bandwidth_profile();
        assert_eq!(low.current_bitrate_bps(), 1_000_000);
    }
}
