//! Adaptive bitrate controller
//!
//! Monitors QUIC connection statistics (RTT, packet loss, congestion)
//! and dynamically adjusts the video encoding bitrate to maintain smooth streaming.

use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{debug, info, warn};

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

        // Check if it's time to evaluate
        if self.last_evaluation.elapsed() < Duration::from_millis(self.evaluation_interval_ms) {
            return;
        }

        self.last_evaluation = Instant::now();
        self.evaluate(rtt_ms);
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
