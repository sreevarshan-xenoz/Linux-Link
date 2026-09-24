//! Tail latency: percentile sampling for the metrics that decide whether a
//! session feels good (roadmap 2141-2146).
//!
//! An average hides the failure class this project keeps shipping: a link that
//! encodes in 4 ms on average but in 120 ms on one frame in fifty looks fine in
//! a log line and stutters on the phone. So a [`Samples`] reservoir keeps enough
//! of the distribution to answer p50/p90/p95/p99/max instead.
//!
//! Storage is bounded by design — a two-hour session at 60 fps is 432 000
//! samples, and keeping them all to compute a median would be absurd. Below
//! capacity every sample is kept and the percentiles are *exact*; past it the
//! reservoir switches to Algorithm R (each observation replaces a random slot
//! with probability capacity/seen), which keeps the percentiles unbiased
//! estimates over the whole session rather than a sliding window over the tail.
//! `max` and `count` stay exact either way, because they are tracked on the way
//! in and never depend on what survived the reservoir.

use std::sync::Mutex;

/// Samples retained per metric. ~64 KiB per metric, ~320 KiB for the five the
/// session record carries.
pub const DEFAULT_CAPACITY: usize = 8_192;

/// One percentile read-out, in milliseconds, as it appears in a session record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Observations taken over the whole session (not the retained subset).
    pub count: u64,
    pub mean_ms: u64,
    pub p50_ms: u64,
    pub p90_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
}

impl Summary {
    /// `key_n=…\tkey_p50=…\t…` — the tab-separated tail the session log line
    /// carries, so a record stays parseable by `split('\t')` and greppable by
    /// prefix. The mean is deliberately absent: a line already has one place for
    /// an average, and this one is for the tail.
    pub fn format_tail(&self, key: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = write!(
            s,
            "{key}_n={}\t{key}_p50={}\t{key}_p90={}\t{key}_p95={}\t{key}_p99={}\t{key}_max={}",
            self.count, self.p50_ms, self.p90_ms, self.p95_ms, self.p99_ms, self.max_ms
        );
        s
    }
}

struct Reservoir {
    kept: Vec<u64>,
    capacity: usize,
    seen: u64,
    sum_us: u128,
    max_us: u64,
    rng: u64,
}

/// A lock-free-in-spirit, thread-safe sample collector: push microseconds, get
/// a [`Summary`] at the end. Cloning is not supported — one owner per metric,
/// shared behind an `Arc` like the rest of the session recorder.
pub struct Samples {
    inner: Mutex<Reservoir>,
}

impl Default for Samples {
    fn default() -> Self {
        Self::new()
    }
}

impl Samples {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(Reservoir {
                kept: Vec::with_capacity(capacity.min(65_536)),
                capacity: capacity.max(1),
                seen: 0,
                sum_us: 0,
                max_us: 0,
                // Fixed seed: the stream's own timing decides which samples are
                // unusual, and a deterministic substitute is far easier to test.
                rng: 0x9E37_79B9_7F4A_7C15,
            }),
        }
    }

    /// Record one observation in microseconds.
    pub fn push_micros(&self, value_us: u64) {
        let mut r = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        r.seen += 1;
        r.sum_us += u128::from(value_us);
        if value_us > r.max_us {
            r.max_us = value_us;
        }
        if r.kept.len() < r.capacity {
            r.kept.push(value_us);
            return;
        }
        // Algorithm R: keep the reservoir a uniform random sample of everything
        // seen, so a spike early in the session is not erased by a calm tail.
        let slot = r.next_rand() % r.seen;
        if (slot as usize) < r.capacity {
            r.kept[slot as usize] = value_us;
        }
    }

    /// Number of observations taken, exact.
    pub fn count(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).seen
    }

    /// `None` when nothing was recorded, so a session that never encoded a frame
    /// reports "no encode samples" instead of a confident zero.
    pub fn summary_ms(&self) -> Option<Summary> {
        let mut r = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if r.kept.is_empty() {
            return None;
        }
        r.kept.sort_unstable();
        let mean_us = (r.sum_us / u128::from(r.seen)) as u64;
        Some(Summary {
            count: r.seen,
            mean_ms: mean_us / 1_000,
            p50_ms: percentile_us(&r.kept, 50) / 1_000,
            p90_ms: percentile_us(&r.kept, 90) / 1_000,
            p95_ms: percentile_us(&r.kept, 95) / 1_000,
            p99_ms: percentile_us(&r.kept, 99) / 1_000,
            max_ms: r.max_us / 1_000,
        })
    }

    /// Percentiles and max together as `(p50, p90, p95, p99, max)` in
    /// microseconds — the shape the benchmark regression check compares.
    pub fn tail_us(&self) -> Option<(u64, u64, u64, u64, u64)> {
        let mut r = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if r.kept.is_empty() {
            return None;
        }
        r.kept.sort_unstable();
        Some((
            percentile_us(&r.kept, 50),
            percentile_us(&r.kept, 90),
            percentile_us(&r.kept, 95),
            percentile_us(&r.kept, 99),
            r.max_us,
        ))
    }
}

impl Reservoir {
    /// xorshift64*: enough entropy for a reservoir draw, no dependency, and it
    /// cannot be zero-seeded into a fixed point.
    fn next_rand(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Nearest-rank percentile (`ceil(p/100 · n)`-th smallest, 1-based). Reported as
/// an actual observed sample rather than interpolated between two, because a
/// latency claim that names a number nobody ever experienced is not a
/// measurement.
fn percentile_us(sorted: &[u64], p: u64) -> u64 {
    debug_assert!(!sorted.is_empty());
    let n = sorted.len() as u64;
    let rank = (p * n).div_ceil(100).clamp(1, n) as usize;
    sorted[rank - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_all(samples: &Samples, values: impl IntoIterator<Item = u64>) {
        for v in values {
            samples.push_micros(v);
        }
    }

    #[test]
    fn no_samples_is_no_claim() {
        assert!(Samples::new().summary_ms().is_none());
        assert!(Samples::new().tail_us().is_none());
    }

    #[test]
    fn a_single_sample_is_its_own_every_percentile() {
        let s = Samples::new();
        s.push_micros(8_400);
        let sum = s.summary_ms().unwrap();
        assert_eq!(sum.count, 1);
        assert_eq!(
            (sum.p50_ms, sum.p90_ms, sum.p99_ms, sum.max_ms),
            (8, 8, 8, 8)
        );
    }

    #[test]
    fn below_capacity_percentiles_are_exact() {
        let s = Samples::new();
        push_all(&s, (1..=100).map(|i| i * 1_000));
        let sum = s.summary_ms().unwrap();
        assert_eq!(sum.count, 100);
        assert_eq!(sum.p50_ms, 50);
        assert_eq!(sum.p90_ms, 90);
        assert_eq!(sum.p95_ms, 95);
        assert_eq!(sum.p99_ms, 99);
        assert_eq!(sum.max_ms, 100);
        assert_eq!(sum.mean_ms, 50);
    }

    #[test]
    fn nearest_rank_rounds_up_to_an_observed_value() {
        let s = Samples::new();
        // 10 samples: p99 is rank ceil(9.9)=10, not an interpolation at 9.9.
        push_all(&s, (1..=10).map(|i| i * 1_000));
        let sum = s.summary_ms().unwrap();
        assert_eq!((sum.p90_ms, sum.p99_ms), (9, 10));
    }

    #[test]
    fn reservoir_stays_bounded_and_keeps_count_and_max_exact() {
        let s = Samples::with_capacity(64);
        push_all(&s, 0..200_000u64);
        let sum = s.summary_ms().unwrap();
        assert_eq!(sum.count, 200_000);
        assert_eq!(sum.max_ms, 199);
        assert!(s.inner.lock().unwrap().kept.len() <= 64);
    }

    #[test]
    fn a_saturated_session_still_estimates_its_median() {
        // 1..=N is uniform, so the true median is N/2; a reservoir that quietly
        // became a sliding window over the last 64 samples would report ~3N/4.
        let s = Samples::with_capacity(4_096);
        push_all(&s, (0..100_000u64).map(|i| i * 1_000));
        let sum = s.summary_ms().unwrap();
        assert!(
            sum.p50_ms > 45_000 && sum.p50_ms < 55_000,
            "p50 {} ms is >10% off the true median (50 000 ms) of a uniform stream",
            sum.p50_ms
        );
        assert!(sum.p99_ms > sum.p50_ms);
    }

    #[test]
    fn one_early_spike_survives_a_calm_tail() {
        // The reason for a whole-session reservoir rather than a window: a
        // 900 ms hitch ten frames in must still show up at p99 an hour later.
        let s = Samples::with_capacity(128);
        s.push_micros(900_000);
        push_all(&s, (0..4_000u64).map(|_| 4_000));
        let sum = s.summary_ms().unwrap();
        assert_eq!(sum.max_ms, 900);
        assert_eq!(sum.count, 4_001);
        assert_eq!(sum.p99_ms, 4);
    }

    #[test]
    fn format_tail_emits_one_key_per_stat_and_no_average() {
        let s = Samples::new();
        push_all(&s, (1..=100).map(|i| i * 1_000));
        let line = s.summary_ms().unwrap().format_tail("enc");
        assert!(line.starts_with("enc_n=100\tenc_p50=50"));
        for key in ["enc_p50", "enc_p90", "enc_p95", "enc_p99", "enc_max"] {
            assert!(line.contains(key), "missing {key} in {line}");
        }
        assert!(
            !line.contains("mean"),
            "the tail line must not carry a mean"
        );
        assert!(!line.contains('\n'));
    }
}
