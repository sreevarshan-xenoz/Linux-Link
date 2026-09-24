//! Turning cumulative counters into rates the HUD is allowed to quote.
//!
//! The bridge counts received frames and bytes in atomics (see
//! [`crate::session`]). Dividing a session's totals by its lifetime answers a
//! question nobody is asking while they watch a picture: the number is a
//! weighted average of every second since the session started, so a link that
//! stalled a minute ago still reads as healthy, and a link that just recovered
//! still reads as stalled. These functions exist so the HUD's rate and RTT
//! numbers describe the window they were measured over, and so the display can
//! say how much of a sample that window really is.

use std::time::{Duration, Instant};

/// One read of the cumulative counters: when, and how much had arrived by then.
pub type Snapshot = (Instant, u64, u64);

/// The reads a window is measured across, oldest first — what [`push_snapshot`]
/// produces and [`rates_over`] consumes.
pub type History = Vec<Snapshot>;

/// What the link delivered over the window a set of snapshots covers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rates {
    pub fps: f64,
    pub kbps: u64,
    /// The span the two numbers above were divided by. Shorter than the
    /// requested window at session start, which is when a rate is least
    /// trustworthy and the display has to be able to say so.
    pub span: Duration,
}

impl Rates {
    fn nothing() -> Self {
        Self {
            fps: 0.0,
            kbps: 0,
            span: Duration::ZERO,
        }
    }
}

/// Below this, a rate is arithmetic noise rather than a measurement: two reads
/// a few milliseconds apart produce a number that means nothing about the link.
const MIN_SPAN: Duration = Duration::from_millis(250);

/// Frames and bytes received, as a rate over the newest `window` of reads.
pub fn rates_over(snapshots: &[Snapshot], window: Duration) -> Rates {
    let Some(&(newest_at, newest_frames, newest_bytes)) = snapshots.last() else {
        return Rates::nothing();
    };
    // Walking back from the newest read, the oldest one still inside the window
    // is the base of the diff. Counters are monotonic within a session because
    // `push_snapshot` discards a dead session's history, so what the two reads
    // differ by is exactly the traffic the window carried.
    let Some(&(base_at, base_frames, base_bytes)) = snapshots
        .iter()
        .rev()
        .take_while(|&&(at, _, _)| newest_at - at <= window)
        .last()
    else {
        return Rates::nothing();
    };
    let span = newest_at - base_at;
    if span < MIN_SPAN {
        return Rates::nothing();
    }
    // Kilobits over the exact span, in integer microsecond maths: casting the
    // duration to whole seconds would turn a 2.6 s window into a 2 s one and
    // inflate the rate.
    let micros = span.as_micros().max(1) as u64;
    Rates {
        fps: (newest_frames - base_frames) as f64 / span.as_secs_f64(),
        kbps: (newest_bytes - base_bytes) * 8_000 / micros,
        span,
    }
}

/// Record a read of the counters, keeping only what a window can need.
///
/// A new session resets the counters to zero (see `stop_streaming`), so a read
/// that counts *less* than the one before it ends the previous session's
/// history: diffing across that boundary would subtract one session's total from
/// another's and call the result a rate.
pub fn push_snapshot(history: &mut History, at: Instant, frames: u64, bytes: u64) {
    if history
        .last()
        .is_some_and(|&(_, f, b)| frames < f || bytes < b)
    {
        history.clear();
    }
    history.push((at, frames, bytes));
    let cutoff = at - RATE_HISTORY;
    let stale = history
        .iter()
        .take_while(|&&(at, _, _)| at < cutoff)
        .count();
    history.drain(..stale);
}

/// How much history [`push_snapshot`] keeps: the HUD's window, plus the slack a
/// poller that reads on a fixed interval can miss by.
pub const RATE_HISTORY: Duration = Duration::from_secs(10);

/// The window the HUD's rates are measured over.
pub const RATE_WINDOW: Duration = Duration::from_secs(3);

/// How many one-second RTT polls the link figure is drawn from.
pub const RTT_SAMPLES: usize = 8;

/// The middle of a set of values, or `None` when there is nothing to summarise.
///
/// The transport reports one smoothed RTT per poll, and neither quinn nor iroh
/// exposes its variance, so a median of successive polls is the most confidence
/// this number can carry: stable against the single spike a mean would absorb,
/// and its sample count says how little history stands behind it.
pub fn median(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    Some(if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) / 2
    })
}

/// Keep only the newest `limit` entries of a rolling sample buffer.
pub fn trim<T>(buffer: &mut Vec<T>, limit: usize) {
    let stale = buffer.len().saturating_sub(limit);
    buffer.drain(..stale);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `Instant` cannot be constructed, so fixtures shift off a real one:
    /// only the differences between reads matter to a measurement.
    fn now() -> Instant {
        Instant::now() + Duration::from_secs(1_000)
    }

    fn history(entries: &[(u64, u64, u64)]) -> History {
        let start = now();
        entries
            .iter()
            .map(|(secs, frames, bytes)| (start + Duration::from_secs(*secs), *frames, *bytes))
            .collect()
    }

    #[test]
    fn a_rate_is_measured_over_the_window_not_over_the_session() {
        // A session that ran bright for a minute and then settled at 30 fps:
        // the lifetime average would still be quoting that first minute.
        let snapshots = history(&[
            (0, 0, 0),
            (59, 1_800, 90_000_000),
            (60, 1_830, 91_500_000),
            (61, 1_860, 93_000_000),
            (62, 1_890, 94_500_000),
        ]);
        let rates = rates_over(&snapshots, RATE_WINDOW);
        assert_eq!(rates.fps.round(), 30.0, "30 frames/s across the window");
        assert_eq!(rates.span, Duration::from_secs(3));
        assert_eq!(rates.kbps, 12_000, "4.5 MB in 3 s is 12 Mbit/s");
    }

    #[test]
    fn an_older_snapshot_outside_the_window_is_not_used_as_the_base() {
        // Two seconds of real history, so the divisor is two seconds and not a
        // minute of idle time that would read as a dead link.
        let snapshots = history(&[(0, 0, 0), (30, 300, 30_000_000), (32, 360, 33_000_000)]);
        let rates = rates_over(&snapshots, RATE_WINDOW);
        assert_eq!(rates.span, Duration::from_secs(2));
        assert_eq!(rates.fps.round(), 30.0);
    }

    #[test]
    fn one_read_is_a_span_of_nothing_and_reports_no_rate() {
        let snapshots = history(&[(0, 500, 5_000_000)]);
        assert_eq!(rates_over(&snapshots, RATE_WINDOW), Rates::nothing());
        assert_eq!(rates_over(&history(&[]), RATE_WINDOW), Rates::nothing());
    }

    #[test]
    fn reads_a_few_milliseconds_apart_produce_no_number() {
        // A rate from 40 ms of samples is arithmetic, not a measurement.
        let start = now();
        let snapshots: History = [
            (Duration::ZERO, 0u64, 0u64),
            (Duration::from_millis(40), 2, 100_000),
        ]
        .iter()
        .map(|(d, f, b)| (start + *d, *f, *b))
        .collect();
        assert_eq!(
            rates_over(&snapshots, RATE_WINDOW),
            Rates::nothing(),
            "the 250 ms floor keeps a burst of polls from reading as a rate"
        );
    }

    #[test]
    fn a_counter_reset_ends_the_previous_sessions_history() {
        let mut history = History::new();
        let t = now();
        push_snapshot(&mut history, t, 10_000, 50_000_000);
        push_snapshot(&mut history, t + Duration::from_secs(1), 10_300, 51_000_000);
        // A new session counts from zero. Averaging across the boundary would
        // subtract one session's total from another's.
        push_snapshot(&mut history, t + Duration::from_secs(2), 5, 100_000);
        assert_eq!(history.len(), 1, "the dead session's reads are gone");
        assert_eq!(
            rates_over(&history, RATE_WINDOW),
            Rates::nothing(),
            "one read is not yet a rate"
        );
        push_snapshot(&mut history, t + Duration::from_secs(3), 35, 200_000);
        let rates = rates_over(&history, RATE_WINDOW);
        assert_eq!(rates.fps.round(), 30.0, "30 frames over the 1 s span");
        assert_eq!(rates.span, Duration::from_secs(1));
    }

    #[test]
    fn history_beyond_the_window_slides_out() {
        let mut history = History::new();
        let t = now();
        for secs in 0..30 {
            push_snapshot(
                &mut history,
                t + Duration::from_secs(secs),
                secs * 30,
                secs * 1_000,
            );
        }
        assert_eq!(
            history.len(),
            RATE_HISTORY.as_secs() as usize + 1,
            "one read per second survives a {} s history, no more",
            RATE_HISTORY.as_secs()
        );
        assert!(
            t + Duration::from_secs(29) - history.first().unwrap().0 <= RATE_HISTORY,
            "the oldest read kept is still inside the history"
        );
        assert_eq!(history.len(), RATE_HISTORY.as_secs() as usize + 1);
    }

    #[test]
    fn the_median_ignores_one_spike_a_mean_would_absorb() {
        assert_eq!(median(&[28_000, 27_000, 29_000, 900_000]), Some(28_500));
        assert_eq!(median(&[28_000]), Some(28_000));
        assert_eq!(median(&[]), None);
    }

    #[test]
    fn a_sample_buffer_keeps_only_the_newest_reads() {
        let mut buffer: Vec<u64> = Vec::new();
        for value in 0..20 {
            buffer.push(value);
            trim(&mut buffer, RTT_SAMPLES);
            assert!(buffer.len() <= RTT_SAMPLES);
        }
        assert_eq!(buffer.last(), Some(&19));
        assert_eq!(buffer.first(), Some(&12));
    }
}
