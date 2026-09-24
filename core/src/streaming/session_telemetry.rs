//! R4 A2 — per-stream-session outcome telemetry.
//!
//! Every video pipeline run is observed by a [`SessionRecorder`] and written
//! as one `key=value` line through a host-registered sink (the server appends
//! to a rotating file under its state dir). This is the instrument the relay
//! research says we need: hole punching succeeds ~70% of the time even after
//! prerequisites, so *how* sessions actually connect on real networks —
//! LAN, punched-direct, or riding a relay — must be measured, not guessed.
//!
//! Wire-level goodput (bytes the transport actually pushed) is logged, not
//! encoder output: backlog trims make those numbers differ, and the transport
//! number is what the user experiences.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::metrics::{Samples, Summary};

use super::connection::{SharedConnection, TransportFamily};

/// Terminal classification of one streaming session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Normal end of a pipeline run — graded against transport family and
    /// observed paths by [`SessionRecorder::finish`] (never logged as-is).
    Completed,
    /// Quinn (LAN / Tailscale-routable) connection — always direct.
    LanDirect,
    /// iroh WAN whose sampled paths were all direct (punched).
    WanPunched,
    /// iroh WAN that rode a relay at some point during the session.
    WanRelayed,
    /// Rejected before the pipeline started (e.g. pairing gate).
    Rejected,
    /// Pipeline torn down by an error (capture/encoder/transport failure).
    Failed,
}

impl SessionOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionOutcome::Completed => "completed",
            SessionOutcome::LanDirect => "lan_direct",
            SessionOutcome::WanPunched => "wan_punched",
            SessionOutcome::WanRelayed => "wan_relayed",
            SessionOutcome::Rejected => "rejected",
            SessionOutcome::Failed => "failed",
        }
    }
}

/// One log line, already classified. Built by [`SessionRecorder::finish`].
#[derive(Debug, Clone)]
pub struct SessionReport {
    pub unix_secs: u64,
    pub outcome: SessionOutcome,
    /// True if any sample during the session rode a relay, even if the final
    /// one was direct — the punching-completes-mid-session case.
    pub ever_relayed: bool,
    pub duration_secs: u64,
    pub rtt_avg_ms: u64,
    pub goodput_kbps: u64,
    pub device_id: Option<String>,
    /// Link RTT distribution, or `None` when the session never sampled the
    /// transport (immediate teardown).
    pub rtt_tail: Option<Summary>,
    /// Per-frame encode time distribution, or `None` when no frame was encoded.
    pub encode_tail: Option<Summary>,
}

impl SessionReport {
    /// Machine- and human-friendly single line, tab-separated `k=v` fields.
    pub fn format(&self) -> String {
        use std::fmt::Write as _;
        let mut line = String::with_capacity(160);
        write!(
            line,
            "ts={}\toutcome={}\tever_relayed={}\tdur={}\trtt_ms={}\tkbps={}",
            self.unix_secs,
            self.outcome.as_str(),
            self.ever_relayed,
            self.duration_secs,
            self.rtt_avg_ms,
            self.goodput_kbps,
        )
        .expect("writing to String cannot fail");
        if let Some(tail) = &self.rtt_tail {
            write!(line, "\t{}", tail.format_tail("rtt")).expect("infallible");
        }
        if let Some(tail) = &self.encode_tail {
            write!(line, "\t{}", tail.format_tail("enc")).expect("infallible");
        }
        if let Some(id) = &self.device_id {
            // Defensive: ids are UTF-8 device names from the pairing layer.
            let id = id.replace(['\t', '\n'], " ");
            write!(line, "\tdev={id}").expect("infallible");
        }
        line
    }
}

type Sink = std::sync::Arc<dyn Fn(&SessionReport) + Send + Sync + 'static>;

static SINK: OnceLock<Sink> = OnceLock::new();

/// Register the process-wide report sink. First caller wins; unset means
/// telemetry is off (every recorder becomes a no-op) — the default for
/// clients and tests that never wire a log up.
pub fn set_session_telemetry_callback<F>(f: F)
where
    F: Fn(&SessionReport) + Send + Sync + 'static,
{
    let _ = SINK.set(std::sync::Arc::new(f));
}

fn sink() -> Option<&'static Sink> {
    SINK.get()
}

/// Live recorder for one pipeline run: passively observes the connection
/// (via the trait's `stats()`), accumulates RTT samples, and emits the
/// report when [`SessionGuard`] is dropped. Cheap enough to poll from any
/// long-running task in the pipeline.
pub struct SessionRecorder {
    started: Instant,
    ever_relayed: AtomicU64,
    rtt_sum_us: AtomicU64,
    rtt_samples: AtomicU64,
    rtt_tail: Samples,
    encode_tail: Samples,
    family: TransportFamily,
    device_id: Option<String>,
}

impl SessionRecorder {
    pub fn new(family: TransportFamily, device_id: Option<String>) -> Self {
        Self {
            started: Instant::now(),
            ever_relayed: AtomicU64::new(0),
            rtt_sum_us: AtomicU64::new(0),
            rtt_samples: AtomicU64::new(0),
            rtt_tail: Samples::new(),
            encode_tail: Samples::new(),
            family,
            device_id,
        }
    }

    /// Observe the connection once. Call every few seconds from a pipeline
    /// task; sessions that never sample (immediate teardown) still log, with
    /// zero-valued samples.
    pub fn sample(&self, connection: &SharedConnection) {
        let stats = connection.stats();
        if stats.relayed {
            self.ever_relayed.store(1, Ordering::Relaxed);
        }
        self.rtt_sum_us
            .fetch_add(stats.rtt.as_micros() as u64, Ordering::Relaxed);
        self.rtt_samples.fetch_add(1, Ordering::Relaxed);
        self.rtt_tail.push_micros(stats.rtt.as_micros() as u64);
    }

    /// Time one `encode_frame` call. Called per frame from the encode task, so
    /// it must stay cheap: a mutex over a bounded array, no allocation.
    pub fn record_encode(&self, elapsed: Duration) {
        self.encode_tail.push_micros(elapsed.as_micros() as u64);
    }

    pub fn finish(&self, outcome: SessionOutcome, bytes_sent: u64) -> SessionReport {
        let duration = self.started.elapsed();
        let duration_secs = duration.as_secs();
        let samples = self.rtt_samples.load(Ordering::Relaxed).max(1);
        let rtt_avg_ms = self.rtt_sum_us.load(Ordering::Relaxed) / samples / 1000;
        let goodput_kbps = (bytes_sent * 8 / 1000)
            .checked_div(duration_secs)
            .unwrap_or(0);
        let ever_relayed = self.ever_relayed.load(Ordering::Relaxed) == 1;
        SessionReport {
            unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            outcome: self.classify(outcome),
            ever_relayed,
            duration_secs,
            rtt_avg_ms,
            goodput_kbps,
            device_id: self.device_id.clone(),
            rtt_tail: self.rtt_tail.summary_ms(),
            encode_tail: self.encode_tail.summary_ms(),
        }
    }

    /// Normalise a pipeline outcome against what was actually observed:
    /// a completed run is graded by transport family (relaying is an iroh
    /// concept — a quinn session is always direct) and by whether a relay
    /// path was ever selected. Rejections/failures are reported as-is.
    fn classify(&self, outcome: SessionOutcome) -> SessionOutcome {
        if outcome != SessionOutcome::Completed {
            return outcome;
        }
        match self.family {
            TransportFamily::Quinn => SessionOutcome::LanDirect,
            TransportFamily::Iroh => {
                if self.ever_relayed.load(Ordering::Relaxed) == 1 {
                    SessionOutcome::WanRelayed
                } else {
                    SessionOutcome::WanPunched
                }
            }
        }
    }

    /// Arm end-of-session logging for one pipeline run. Drop the guard at
    /// every exit point of `run_pipeline`; the guard defaults to
    /// [`SessionOutcome::Failed`] unless the pipeline marks completion (via
    /// [`SessionGuard::mark_completed`]) or records an explicit terminal
    /// outcome (e.g. the pairing-gate rejection).
    pub fn guard(&self, bytes_sent: Arc<AtomicU64>) -> SessionGuard<'_> {
        SessionGuard {
            recorder: self,
            bytes_sent,
            outcome: std::sync::Mutex::new(SessionOutcome::Failed),
            emitted: AtomicBool::new(false),
        }
    }
}

/// Guard that emits the report when the pipeline function returns.
pub struct SessionGuard<'a> {
    recorder: &'a SessionRecorder,
    bytes_sent: Arc<AtomicU64>,
    outcome: std::sync::Mutex<SessionOutcome>,
    emitted: AtomicBool,
}

impl SessionGuard<'_> {
    /// The pipeline reached its normal join/teardown path; the logged
    /// outcome is graded from the transport family and observed paths.
    pub fn mark_completed(&self) {
        if let Ok(mut g) = self.outcome.lock() {
            *g = SessionOutcome::Completed;
        }
    }

    /// Record a terminal outcome that bypasses the normal exit path (e.g.
    /// the pairing gate rejecting an unpaired device).
    pub fn record(&self, outcome: SessionOutcome) {
        if let Ok(mut g) = self.outcome.lock() {
            *g = outcome;
        }
        self.emit();
        self.emitted.store(true, Ordering::Relaxed);
    }

    fn emit(&self) {
        let Some(sink) = sink() else { return };
        let outcome = *self.outcome.lock().unwrap_or_else(|p| p.into_inner());
        let report = self
            .recorder
            .finish(outcome, self.bytes_sent.load(Ordering::Relaxed));
        sink(&report);
        info_line(&report);
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if !self.emitted.load(Ordering::Relaxed) {
            self.emit();
        }
    }
}

/// Mirror the report into the tracing log at a sensible level, so journal
/// readers see the same truth as the file.
fn info_line(report: &SessionReport) {
    let msg = format!("streaming session {}", report.outcome.as_str());
    match report.outcome {
        SessionOutcome::Rejected | SessionOutcome::Failed => tracing::warn!("{msg}"),
        _ => tracing::info!("{msg}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(outcome: SessionOutcome) -> SessionReport {
        SessionReport {
            unix_secs: 123,
            outcome,
            ever_relayed: outcome == SessionOutcome::WanRelayed,
            duration_secs: 10,
            rtt_avg_ms: 42,
            goodput_kbps: 8_000,
            device_id: Some("phone-1".into()),
            rtt_tail: None,
            encode_tail: None,
        }
    }

    #[test]
    fn report_line_has_all_fields() {
        let mut r = report(SessionOutcome::WanRelayed);
        let tails = Samples::new();
        for i in 1..=100u64 {
            tails.push_micros(i * 1_000);
        }
        let tail = tails.summary_ms();
        r.rtt_tail = tail;
        r.encode_tail = tail;
        let line = r.format();
        assert!(line.contains("outcome=wan_relayed"));
        assert!(line.contains("ever_relayed=true"));
        assert!(line.contains("dev=phone-1"));
        assert!(line.contains("kbps=8000"));
        // Both tails present, each under its own prefix, so a reader can tell a
        // 99th-percentile encode hitch from a 99th-percentile link stall.
        assert!(line.contains("rtt_p99=99\trtt_max=100"), "{line}");
        assert!(line.contains("enc_p99=99\tenc_max=100"), "{line}");
    }

    #[test]
    fn a_session_that_never_encoded_reports_no_encode_tail() {
        let rec = SessionRecorder::new(TransportFamily::Quinn, None);
        let report = rec.finish(SessionOutcome::Completed, 0);
        assert!(report.encode_tail.is_none());
        assert!(report.rtt_tail.is_none());
        // The line stays parsable: no dangling `enc_p50=` with a zero in it.
        let line = report.format();
        assert!(!line.contains("enc_"), "{line}");
        assert!(!line.contains("rtt_p"), "{line}");
    }

    #[test]
    fn encode_samples_reach_the_report_as_a_distribution() {
        // The exact failure the average hides: 10% of frames stall at 30x the
        // typical encode time. Mean 15 ms still reads as "fine" in a log line.
        let rec = SessionRecorder::new(TransportFamily::Quinn, None);
        for _ in 0..90 {
            rec.record_encode(Duration::from_millis(4));
        }
        for _ in 0..10 {
            rec.record_encode(Duration::from_millis(120));
        }
        let report = rec.finish(SessionOutcome::Completed, 0);
        let tail = report.encode_tail.expect("samples were taken");
        assert_eq!(tail.count, 100);
        assert_eq!(
            tail.mean_ms, 15,
            "the mean the old telemetry would have quoted"
        );
        assert_eq!(tail.p50_ms, 4);
        assert_eq!(tail.p95_ms, 120, "a one-in-ten stall has to be visible");
        assert_eq!(tail.p99_ms, 120);
        assert_eq!(tail.max_ms, 120);
    }

    #[test]
    fn completed_quinn_session_is_lan_direct() {
        let rec = SessionRecorder::new(TransportFamily::Quinn, None);
        let report = rec.finish(SessionOutcome::Completed, 0);
        assert_eq!(report.outcome, SessionOutcome::LanDirect);
    }

    #[test]
    fn completed_iroh_session_is_graded_by_observed_paths() {
        let punched = SessionRecorder::new(TransportFamily::Iroh, None);
        assert_eq!(
            punched.finish(SessionOutcome::Completed, 0).outcome,
            SessionOutcome::WanPunched
        );
        let relayed = SessionRecorder::new(TransportFamily::Iroh, None);
        relayed.ever_relayed.store(1, Ordering::Relaxed);
        assert_eq!(
            relayed.finish(SessionOutcome::Completed, 0).outcome,
            SessionOutcome::WanRelayed
        );
    }

    #[test]
    fn explicit_outcomes_are_not_reclassified() {
        let rec = SessionRecorder::new(TransportFamily::Iroh, None);
        for outcome in [SessionOutcome::Rejected, SessionOutcome::Failed] {
            let report = rec.finish(outcome, 0);
            assert_eq!(report.outcome, outcome);
        }
        // guard() is what the pipeline arms; it must be constructible.
        let _guard = rec.guard(Arc::new(AtomicU64::new(0)));
    }
}
