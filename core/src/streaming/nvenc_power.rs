//! NVENC GPU power pin (R4 C3).
//!
//! NVIDIA's default *adaptive* power management downclocks the GPU between
//! bursty encode work, so the first frames of a session (and any idle gap)
//! pay a clock ramp that shows up as latency jitter. RustDesk and Sunshine
//! both pin the GPU into a high-power state for the duration of an active
//! NVENC session and restore default management afterwards. This is that,
//! driven through `nvidia-smi` (the only tool that reliably works across
//! driver versions without linking NVML).
//!
//! It is strictly best-effort and only ever constructed when an NVENC
//! sidecar actually opened:
//! - no `nvidia-smi` binary (not an NVIDIA box) → no-op;
//! - the clock query or the lock is refused (no privilege, unsupported
//!   feature) → no-op, nothing to restore;
//! - the lock succeeds → an RAII [`NvencPowerGuard`] resets the clocks on
//!   Drop, so session end *and* a dropped-while-degraded encoder both
//!   clean up.
//!
//! The command shapes are pure and unit-tested; the subprocess paths need a
//! real NVIDIA GPU + permission and are desktop/device gated.

use std::process::Command;

use tracing::{debug, info, warn};

/// Query the max graphics clock of GPU 0 (the encode GPU), in MHz, no units.
pub(crate) fn query_args() -> Vec<String> {
    vec![
        "-i".into(),
        "0".into(),
        "--query-gpu=clocks.max.graphics".into(),
        "--format=csv,noheader,nounits".into(),
    ]
}

/// Enable driver persistence mode so the pin survives the query/lock child
/// processes briefly idling the driver (best-effort; ignored on failure).
pub(crate) fn persistence_args() -> Vec<String> {
    vec!["-i".into(), "0".into(), "-pm".into(), "1".into()]
}

/// Lock GPU 0's graphics clock to `max_mhz` (min == max → hold the ceiling).
pub(crate) fn lock_args(max_mhz: u32) -> Vec<String> {
    let range = format!("{max_mhz},{max_mhz}");
    vec!["-i".into(), "0".into(), "--lock-gpu-clocks".into(), range]
}

/// Return GPU 0 to default clock management.
pub(crate) fn reset_args() -> Vec<String> {
    vec!["-i".into(), "0".into(), "--reset-gpu-clocks".into()]
}

/// Parse `nvidia-smi --query-gpu=clocks.max.graphics` output. Accepts a bare
/// number, one with a `mhz` suffix, or leading whitespace; rejects `N/A`,
/// empty, or non-numeric so we never lock to a bogus clock.
pub(crate) fn parse_max_clock(raw: &str) -> Option<u32> {
    let token = raw.split_whitespace().next()?;
    if token.eq_ignore_ascii_case("n/a") {
        return None;
    }
    let mhz: u32 = token.parse().ok()?;
    (mhz > 0).then_some(mhz)
}

/// Held only while the clock lock actually took effect; Drop restores.
pub struct NvencPowerGuard {
    _locked: (),
}

impl NvencPowerGuard {
    /// Attempt to pin GPU 0 to its max graphics clock. Returns `None` (and
    /// logs the reason) whenever the box/tooling/privilege says no, so the
    /// caller never has to special-case non-NVIDIA hosts.
    pub(crate) fn acquire() -> Option<Self> {
        // No NVIDIA tooling → not our problem, silently skip.
        let query = match Command::new("nvidia-smi").args(query_args()).output() {
            Ok(out) => out,
            Err(e) => {
                debug!("nvidia-smi unavailable ({e}); skipping NVENC power pin");
                return None;
            }
        };
        if !query.status.success() {
            debug!("nvidia-smi clock query failed; skipping NVENC power pin");
            return None;
        }
        let raw = String::from_utf8_lossy(&query.stdout);
        let Some(max_mhz) = parse_max_clock(&raw) else {
            warn!("could not parse NVENC max graphics clock from {raw:?}; skipping power pin");
            return None;
        };

        // Persistence mode is advisory — ignore its result.
        let _ = Command::new("nvidia-smi").args(persistence_args()).output();

        match Command::new("nvidia-smi").args(lock_args(max_mhz)).output() {
            Ok(out) if out.status.success() => {
                info!("pinned NVENC GPU 0 graphics clock to {max_mhz} MHz for this session");
                Some(Self { _locked: () })
            }
            Ok(out) => {
                // Typically permission denied; nothing was locked, so no reset.
                let err = String::from_utf8_lossy(&out.stderr);
                warn!(
                    "nvidia-smi clock lock refused ({}); running unpinned",
                    err.trim()
                );
                None
            }
            Err(e) => {
                warn!("failed to run nvidia-smi clock lock ({e}); running unpinned");
                None
            }
        }
    }
}

impl Drop for NvencPowerGuard {
    fn drop(&mut self) {
        match Command::new("nvidia-smi").args(reset_args()).output() {
            Ok(out) if out.status.success() => {
                info!("restored NVENC GPU 0 to default clock management");
            }
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                warn!("nvidia-smi clock reset failed ({})", err.trim());
            }
            Err(e) => warn!("failed to run nvidia-smi clock reset ({e})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_and_suffixed_clocks() {
        assert_eq!(parse_max_clock("1980"), Some(1980));
        assert_eq!(parse_max_clock("1980 mhz\n"), Some(1980));
        assert_eq!(parse_max_clock("   1455\t"), Some(1455));
    }

    #[test]
    fn rejects_unusable_clock_values() {
        assert_eq!(parse_max_clock("N/A"), None);
        assert_eq!(parse_max_clock(""), None);
        assert_eq!(parse_max_clock("0"), None);
        assert_eq!(parse_max_clock("boost"), None);
    }

    #[test]
    fn command_shapes_target_gpu_zero() {
        assert!(query_args().contains(&"--query-gpu=clocks.max.graphics".to_string()));
        assert_eq!(lock_args(1980).last().unwrap(), "1980,1980");
        assert!(lock_args(1980).contains(&"--lock-gpu-clocks".to_string()));
        assert!(reset_args().contains(&"--reset-gpu-clocks".to_string()));
        for args in [query_args(), lock_args(1), reset_args(), persistence_args()] {
            assert!(
                args.windows(2).any(|w| w == ["-i", "0"]),
                "pins GPU 0: {args:?}"
            );
        }
    }
}
