//! R4 A2 — server-side session telemetry log.
//!
//! Registers a sink with `core`'s session recorder so every streaming
//! pipeline run appends one outcome line (LAN / WAN punched / WAN relayed /
//! rejected / failed, with duration, mean RTT and wire goodput) to a
//! size-capped log under the state dir. The production counterpart of the
//! research finding that hole punching succeeds ~70% of the time even after
//! prerequisites — the relayed share is a number we must measure, not
//! assume. `linux-link sessions` renders the log for humans.

use crate::state;
use anyhow::Result;
use std::path::PathBuf;

/// Core caps each line's device id at 255 bytes (u8 length prefix), so a
/// 512-byte buffer always holds a full line.
const MAX_LINE_BYTES: usize = 512;
/// Rotation threshold: keep the newest half when the log doubles past it.
const MAX_LOG_BYTES: u64 = 1024 * 1024;

pub fn session_log_path() -> Result<PathBuf> {
    Ok(state::state_dir()?.join("streaming_sessions.log"))
}

/// Install the core telemetry sink → [`record`]. Called once at server
/// startup; a second call is a no-op (core keeps the first sink).
pub fn init() {
    linux_link_core::streaming::set_session_telemetry_callback(|report| {
        if let Err(e) = record(report) {
            tracing::warn!("Failed to record session telemetry: {e}");
        }
    });
}

/// Append one formatted report line, rotating when the log grows past
/// [`MAX_LOG_BYTES`] (newest half kept).
pub fn record(report: &linux_link_core::streaming::SessionReport) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let path = session_log_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    writeln!(file, "{}", report.format())?;
    let size = file.metadata()?.len();
    if size > MAX_LOG_BYTES {
        let mut buf = vec![0u8; (size / 2) as usize];
        file.seek(SeekFrom::End(-(buf.len() as i64)))?;
        file.read_exact(&mut buf)?;
        // Drop a leading partial line from the window we kept.
        let trimmed = match buf.iter().position(|b| *b == b'\n') {
            Some(i) => &buf[i + 1..],
            None => &buf[..],
        };
        // Open fresh (truncating) — the append handle's position is at EOF
        // and keep-all-truncate would race with itself on some filesystems.
        std::fs::write(&path, trimmed)?;
    }
    Ok(())
}

/// Read the last `count` telemetry lines (chronological order).
pub fn read_recent(count: usize) -> Result<Vec<String>> {
    let all = read_recent_from(&session_log_path()?)?;
    let start = all.len().saturating_sub(count.max(1));
    Ok(all[start..].to_vec())
}

/// Read the last `count` lines of a specific log (exposed for tests).
pub fn read_recent_from(path: &PathBuf) -> Result<Vec<String>> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut lines: Vec<String> = String::from_utf8_lossy(&data)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    if lines.len() > 10_000 {
        lines.drain(..lines.len() - 10_000);
    }
    Ok(lines)
}

/// Human summary: outcome tally + the recent tail. Printed by
/// `linux-link sessions`.
pub fn print_sessions(count: usize) -> Result<()> {
    let lines = read_recent(count.max(1))?;
    if lines.is_empty() {
        println!("No streaming sessions recorded yet.");
        println!("(log: {})", session_log_path()?.display());
        return Ok(());
    }
    // Tally from the whole log, tail from the requested window.
    let all = read_recent_from(&session_log_path()?).unwrap_or_default();
    let mut tally: std::collections::BTreeMap<&str, u64> = Default::default();
    for line in &all {
        if let Some(field) = line.split('\t').find(|f| f.starts_with("outcome=")) {
            *tally.entry(&field["outcome=".len()..]).or_default() += 1;
        }
    }
    println!(
        "{} sessions recorded ({}):",
        all.len(),
        session_log_path()?.display()
    );
    for (outcome, n) in &tally {
        println!("  {outcome:<12} {n}");
    }
    let relayed = tally.get("wan_relayed").copied().unwrap_or(0)
        + all
            .iter()
            .filter(|l| l.contains("ever_relayed=true"))
            .count() as u64;
    if !all.is_empty() {
        println!(
            "relayed share: {} of {} ({:.0}%)",
            relayed,
            all.len(),
            100.0 * relayed as f64 / all.len() as f64
        );
    }
    println!("last {}:", count);
    for line in &lines {
        println!("  {line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_link_core::streaming::SessionReport;
    use std::io::Write;

    fn report(outcome: &'static str) -> SessionReport {
        // Build via the core type's fields (they're public).
        let kind = match outcome {
            "lan_direct" => linux_link_core::streaming::SessionOutcome::LanDirect,
            "wan_punched" => linux_link_core::streaming::SessionOutcome::WanPunched,
            "wan_relayed" => linux_link_core::streaming::SessionOutcome::WanRelayed,
            "rejected" => linux_link_core::streaming::SessionOutcome::Rejected,
            _ => linux_link_core::streaming::SessionOutcome::Failed,
        };
        SessionReport {
            unix_secs: 100,
            outcome: kind,
            ever_relayed: kind == linux_link_core::streaming::SessionOutcome::WanRelayed,
            duration_secs: 60,
            rtt_avg_ms: 30,
            goodput_kbps: 5000,
            device_id: Some("pixel-9".into()),
        }
    }

    #[test]
    fn recent_lines_are_chronological_and_capped() {
        let dir = std::env::temp_dir().join(format!("ll-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("streaming_sessions.log");
        for _ in 0..5 {
            let line = format!("{}\n", report("wan_relayed").format());
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
        }
        for outcome in ["lan_direct", "wan_punched", "rejected", "failed"] {
            let line = format!("{}\n", report(outcome).format());
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(line.as_bytes())
                .unwrap();
        }
        let lines = read_recent_from(&path).unwrap();
        assert_eq!(lines.len(), 9);
        assert_eq!(lines[0].matches("outcome=").count(), 1);
        let tail = {
            let mut v = lines.iter().rev().take(3).cloned().collect::<Vec<_>>();
            v.reverse();
            v
        };
        assert!(tail[0].contains("wan_punched"));
        assert!(tail[1].contains("rejected"));
        assert!(tail[2].contains("failed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn outcomes_are_distinguishable_in_the_log() {
        let lan = report("lan_direct").format();
        let punched = report("wan_punched").format();
        let relayed = report("wan_relayed").format();
        assert!(lan.contains("outcome=lan_direct"));
        assert!(punched.contains("outcome=wan_punched"));
        assert!(relayed.contains("outcome=wan_relayed"));
        assert!(relayed.contains("ever_relayed=true"));
        assert!(!punched.contains("ever_relayed=true"));
    }
}
