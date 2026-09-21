use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "linux-link")]
#[command(about = "Linux Link - secure remote desktop over Tailscale")]
pub struct Cli {
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the server daemon
    Start,
    /// Stop a running server process started with `linux-link start`
    Stop,
    /// Print local tailscale status
    Status,
    /// Show recorded streaming-session outcomes (R4 A2 telemetry log)
    Sessions {
        /// Number of recent sessions to list
        #[arg(short, long, default_value_t = 10)]
        count: usize,
    },
    /// List peers currently visible on the tailnet
    List,
    /// Continuously watch peer discovery events
    Watch {
        /// Poll interval in seconds
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
    },
    /// Show configured KDE Connect capability sets
    Capabilities,
    /// Connect to a peer and perform a basic control-channel handshake
    Connect {
        /// Peer hostname, MagicDNS name, or Tailscale IP
        peer: String,
        /// Control port to connect to
        #[arg(short, long, default_value_t = linux_link_core::DEFAULT_CONTROL_PORT)]
        port: u16,
    },
    /// Set or generate a temporary pairing PIN
    Pair {
        /// Optional 6-digit PIN
        pin: Option<String>,
        /// Time-box the trust this PIN grants (e.g. 45s, 15m, 2h, 7d).
        /// Omit for permanent trust. R4 D3 one-off support sessions.
        #[arg(long, value_parser = parse_grant_secs)]
        grant: Option<u64>,
    },
    /// Remove a paired device from the trust store (all if no id is given)
    Unpair {
        /// Device id to untrust (omit to untrust all devices)
        device_id: Option<String>,
    },
}

/// Parse a `--grant` duration (`45s`, `15m`, `2h`, `7d`, combinable like
/// `1h30m`) into seconds. Used as a clap `value_parser` so bad input fails
/// at argument parsing.
pub fn parse_grant_secs(input: &str) -> Result<u64, String> {
    let unit_secs = |c: char| match c {
        's' => Some(1u64),
        'm' => Some(60),
        'h' => Some(3600),
        'd' => Some(86400),
        _ => None,
    };
    let mut total = 0u64;
    let mut digits = String::new();
    let mut saw_unit = false;
    for c in input.trim().chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            let unit = unit_secs(c)
                .ok_or_else(|| format!("invalid unit '{c}' in '{input}' (expected s/m/h/d)"))?;
            if digits.is_empty() {
                return Err(format!("missing number before '{c}' in '{input}'"));
            }
            total += digits.parse::<u64>().map_err(|e| e.to_string())? * unit;
            digits.clear();
            saw_unit = true;
        }
    }
    if !digits.is_empty() || !saw_unit {
        return Err(format!(
            "'{input}' must be a number with a unit, e.g. 15m (s/m/h/d, combinable: 1h30m)"
        ));
    }
    if total == 0 || total > 365 * 86400 {
        return Err(format!("grant must be between 1s and 365d, got '{input}'"));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::parse_grant_secs;

    #[test]
    fn grant_durations_parse() {
        assert_eq!(parse_grant_secs("45s"), Ok(45));
        assert_eq!(parse_grant_secs("15m"), Ok(900));
        assert_eq!(parse_grant_secs("2h"), Ok(7200));
        assert_eq!(parse_grant_secs("1h30m"), Ok(5400));
        assert_eq!(parse_grant_secs(" 10m "), Ok(600));
    }

    #[test]
    fn grant_rejects_bad_input() {
        for bad in ["", "15", "15x", "m", "1h-30m", "0s", "366d", "1w"] {
            assert!(parse_grant_secs(bad).is_err(), "must reject {bad:?}");
        }
    }
}
