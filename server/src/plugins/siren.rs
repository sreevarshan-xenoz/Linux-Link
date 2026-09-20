use linux_link_core::error::Result;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};

/// Find-my-device siren (KDE Connect parity, Tier-2 #11).
///
/// Answers `kdeconnect.findmydevice` `{ring: true}` by playing a looping
/// system sound for a bounded time, so a phone can make an unattended
/// desktop audible. The same packet pushed *to* a client makes the phone
/// ring; this plugin is the receiving side on the desktop.
#[derive(Debug)]
pub struct SirenPlugin;

impl Default for SirenPlugin {
    fn default() -> Self {
        Self
    }
}

impl SirenPlugin {
    pub fn new() -> Self {
        Self
    }
}

/// How long the desktop siren rings before self-stopping.
const SIREN_SECS: u64 = 30;

/// Candidate sounds, best first: a loopable alarm-ish file from the
/// freedesktop sound theme.
const SOUND_CANDIDATES: &[&str] = &[
    "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga",
    "/usr/share/sounds/freedesktop/stereo/bell.oga",
];

#[async_trait::async_trait]
impl Plugin for SirenPlugin {
    fn name(&self) -> &'static str {
        "siren"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.findmydevice"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &[]
    }

    async fn handle_packet(
        &self,
        packet: &NetworkPacket,
        _sender: &dyn DeviceSender,
    ) -> Result<()> {
        if packet.packet_type == "kdeconnect.findmydevice"
            && packet
                .body
                .get("ring")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
        {
            tokio::spawn(async { ring_desktop(SIREN_SECS).await });
        }
        Ok(())
    }
}

/// Play a looping sound for `secs`, trying each player and file. Never
/// errors out of the plugin: a headless box with no sound setup simply
/// stays quiet.
async fn ring_desktop(secs: u64) {
    for player in ["pw-play", "paplay"] {
        for sound in SOUND_CANDIDATES {
            if !std::path::Path::new(sound).exists() {
                continue;
            }
            // `--loop` exists on both pw-play and paplay.
            let mut child = tokio::process::Command::new(player)
                .args(["--loop", sound])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            match child.as_mut() {
                Ok(c) => {
                    tracing::info!("Find-my-device: ringing desktop via {player} {sound}");
                    let _ =
                        tokio::time::timeout(std::time::Duration::from_secs(secs), c.wait()).await;
                    let _ = c.kill().await;
                    return;
                }
                Err(_) => continue,
            }
        }
    }
    tracing::warn!("Find-my-device: no playable sound found, desktop stays quiet");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sound_candidates_are_absolute_oga_paths() {
        assert!(
            SOUND_CANDIDATES
                .iter()
                .all(|s| s.starts_with('/') && s.ends_with(".oga"))
        );
    }

    #[test]
    fn plugin_declares_findmydevice_capability() {
        assert!(
            SirenPlugin::new()
                .incoming_capabilities()
                .contains(&"kdeconnect.findmydevice")
        );
    }
}
