use anyhow::Result;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};

/// F2: Monitor enumeration plugin.
///
/// Responds to `kdeconnect.linuxlink.monitors` queries by reporting
/// the number of monitors available (useful for multi-monitor streaming).
pub struct MonitorsPlugin;

#[async_trait::async_trait]
impl Plugin for MonitorsPlugin {
    fn name(&self) -> &'static str {
        "monitors"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.linuxlink.monitors"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &[]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        if packet.packet_type == "kdeconnect.linuxlink.monitors" {
            let count = enumerate_monitors();
            let response = NetworkPacket::new("kdeconnect.linuxlink.monitors")
                .with_body(serde_json::json!({ "count": count }));
            sender.send_packet(&response).await?;
            tracing::info!("Monitors queried: {count}");
        }
        Ok(())
    }
}

/// Enumerate monitors on the current display server using xrandr (X11) or
/// environment variable heuristics (Wayland). Defaults to 1.
fn enumerate_monitors() -> u32 {
    // Try xrandr (most reliable on X11)
    if let Ok(output) = std::process::Command::new("xrandr")
        .args(["--listmonitors"])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "Monitors: N" from first line
        for line in stdout.lines() {
            if let Some(rest) = line.strip_prefix("Monitors: ") {
                if let Ok(count) = rest.trim().parse::<u32>() {
                    return count.max(1);
                }
                break;
            }
        }
    }

    // Try wlr-randr (Wayland)
    if let Ok(output) = std::process::Command::new("wlr-randr").output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Each output is separated by blank lines
        let count = stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count()
            .max(1) as u32;
        return count;
    }

    // Try kscreen-doctor (KDE Wayland)
    if let Ok(output) = std::process::Command::new("kscreen-doctor")
        .args(["-o"])
        .output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let count = stdout
            .lines()
            .filter(|l| l.contains("Output"))
            .count()
            .max(1) as u32;
        return count;
    }

    // Default: single monitor
    1
}
