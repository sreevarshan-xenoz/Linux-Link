use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use tokio::process::Command;

/// Power management plugin — handles sleep, shutdown, and restart commands.
///
/// Listens for `kdeconnect.linuxlink.power` packets and executes the
/// corresponding systemctl command on the host.
pub struct PowerPlugin;

impl Default for PowerPlugin {
    fn default() -> Self {
        Self
    }
}

impl PowerPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Plugin for PowerPlugin {
    fn name(&self) -> &'static str {
        "power"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.linuxlink.power"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &[]
    }

    async fn handle_packet(
        &self,
        packet: &NetworkPacket,
        _sender: &dyn DeviceSender,
    ) -> Result<()> {
        if packet.packet_type.as_str() == "kdeconnect.linuxlink.power" {
            let body = &packet.body;
            let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("");

            match action {
                "sleep" => execute_systemctl("suspend").await,
                "shutdown" => execute_systemctl("poweroff").await,
                "restart" => execute_systemctl("reboot").await,
                "hibernate" => execute_systemctl("hibernate").await,
                other => {
                    tracing::warn!("Unknown power action: {other}");
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
}

/// Execute a systemctl command with `pkexec` for privilege escalation
/// (falls back to direct systemctl for passwordless sudo configurations).
async fn execute_systemctl(action: &str) -> Result<()> {
    tracing::info!("Executing power action: {action}");

    // Try pkexec first (Ubuntu/GNOME default), then fall back to direct systemctl
    let pkexec_result = match Command::new("pkexec").arg("systemctl").arg(action).spawn() {
        Ok(mut child) => match child.wait().await {
            Ok(status) => Some(status.success()),
            Err(e) => {
                tracing::warn!("pkexec wait error for '{action}': {e}");
                None
            }
        },
        Err(e) => {
            tracing::warn!("pkexec not available for '{action}': {e}");
            None
        }
    };

    match pkexec_result {
        Some(true) => {
            tracing::info!("Power action '{action}' succeeded via pkexec");
            return Ok(());
        }
        _ => {
            // pkexec failed or unavailable — try direct systemctl
            tracing::warn!("pkexec failed for '{action}', trying direct systemctl");
        }
    }

    // Fallback: try direct systemctl
    let output = Command::new("systemctl")
        .arg(action)
        .output()
        .await
        .with_context(|| format!("Failed to run systemctl {action}"))?;

    if output.status.success() {
        tracing::info!("Power action '{action}' succeeded via direct systemctl");
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Power action '{action}' failed: {stderr}",);
    }
}
