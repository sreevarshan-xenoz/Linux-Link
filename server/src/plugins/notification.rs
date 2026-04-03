use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};

#[derive(Debug)]
pub struct NotificationPlugin;

impl NotificationPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Plugin for NotificationPlugin {
    fn name(&self) -> &'static str {
        "notification"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.notification", "kdeconnect.notification.request"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.notification"]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.notification" => {
                let body = &packet.body;
                let title = body
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Notification");
                let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
                let app = body.get("app").and_then(|v| v.as_str()).unwrap_or("Remote");

                if let Err(e) = show_desktop_notification(app, title, text).await {
                    tracing::warn!("Failed to show notification: {}", e);
                }
            }
            "kdeconnect.notification.request" => {
                // Acknowledge the request - we support notifications
                let response = NetworkPacket::new("kdeconnect.notification");
                sender.send_packet(&response).await?;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Show a desktop notification via `notify-send` (freedesktop notifications).
async fn show_desktop_notification(app: &str, title: &str, text: &str) -> Result<()> {
    let summary = format!("{}: {}", app, title);

    let output = tokio::process::Command::new("notify-send")
        .args([
            &summary,
            text,
            "--app-name",
            "Linux Link",
            "--expire",
            "5000",
        ])
        .output()
        .await
        .context("failed to execute notify-send")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("notify-send failed: {}", stderr.trim());
    }

    tracing::info!("Notification shown: {} - {}", title, text);
    Ok(())
}
