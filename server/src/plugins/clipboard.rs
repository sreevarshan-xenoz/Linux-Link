use linux_link_core::error::Result;
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct ClipboardPlugin;

impl Default for ClipboardPlugin {
    fn default() -> Self {
        Self
    }
}

impl ClipboardPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Plugin for ClipboardPlugin {
    fn name(&self) -> &'static str {
        "clipboard"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.clipboard", "kdeconnect.clipboard.connect"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.clipboard"]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.clipboard" => {
                // Remote clipboard update - set local clipboard
                if let Some(content) = packet.body.get("content").and_then(|v| v.as_str()) {
                    if let Err(e) = set_clipboard(content).await {
                        tracing::warn!("Failed to set clipboard: {}", e);
                    }
                }
            }
            "kdeconnect.clipboard.connect" => {
                // Remote requested our clipboard - get and send it
                if let Ok(content) = get_clipboard().await {
                    let response = NetworkPacket::new("kdeconnect.clipboard").with_body(json!({
                        "content": content,
                        "timestamp": SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis(),
                    }));
                    sender.send_packet(&response).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Set system clipboard using `wl-copy`.
async fn set_clipboard(content: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| linux_link_core::error::LinuxLinkError::Io {
            operation: "spawn wl-copy",
            detail: e.to_string(),
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(content.as_bytes()).await?;
        stdin.flush().await?;
    }

    child.wait().await?;
    Ok(())
}

/// Get system clipboard using `wl-paste`.
async fn get_clipboard() -> Result<String> {
    let output = tokio::process::Command::new("wl-paste")
        .arg("--no-newline")
        .output()
        .await?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(linux_link_core::error::LinuxLinkError::Io {
            operation: "wl-paste",
            detail: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}
