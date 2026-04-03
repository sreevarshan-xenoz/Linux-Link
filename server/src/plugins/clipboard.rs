use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct ClipboardPlugin;

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
                    set_clipboard(content).await?;
                    tracing::debug!("Clipboard updated from remote ({} chars)", content.len());
                }
            }
            "kdeconnect.clipboard.connect" => {
                // Client wants initial clipboard sync - send current content
                match get_clipboard().await {
                    Ok(content) => {
                        let timestamp = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);
                        let response =
                            NetworkPacket::new("kdeconnect.clipboard").with_body(json!({
                                "content": content,
                                "timestamp": timestamp,
                            }));
                        sender.send_packet(&response).await?;
                    }
                    Err(e) => {
                        tracing::debug!("No clipboard content to sync: {}", e);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Read text content from the system clipboard (X11 primary + regular).
async fn get_clipboard() -> Result<String> {
    // Try wl-clipboard first (Wayland native)
    match tokio::process::Command::new("wl-paste").output().await {
        Ok(output) if output.status.success() => {
            return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        _ => {}
    }

    // Fallback to xclip (X11 compatibility)
    match tokio::process::Command::new("xclip")
        .args(["-selection", "clipboard", "-o"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            return Ok(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        _ => {}
    }

    anyhow::bail!("no clipboard tool available (tried wl-paste, xclip)")
}

/// Set the system clipboard to the given text.
async fn set_clipboard(content: &str) -> Result<()> {
    // Try wl-clipboard first
    match tokio::process::Command::new("wl-copy")
        .stdin(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(output) if output.status.success() => return Ok(()),
        _ => {}
    }

    // Fallback to xclip
    let mut child = tokio::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("xclip not available")?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(content.as_bytes())
            .await
            .context("failed to write clipboard data")?;
    }

    child.wait().await.context("xclip failed")?;

    Ok(())
}
