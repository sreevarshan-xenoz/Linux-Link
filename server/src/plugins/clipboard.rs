use anyhow::Result;
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
                    if let Err(e) = set_clipboard(content).await {
                        tracing::warn!("Failed to set clipboard: {}", e);
                    } else {
                        tracing::debug!("Clipboard updated from remote ({} chars)", content.len());
                    }
                }
            }
            "kdeconnect.clipboard.connect" => {
                // Client wants initial clipboard sync - send current content
                let content = match get_clipboard().await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("Clipboard unavailable: {}", e);
                        String::new()
                    }
                };
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
            _ => {}
        }
        Ok(())
    }
}

/// Read text content from the system clipboard.
/// Tries: wl-paste (Wayland) -> xclip (X11) -> xsel (X11, lighter).
async fn get_clipboard() -> Result<String> {
    // Try wl-clipboard first (Wayland native)
    match tokio::process::Command::new("wl-paste").arg("--no-newline").output().await {
        Ok(output) if output.status.success() => {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        _ => {}
    }

    // Fallback to xclip (X11 compatibility)
    match tokio::process::Command::new("xclip")
        .args(["-o", "-selection", "clipboard"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        _ => {}
    }

    // Fallback to xsel (lighter X11 alternative)
    match tokio::process::Command::new("xsel")
        .args(["--clipboard", "--output"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
        _ => {}
    }

    anyhow::bail!("No clipboard utility found (tried wl-paste, xclip, xsel)")
}

/// Set the system clipboard to the given text.
/// Tries: wl-copy (Wayland) -> xclip (X11) -> xsel (X11, lighter).
async fn set_clipboard(content: &str) -> Result<()> {
    // Try wl-clipboard first
    match tokio::process::Command::new("wl-copy")
        .arg(content)
        .status()
        .await
    {
        Ok(status) if status.success() => return Ok(()),
        _ => {}
    }

    // Fallback to xclip
    let mut child = match tokio::process::Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            // Try xsel
            let mut child = tokio::process::Command::new("xsel")
                .args(["--clipboard", "--input"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .map_err(|_| anyhow::anyhow!("No clipboard utility found (tried wl-copy, xclip, xsel)"))?;

            if let Some(mut stdin) = child.stdin.take() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(content.as_bytes()).await?;
            }
            child.wait().await?;
            return Ok(());
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(content.as_bytes()).await?;
    }
    child.wait().await?;

    Ok(())
}
