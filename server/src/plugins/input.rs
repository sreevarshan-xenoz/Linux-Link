use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};

#[derive(Debug, Default)]
pub struct InputPlugin;

impl InputPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl Plugin for InputPlugin {
    fn name(&self) -> &'static str {
        "input"
    }

    fn incoming_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.mousepad.request", "kdeconnect.presenter"]
    }

    fn outgoing_capabilities(&self) -> &'static [&'static str] {
        &["kdeconnect.mousepad.echo"]
    }

    async fn handle_packet(&self, packet: &NetworkPacket, sender: &dyn DeviceSender) -> Result<()> {
        match packet.packet_type.as_str() {
            "kdeconnect.mousepad.request" => {
                let body = &packet.body;

                // Handle mouse movement
                if let (Some(x), Some(y)) = (
                    body.get("dx").and_then(|v| v.as_f64()),
                    body.get("dy").and_then(|v| v.as_f64()),
                ) {
                    if x != 0.0 || y != 0.0 {
                        move_mouse(x, y).await?;
                    }
                }

                // Handle mouse button events
                if let Some(is_pressed) = body.get("isPressed").and_then(|v| v.as_bool()) {
                    if let Some(button) = body.get("button").and_then(|v| v.as_i64()) {
                        mouse_button(button as i32, is_pressed).await?;
                    }
                }

                // Handle scroll events
                if let (Some(x), Some(y)) = (
                    body.get("dx").and_then(|v| v.as_f64()),
                    body.get("dy").and_then(|v| v.as_f64()),
                ) {
                    if x != 0.0 || y != 0.0 {
                        // Small deltas are mouse movement, larger ones are scroll
                        if x.abs() > 10.0 || y.abs() > 10.0 {
                            // Already handled as mouse movement above
                        }
                    }
                }

                // Handle keyboard input
                if let Some(key) = body.get("key").and_then(|v| v.as_str()) {
                    // Special key handling
                    handle_special_key(key).await?;
                }

                if let Some(text) = body.get("text").and_then(|v| v.as_str()) {
                    type_text(text).await?;
                }

                // Echo back for mousepad protocol
                let echo = NetworkPacket::new("kdeconnect.mousepad.echo");
                sender.send_packet(&echo).await?;
            }
            "kdeconnect.presenter" => {
                // Presenter remote - handle play/pause/next/previous
                if let Some(action) = packet.body.get("action").and_then(|v| v.as_str()) {
                    handle_presenter_action(action).await?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Move the mouse by relative amounts.
async fn move_mouse(dx: f64, dy: f64) -> Result<()> {
    let xdotool_args = format!("{:.0} {:.0}", dx, dy);
    tokio::process::Command::new("xdotool")
        .args(["mouse_relative", "--", &xdotool_args])
        .output()
        .await
        .context("failed to execute xdotool for mouse movement")?;
    Ok(())
}

/// Press or release a mouse button.
async fn mouse_button(button: i32, pressed: bool) -> Result<()> {
    let action = if pressed { "mousedown" } else { "mouseup" };
    let btn = button.to_string();
    tokio::process::Command::new("xdotool")
        .args([action, &btn])
        .output()
        .await
        .context("failed to execute xdotool for mouse button")?;
    Ok(())
}

/// Type text using xdotool.
async fn type_text(text: &str) -> Result<()> {
    tokio::process::Command::new("xdotool")
        .args(["type", "--", text])
        .output()
        .await
        .context("failed to execute xdotool for typing")?;
    Ok(())
}

/// Handle special keys (Enter, Escape, arrows, etc.).
async fn handle_special_key(key: &str) -> Result<()> {
    let xdotool_key = match key {
        "Enter" | "\n" | "\r" => "Return",
        "Escape" => "Escape",
        "BackSpace" => "BackSpace",
        "Tab" => "Tab",
        "Delete" => "Delete",
        "Insert" => "Insert",
        "Home" => "Home",
        "End" => "End",
        "PageUp" => "Page_Up",
        "PageDown" => "Page_Down",
        "ArrowUp" | "Up" => "Up",
        "ArrowDown" | "Down" => "Down",
        "ArrowLeft" | "Left" => "Left",
        "ArrowRight" | "Right" => "Right",
        "F1" => "F1",
        "F2" => "F2",
        "F3" => "F3",
        "F4" => "F4",
        "F5" => "F5",
        "F6" => "F6",
        "F7" => "F7",
        "F8" => "F8",
        "F9" => "F9",
        "F10" => "F10",
        "F11" => "F11",
        "F12" => "F12",
        other => other, // Pass through as-is
    };

    tokio::process::Command::new("xdotool")
        .args(["key", xdotool_key])
        .output()
        .await
        .context("failed to execute xdotool for key press")?;
    Ok(())
}

/// Handle presenter remote actions.
async fn handle_presenter_action(action: &str) -> Result<()> {
    match action {
        "play" | "pause" | "next" | "prev" | "previous" => {
            let key = match action {
                "next" | "previous" | "prev" => "Next",
                "play" | "pause" => "space",
                _ => action,
            };
            tokio::process::Command::new("xdotool")
                .args(["key", key])
                .output()
                .await
                .context("failed to execute xdotool for presenter action")?;
        }
        other => {
            tracing::debug!("Unknown presenter action: {}", other);
        }
    }
    Ok(())
}
