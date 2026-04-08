use anyhow::{Context, Result};
use linux_link_core::protocol::kdeconnect::{DeviceSender, NetworkPacket, Plugin};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::input_injector::{InputInjector, button_id_to_mouse, key_name_to_enigo_key};

/// Input plugin with native input injection via enigo
pub struct InputPlugin {
    injector: Arc<Mutex<Option<InputInjector>>>,
}

impl InputPlugin {
    pub fn new() -> Self {
        Self {
            injector: Arc::new(Mutex::new(None)),
        }
    }

    /// Lazily initialize the injector
    async fn get_injector(&self) -> Result<Arc<Mutex<Option<InputInjector>>>> {
        let mut opt = self.injector.lock().await;
        if opt.is_none() {
            *opt = Some(InputInjector::new().context("Failed to create input injector")?);
            debug!("Input injector initialized on first use");
        }
        Ok(self.injector.clone())
    }
}

impl Default for InputPlugin {
    fn default() -> Self {
        Self::new()
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

                // Handle keyboard input first (text)
                if let Some(text) = body.get("text").and_then(|v| v.as_str())
                    && let Err(e) = self.type_text(text).await
                {
                    warn!("Failed to type text: {}", e);
                }

                // Handle special key
                if let Some(key) = body.get("key").and_then(|v| v.as_str())
                    && let Err(e) = self.press_key(key).await
                {
                    warn!("Failed to press key '{}': {}", key, e);
                }

                // Handle mouse movement
                if let (Some(x), Some(y)) = (
                    body.get("dx").and_then(|v| v.as_f64()),
                    body.get("dy").and_then(|v| v.as_f64()),
                ) && (x != 0.0 || y != 0.0)
                    && let Err(e) = self.move_mouse(x as i32, y as i32).await
                {
                    warn!("Failed to move mouse: {}", e);
                }

                // Handle mouse button events
                if let Some(is_pressed) = body.get("isPressed").and_then(|v| v.as_bool())
                    && let Some(button) = body.get("button").and_then(|v| v.as_i64())
                    && let Err(e) = self.mouse_button(button as i32, is_pressed).await
                {
                    warn!("Failed to handle mouse button: {}", e);
                }

                // Handle scroll events (small deltas are movement, larger ones are scroll)
                if let (Some(x), Some(y)) = (
                    body.get("dx").and_then(|v| v.as_f64()),
                    body.get("dy").and_then(|v| v.as_f64()),
                ) && (x != 0.0 || y != 0.0)
                    && (x.abs() > 10.0 || y.abs() > 10.0)
                {
                    // Already handled as mouse movement above
                }

                // Echo back for mousepad protocol
                let echo = NetworkPacket::new("kdeconnect.mousepad.echo");
                sender.send_packet(&echo).await?;
            }
            "kdeconnect.presenter" => {
                // Presenter remote - handle play/pause/next/previous
                if let Some(action) = packet.body.get("action").and_then(|v| v.as_str())
                    && let Err(e) = self.handle_presenter_action(action).await
                {
                    warn!("Failed to handle presenter action '{}': {}", action, e);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl InputPlugin {
    /// Move the mouse by relative amounts.
    async fn move_mouse(&self, dx: i32, dy: i32) -> Result<()> {
        let injector = self.get_injector().await?;
        let mut inj = injector.lock().await;
        if let Some(ref mut injector) = *inj {
            injector.move_mouse_relative(dx, dy)
        } else {
            unreachable!()
        }
    }

    /// Press or release a mouse button.
    async fn mouse_button(&self, button: i32, pressed: bool) -> Result<()> {
        let injector = self.get_injector().await?;
        let mut inj = injector.lock().await;
        if let Some(ref mut injector) = *inj {
            let mouse_key = button_id_to_mouse(button);
            injector.mouse_button(mouse_key, pressed)
        } else {
            unreachable!()
        }
    }

    /// Type text using native input.
    async fn type_text(&self, text: &str) -> Result<()> {
        let injector = self.get_injector().await?;
        let mut inj = injector.lock().await;
        if let Some(ref mut injector) = *inj {
            injector.text(text)
        } else {
            unreachable!()
        }
    }

    /// Handle special keys (Enter, Escape, arrows, etc.).
    async fn press_key(&self, key: &str) -> Result<()> {
        let injector = self.get_injector().await?;
        let mut inj = injector.lock().await;
        if let Some(ref mut injector) = *inj {
            let enigo_key = key_name_to_enigo_key(key);
            injector.key(enigo_key, true)?;
            injector.key(enigo_key, false)
        } else {
            unreachable!()
        }
    }

    /// Handle presenter remote actions.
    async fn handle_presenter_action(&self, action: &str) -> Result<()> {
        let injector = self.get_injector().await?;
        let mut inj = injector.lock().await;
        if let Some(ref mut injector) = *inj {
            match action {
                "next" | "previous" | "prev" => {
                    let key = if action == "next" {
                        Key::RightArrow
                    } else {
                        Key::LeftArrow
                    };
                    injector.key(key, true)?;
                    injector.key(key, false)?;
                }
                "play" | "pause" => {
                    injector.key(Key::Space, true)?;
                    injector.key(Key::Space, false)?;
                }
                other => {
                    warn!("Unknown presenter action: {}", other);
                }
            }
        }
        Ok(())
    }
}

use enigo::Key;
