//! Native input injection using enigo (Wayland/X11 cross-platform)
//!
//! Replaces xdotool subprocess calls with native Rust input simulation.

use anyhow::{Context, Result};
use enigo::{Coordinate, Enigo, Key, Keyboard, Mouse, Settings};
use tracing::debug;

/// Global input injector instance
pub struct InputInjector {
    enigo: Enigo,
}

impl InputInjector {
    /// Create a new input injector
    pub fn new() -> Result<Self> {
        let enigo = Enigo::new(&Settings::default())
            .context("Failed to initialize enigo input injector")?;

        debug!("Input injector initialized");
        Ok(Self { enigo })
    }

    /// Move mouse by relative delta
    pub fn move_mouse_relative(&mut self, dx: i32, dy: i32) -> Result<()> {
        self.enigo
            .move_mouse(dx, dy, Coordinate::Rel)
            .context("Failed to move mouse")?;
        debug!("Mouse moved relative: dx={}, dy={}", dx, dy);
        Ok(())
    }

    /// Move mouse to absolute position
    #[allow(dead_code)]
    pub fn move_mouse_absolute(&mut self, x: i32, y: i32) -> Result<()> {
        self.enigo
            .move_mouse(x, y, Coordinate::Abs)
            .context("Failed to move mouse to absolute position")?;
        debug!("Mouse moved to: x={}, y={}", x, y);
        Ok(())
    }

    /// Press or release a mouse button
    pub fn mouse_button(&mut self, button: MouseKey, pressed: bool) -> Result<()> {
        if pressed {
            self.enigo
                .button(button.as_enigo_button(), enigo::Direction::Press)
                .context("Failed to press mouse button")?;
        } else {
            self.enigo
                .button(button.as_enigo_button(), enigo::Direction::Release)
                .context("Failed to release mouse button")?;
        }
        debug!(
            "Mouse button {:?} {}",
            button,
            if pressed { "pressed" } else { "released" }
        );
        Ok(())
    }

    /// Scroll the mouse wheel
    #[allow(dead_code)]
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<()> {
        if y != 0 {
            self.enigo
                .scroll((y.abs() / 10).max(1), enigo::Axis::Vertical)
                .context("Failed to scroll vertically")?;
        }
        if x != 0 {
            self.enigo
                .scroll((x.abs() / 10).max(1), enigo::Axis::Horizontal)
                .context("Failed to scroll horizontally")?;
        }
        debug!("Scrolled: x={}, y={}", x, y);
        Ok(())
    }

    /// Type a single key
    pub fn key(&mut self, key: Key, pressed: bool) -> Result<()> {
        if pressed {
            self.enigo
                .key(key, enigo::Direction::Press)
                .context("Failed to press key")?;
        } else {
            self.enigo
                .key(key, enigo::Direction::Release)
                .context("Failed to release key")?;
        }
        debug!(
            "Key {:?} {}",
            key,
            if pressed { "pressed" } else { "released" }
        );
        Ok(())
    }

    /// Type text by entering it as unicode characters
    pub fn text(&mut self, text: &str) -> Result<()> {
        self.enigo.text(text).context("Failed to type text")?;
        debug!("Text typed: {} chars", text.chars().count());
        Ok(())
    }
}

/// Mouse button mapping for enigo
#[derive(Debug)]
pub enum MouseKey {
    Left,
    Middle,
    Right,
    Button4,
    Button5,
}

impl MouseKey {
    fn as_enigo_button(&self) -> enigo::Button {
        match *self {
            MouseKey::Left => enigo::Button::Left,
            MouseKey::Middle => enigo::Button::Middle,
            MouseKey::Right => enigo::Button::Right,
            MouseKey::Button4 => enigo::Button::Back,
            MouseKey::Button5 => enigo::Button::Forward,
        }
    }
}

/// Map KDE Connect button IDs to mouse buttons
pub fn button_id_to_mouse(button: i32) -> MouseKey {
    match button {
        1 => MouseKey::Left,
        2 => MouseKey::Middle,
        3 => MouseKey::Right,
        8 => MouseKey::Button4, // Back
        9 => MouseKey::Button5, // Forward
        other => {
            debug!("Unknown mouse button {}, defaulting to left", other);
            MouseKey::Left
        }
    }
}

/// Map key name to enigo Key
pub fn key_name_to_enigo_key(key: &str) -> Key {
    match key {
        "Enter" | "\n" | "\r" => Key::Return,
        "Escape" => Key::Escape,
        "BackSpace" => Key::Backspace,
        "Tab" => Key::Tab,
        "Delete" => Key::Delete,
        "Insert" => Key::Insert,
        "Home" => Key::Home,
        "End" => Key::End,
        "PageUp" => Key::PageUp,
        "PageDown" => Key::PageDown,
        "ArrowUp" | "Up" => Key::UpArrow,
        "ArrowDown" | "Down" => Key::DownArrow,
        "ArrowLeft" | "Left" => Key::LeftArrow,
        "ArrowRight" | "Right" => Key::RightArrow,
        "F1" => Key::F1,
        "F2" => Key::F2,
        "F3" => Key::F3,
        "F4" => Key::F4,
        "F5" => Key::F5,
        "F6" => Key::F6,
        "F7" => Key::F7,
        "F8" => Key::F8,
        "F9" => Key::F9,
        "F10" => Key::F10,
        "F11" => Key::F11,
        "F12" => Key::F12,
        "space" | "Space" => Key::Space,
        other => {
            // For single character keys, try to use them directly
            if other.len() == 1 {
                Key::Unicode(other.chars().next().unwrap_or('?'))
            } else {
                debug!("Unknown key '{}', passing through", other);
                Key::Unicode('?')
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_button_mapping() {
        assert!(matches!(button_id_to_mouse(1), MouseKey::Left));
        assert!(matches!(button_id_to_mouse(2), MouseKey::Middle));
        assert!(matches!(button_id_to_mouse(3), MouseKey::Right));
    }

    #[test]
    fn test_key_mapping() {
        assert!(matches!(key_name_to_enigo_key("Enter"), Key::Return));
        assert!(matches!(key_name_to_enigo_key("Escape"), Key::Escape));
        assert!(matches!(key_name_to_enigo_key("F1"), Key::F1));
        assert!(matches!(key_name_to_enigo_key("ArrowUp"), Key::UpArrow));
    }

    #[test]
    fn test_key_mapping_unicode() {
        assert!(matches!(key_name_to_enigo_key("a"), Key::Unicode('a')));
        assert!(matches!(key_name_to_enigo_key("Z"), Key::Unicode('Z')));
    }
}
