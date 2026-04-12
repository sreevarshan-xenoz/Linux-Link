//! Native input injection with fallback chain: enigo (X11/XWayland) -> uinput (kernel-level)
//!
//! Tries enigo first (works on X11 and XWayland sessions).
//! Falls back to evdev/uinput (works on ALL compositors, requires /dev/uinput access).
//! uinput creates virtual HID devices at the kernel level, so every compositor sees them as real input devices.

use anyhow::{Context, Result};
use enigo::{Enigo, Key, Keyboard, Mouse, Coordinate, Settings};
use evdev::uinput::VirtualDeviceBuilder;
use evdev::{AttributeSet, InputEvent, KeyCode, RelativeAxisCode};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

/// Event type constants from evdev kernel API
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_SYN: u16 = 0x00;
const SYN_REPORT: u16 = 0;

/// Backend for input injection.
#[derive(Debug)]
enum InputBackend {
    /// enigo (X11/XWayland via XTEST)
    Enigo(Mutex<Enigo>),
    /// uinput (universal, kernel-level)
    Uinput(Mutex<evdev::uinput::VirtualDevice>),
}

/// Cross-distro input injector.
///
/// Tries enigo (X11) first, falls back to uinput (kernel-level virtual device).
/// uinput works on ALL compositors but requires /dev/uinput access (root or uinput group).
pub struct InputInjector {
    backend: InputBackend,
}

impl InputInjector {
    /// Create a new input injector.
    ///
    /// Tries enigo (X11/XWayland) first. If that fails, falls back to
    /// uinput (kernel-level virtual input device).
    pub fn new() -> Result<Self> {
        // Try enigo first (works on X11 and XWayland)
        if let Ok(enigo) = Enigo::new(&Settings::default()) {
            info!("Input injector: using enigo (X11/XWayland)");
            return Ok(Self {
                backend: InputBackend::Enigo(Mutex::new(enigo)),
            });
        }

        // Fall back to uinput
        Self::new_uinput()
    }

    /// Create a uinput-based input injector.
    fn new_uinput() -> Result<Self> {
        if !Path::new("/dev/uinput").exists() {
            anyhow::bail!(
                "/dev/uinput not found. Input injection requires either:\n\
                 - X11/XWayland session (for enigo/XTEST), or\n\
                 - /dev/uinput device (run: sudo modprobe uinput)"
            );
        }

        // Build a virtual keyboard + mouse device
        let mut keys = AttributeSet::<KeyCode>::new();
        // Add all common keys
        for keycode in 0..256u16 {
            keys.insert(KeyCode(keycode));
        }

        let mut rel = AttributeSet::<RelativeAxisCode>::new();
        rel.insert(RelativeAxisCode::REL_X);
        rel.insert(RelativeAxisCode::REL_Y);
        rel.insert(RelativeAxisCode::REL_WHEEL);
        rel.insert(RelativeAxisCode::REL_HWHEEL);

        #[allow(deprecated)]
        let device = VirtualDeviceBuilder::new()
            .context("Failed to create virtual device builder")?
            .with_keys(&keys)
            .context("Failed to set up virtual keys")?
            .with_relative_axes(&rel)
            .context("Failed to set up relative axes")?
            .name(b"Linux Link Virtual Input")
            .build()
            .context("Failed to build virtual device. \
                     Ensure /dev/uinput is accessible (add user to 'uinput' group).")?;

        info!("Input injector: using uinput (kernel-level, works on all compositors)");
        Ok(Self {
            backend: InputBackend::Uinput(Mutex::new(device)),
        })
    }

    /// Move mouse by relative delta
    pub fn move_mouse_relative(&mut self, dx: i32, dy: i32) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                e.move_mouse(dx, dy, Coordinate::Rel)
                    .context("enigo mouse move failed")?;
                Ok(())
            }
            InputBackend::Uinput(device) => {
                let mut dev = device.lock().unwrap();
                let events = [
                    InputEvent::new(EV_REL, RelativeAxisCode::REL_X.0, dx),
                    InputEvent::new(EV_REL, RelativeAxisCode::REL_Y.0, dy),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0), // SYN_REPORT
                ];
                dev.emit(&events).context("uinput mouse move failed")?;
                Ok(())
            }
        }
    }

    /// Move mouse to absolute position
    #[allow(dead_code)]
    pub fn move_mouse_absolute(&mut self, x: i32, y: i32) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                e.move_mouse(x, y, Coordinate::Abs)
                    .context("enigo mouse move to absolute position failed")?;
                Ok(())
            }
            InputBackend::Uinput(_device) => {
                // uinput only supports relative movement for mice.
                // Absolute positioning would require a virtual tablet device.
                anyhow::bail!("uinput backend does not support absolute mouse positioning")
            }
        }
    }

    /// Press or release a mouse button
    pub fn mouse_button(&mut self, button: MouseKey, pressed: bool) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                if pressed {
                    e.button(button.as_enigo_button(), enigo::Direction::Press)
                        .context("enigo mouse press failed")?;
                } else {
                    e.button(button.as_enigo_button(), enigo::Direction::Release)
                        .context("enigo mouse release failed")?;
                }
                Ok(())
            }
            InputBackend::Uinput(device) => {
                let mut dev = device.lock().unwrap();
                let key = button.as_evdev_key();
                let value = if pressed { 1 } else { 0 };
                let events = [
                    InputEvent::new(EV_KEY, key.0, value),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                dev.emit(&events).context("uinput mouse click failed")?;
                Ok(())
            }
        }
    }

    /// Scroll the mouse wheel
    #[allow(dead_code)]
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                if y != 0 {
                    e.scroll((y.abs() / 10).max(1), enigo::Axis::Vertical)
                        .context("enigo vertical scroll failed")?;
                }
                if x != 0 {
                    e.scroll((x.abs() / 10).max(1), enigo::Axis::Horizontal)
                        .context("enigo horizontal scroll failed")?;
                }
                Ok(())
            }
            InputBackend::Uinput(device) => {
                let mut dev = device.lock().unwrap();
                let events = [
                    InputEvent::new(EV_REL, RelativeAxisCode::REL_WHEEL.0, y),
                    InputEvent::new(EV_REL, RelativeAxisCode::REL_HWHEEL.0, x),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                dev.emit(&events).context("uinput scroll failed")?;
                Ok(())
            }
        }
    }

    /// Press and release a single key
    pub fn key(&mut self, key: Key, pressed: bool) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                if pressed {
                    e.key(key, enigo::Direction::Press).context("enigo key press failed")?;
                } else {
                    e.key(key, enigo::Direction::Release).context("enigo key release failed")?;
                }
                Ok(())
            }
            InputBackend::Uinput(device) => {
                let mut dev = device.lock().unwrap();
                let evdev_key = key_to_evdev(key);
                let value = if pressed { 1 } else { 0 };
                let events = [
                    InputEvent::new(EV_KEY, evdev_key.0, value),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                dev.emit(&events).context("uinput key failed")?;
                Ok(())
            }
        }
    }

    /// Type text by entering it as unicode characters
    pub fn text(&mut self, text: &str) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let mut e = enigo.lock().unwrap();
                e.text(text).context("enigo text input failed")?;
                Ok(())
            }
            InputBackend::Uinput(device) => {
                // For uinput, fall back to keycode simulation for ASCII.
                // This is a best-effort approach and does not handle Unicode.
                for ch in text.chars() {
                    if let Some(keycode) = char_to_keycode(ch) {
                        let key = KeyCode(keycode);
                        let mut dev = device.lock().unwrap();
                        let events = [
                            InputEvent::new(EV_KEY, key.0, 1), // press
                            InputEvent::new(EV_SYN, SYN_REPORT, 0),
                            InputEvent::new(EV_KEY, key.0, 0), // release
                            InputEvent::new(EV_SYN, SYN_REPORT, 0),
                        ];
                        dev.emit(&events).context("uinput text input failed")?;
                    } else {
                        debug!("Cannot type character with uinput: {ch:?}");
                    }
                }
                Ok(())
            }
        }
    }
}

/// Mouse button mapping for enigo/uinput
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

    fn as_evdev_key(&self) -> KeyCode {
        match *self {
            MouseKey::Left => KeyCode::BTN_LEFT,
            MouseKey::Middle => KeyCode::BTN_MIDDLE,
            MouseKey::Right => KeyCode::BTN_RIGHT,
            MouseKey::Button4 => KeyCode::BTN_SIDE,  // Side button (back)
            MouseKey::Button5 => KeyCode::BTN_EXTRA, // Extra button (forward)
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

/// Map a Linux evdev keycode to an enigo Key.
fn keycode_to_enigo(code: u16) -> Key {
    match code {
        36 => Key::Return,
        14 => Key::Backspace,
        65 => Key::Space,
        23 => Key::Tab,
        1 => Key::Escape,
        103 => Key::UpArrow,
        108 => Key::DownArrow,
        105 => Key::LeftArrow,
        106 => Key::RightArrow,
        59..=68 => Key::F1, // F1-F10 approximate mapping
        _ => Key::Unicode(std::char::from_u32(code as u32).unwrap_or('?')),
    }
}

/// Map an enigo Key to an evdev KeyCode for uinput backend.
fn key_to_evdev(key: Key) -> KeyCode {
    match key {
        Key::Return => KeyCode::KEY_ENTER,
        Key::Backspace => KeyCode::KEY_BACKSPACE,
        Key::Space => KeyCode::KEY_SPACE,
        Key::Tab => KeyCode::KEY_TAB,
        Key::Escape => KeyCode::KEY_ESC,
        Key::UpArrow => KeyCode::KEY_UP,
        Key::DownArrow => KeyCode::KEY_DOWN,
        Key::LeftArrow => KeyCode::KEY_LEFT,
        Key::RightArrow => KeyCode::KEY_RIGHT,
        Key::F1 => KeyCode::KEY_F1,
        Key::F2 => KeyCode::KEY_F2,
        Key::F3 => KeyCode::KEY_F3,
        Key::F4 => KeyCode::KEY_F4,
        Key::F5 => KeyCode::KEY_F5,
        Key::F6 => KeyCode::KEY_F6,
        Key::F7 => KeyCode::KEY_F7,
        Key::F8 => KeyCode::KEY_F8,
        Key::F9 => KeyCode::KEY_F9,
        Key::F10 => KeyCode::KEY_F10,
        Key::F11 => KeyCode::KEY_F11,
        Key::F12 => KeyCode::KEY_F12,
        Key::Delete => KeyCode::KEY_DELETE,
        Key::Insert => KeyCode::KEY_INSERT,
        Key::Home => KeyCode::KEY_HOME,
        Key::End => KeyCode::KEY_END,
        Key::PageUp => KeyCode::KEY_PAGEUP,
        Key::PageDown => KeyCode::KEY_PAGEDOWN,
        Key::Unicode(ch) => char_to_evdev_key(ch).unwrap_or(KeyCode::KEY_UNKNOWN),
        _ => KeyCode::KEY_UNKNOWN,
    }
}

/// Map a character to a Linux evdev keycode.
/// Only handles basic ASCII. Returns None for unsupported characters.
fn char_to_keycode(ch: char) -> Option<u16> {
    match ch {
        // QWERTY layout keycodes (evdev standard)
        'q' | 'Q' => Some(16),
        'w' | 'W' => Some(17),
        'e' | 'E' => Some(18),
        'r' | 'R' => Some(19),
        't' | 'T' => Some(20),
        'y' | 'Y' => Some(21),
        'u' | 'U' => Some(22),
        'i' | 'I' => Some(23),
        'o' | 'O' => Some(24),
        'p' | 'P' => Some(25),
        'a' | 'A' => Some(30),
        's' | 'S' => Some(31),
        'd' | 'D' => Some(32),
        'f' | 'F' => Some(33),
        'g' | 'G' => Some(34),
        'h' | 'H' => Some(35),
        'j' | 'J' => Some(36),
        'k' | 'K' => Some(37),
        'l' | 'L' => Some(38),
        'z' | 'Z' => Some(44),
        'x' | 'X' => Some(45),
        'c' | 'C' => Some(46),
        'v' | 'V' => Some(47),
        'b' | 'B' => Some(48),
        'n' | 'N' => Some(49),
        'm' | 'M' => Some(50),
        // Numbers
        '0' => Some(11),
        '1'..='9' => Some(ch as u16 - '1' as u16 + 2),
        // Special
        ' ' => Some(57),
        '\n' => Some(36),
        '\t' => Some(23),
        _ => None,
    }
}

/// Map a Unicode character to an evdev KeyCode.
fn char_to_evdev_key(ch: char) -> Option<KeyCode> {
    char_to_keycode(ch).map(|code| KeyCode(code))
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

    #[test]
    fn test_char_to_keycode_lowercase() {
        assert_eq!(char_to_keycode('a'), Some(30)); // KEY_A
        assert_eq!(char_to_keycode('z'), Some(44)); // KEY_Z
    }

    #[test]
    fn test_char_to_keycode_uppercase() {
        assert_eq!(char_to_keycode('A'), Some(30));
        assert_eq!(char_to_keycode('Z'), Some(44));
    }

    #[test]
    fn test_char_to_keycode_numbers() {
        assert_eq!(char_to_keycode('0'), Some(11));
        assert_eq!(char_to_keycode('1'), Some(2));
        assert_eq!(char_to_keycode('9'), Some(10));
    }

    #[test]
    fn test_char_to_keycode_space() {
        assert_eq!(char_to_keycode(' '), Some(57));
    }

    #[test]
    fn test_char_to_keycode_unsupported() {
        assert_eq!(char_to_keycode('\u{00e9}'), None);
        assert_eq!(char_to_keycode('\u{4e2d}'), None);
    }

    #[test]
    fn test_keycode_to_enigo_common() {
        assert_eq!(keycode_to_enigo(36), Key::Return);
        assert_eq!(keycode_to_enigo(14), Key::Backspace);
        assert_eq!(keycode_to_enigo(65), Key::Space);
    }

    #[test]
    fn test_key_to_evdev_common() {
        assert_eq!(key_to_evdev(Key::Return), KeyCode::KEY_ENTER);
        assert_eq!(key_to_evdev(Key::Backspace), KeyCode::KEY_BACKSPACE);
        assert_eq!(key_to_evdev(Key::Space), KeyCode::KEY_SPACE);
        assert_eq!(key_to_evdev(Key::Escape), KeyCode::KEY_ESC);
    }

    #[test]
    fn test_key_to_evdev_arrows() {
        assert_eq!(key_to_evdev(Key::UpArrow), KeyCode::KEY_UP);
        assert_eq!(key_to_evdev(Key::DownArrow), KeyCode::KEY_DOWN);
        assert_eq!(key_to_evdev(Key::LeftArrow), KeyCode::KEY_LEFT);
        assert_eq!(key_to_evdev(Key::RightArrow), KeyCode::KEY_RIGHT);
    }

    #[test]
    fn test_key_to_evdev_unicode() {
        assert_eq!(key_to_evdev(Key::Unicode('a')), KeyCode::KEY_A);
        assert_eq!(key_to_evdev(Key::Unicode('z')), KeyCode::KEY_Z);
        assert_eq!(key_to_evdev(Key::Unicode('1')), KeyCode::KEY_1);
    }
}
