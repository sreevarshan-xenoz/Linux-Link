//! Binary input packet protocol for real-time input forwarding over QUIC.
//!
//! Provides a compact binary encoding for mouse, keyboard, and scroll events,
//! replacing the JSON-over-TCP KDE Connect protocol with a much more efficient
//! format (~3-5 bytes per event vs ~80 bytes JSON).

use anyhow::{Context, Result};

/// Tag byte for each packet variant
const TAG_MOUSE_MOVE: u8 = 0;
const TAG_MOUSE_CLICK: u8 = 1;
const TAG_MOUSE_SCROLL: u8 = 2;
const TAG_KEY_EVENT: u8 = 3;
const TAG_TEXT: u8 = 4;
const TAG_GAMEPAD: u8 = 5;

/// A compact binary input event for real-time remote control.
///
/// Each variant is encoded as a single tag byte followed by a fixed-size
/// or length-prefixed payload.
#[derive(Debug, Clone)]
pub enum InputPacket {
    /// Relative mouse movement.
    MouseMove { dx: i16, dy: i16 },
    /// Mouse button press or release.
    MouseClick {
        button: u8, // 0=Left, 1=Middle, 2=Right, 3=Back, 4=Forward
        pressed: bool,
    },
    /// Scroll wheel movement.
    MouseScroll {
        dx: i16, // horizontal scroll
        dy: i16, // vertical scroll
    },
    /// Keyboard key press or release.
    KeyEvent {
        key: u16, // Linux evdev keycode
        pressed: bool,
    },
    /// Raw text input (typed via clipboard paste or IME).
    Text(String),
    /// Gamepad state: 6 analog axes + 16-bit button bitmask.
    Gamepad {
        /// Left stick X, Left stick Y, Right stick X, Right stick Y, L2, R2.
        axes: [i16; 6],
        /// Bitmask of digital buttons (A=0, B=1, X=2, Y=3, LB=4, RB=5,
        /// Select=6, Start=7, Home=8, LSB=9, RSB=10, DPadUp=11,
        /// DPadDown=12, DPadLeft=13, DPadRight=14).
        buttons: u16,
    },
}

impl InputPacket {
    /// Encode this packet into a `Vec<u8>` for sending over a QUIC stream.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            InputPacket::MouseMove { dx, dy } => {
                let mut buf = vec![TAG_MOUSE_MOVE];
                buf.extend_from_slice(&dx.to_le_bytes());
                buf.extend_from_slice(&dy.to_le_bytes());
                buf
            }
            InputPacket::MouseClick { button, pressed } => {
                let mut buf = vec![TAG_MOUSE_CLICK];
                buf.push(*button);
                buf.push(if *pressed { 1 } else { 0 });
                buf
            }
            InputPacket::MouseScroll { dx, dy } => {
                let mut buf = vec![TAG_MOUSE_SCROLL];
                buf.extend_from_slice(&dx.to_le_bytes());
                buf.extend_from_slice(&dy.to_le_bytes());
                buf
            }
            InputPacket::KeyEvent { key, pressed } => {
                let mut buf = vec![TAG_KEY_EVENT];
                buf.extend_from_slice(&key.to_le_bytes());
                buf.push(if *pressed { 1 } else { 0 });
                buf
            }
            InputPacket::Gamepad { axes, buttons } => {
                let mut buf = Vec::with_capacity(1 + 12 + 2);
                buf.push(TAG_GAMEPAD);
                for &axis in axes {
                    buf.extend_from_slice(&axis.to_le_bytes());
                }
                buf.extend_from_slice(&buttons.to_le_bytes());
                buf
            }
            InputPacket::Text(text) => {
                let text_bytes = text.as_bytes();
                let mut buf = Vec::with_capacity(1 + 4 + text_bytes.len());
                buf.push(TAG_TEXT);
                buf.extend_from_slice(&(text_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(text_bytes);
                buf
            }
        }
    }

    /// Decode a packet from a byte slice.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            anyhow::bail!("Empty input packet data");
        }

        let tag = data[0];
        match tag {
            TAG_MOUSE_MOVE => {
                anyhow::ensure!(data.len() >= 5, "MouseMove packet too short");
                let dx = i16::from_le_bytes(data[1..3].try_into().unwrap());
                let dy = i16::from_le_bytes(data[3..5].try_into().unwrap());
                Ok(InputPacket::MouseMove { dx, dy })
            }
            TAG_MOUSE_CLICK => {
                anyhow::ensure!(data.len() >= 3, "MouseClick packet too short");
                let button = data[1];
                let pressed = data[2] != 0;
                Ok(InputPacket::MouseClick { button, pressed })
            }
            TAG_MOUSE_SCROLL => {
                anyhow::ensure!(data.len() >= 5, "MouseScroll packet too short");
                let dx = i16::from_le_bytes(data[1..3].try_into().unwrap());
                let dy = i16::from_le_bytes(data[3..5].try_into().unwrap());
                Ok(InputPacket::MouseScroll { dx, dy })
            }
            TAG_KEY_EVENT => {
                anyhow::ensure!(data.len() >= 4, "KeyEvent packet too short");
                let key = u16::from_le_bytes(data[1..3].try_into().unwrap());
                let pressed = data[3] != 0;
                Ok(InputPacket::KeyEvent { key, pressed })
            }
            TAG_GAMEPAD => {
                anyhow::ensure!(data.len() >= 15, "Gamepad packet too short");
                let mut axes = [0i16; 6];
                for (i, axis) in axes.iter_mut().enumerate() {
                    let offset = 1 + i * 2;
                    *axis = i16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
                }
                let buttons = u16::from_le_bytes(data[13..15].try_into().unwrap());
                Ok(InputPacket::Gamepad { axes, buttons })
            }
            TAG_TEXT => {
                anyhow::ensure!(data.len() >= 5, "Text packet too short");
                let len = u32::from_le_bytes(data[1..5].try_into().unwrap()) as usize;
                anyhow::ensure!(data.len() >= 5 + len, "Text packet payload truncated");
                let text = String::from_utf8(data[5..5 + len].to_vec())
                    .context("Invalid UTF-8 in Text packet")?;
                Ok(InputPacket::Text(text))
            }
            _ => {
                anyhow::bail!("Unknown input packet tag: {}", tag);
            }
        }
    }
}

impl From<InputPacket> for Vec<u8> {
    fn from(packet: InputPacket) -> Self {
        packet.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mouse_move_roundtrip() {
        let packet = InputPacket::MouseMove { dx: 127, dy: -128 };
        let data = packet.encode();
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::MouseMove { dx, dy } => {
                assert_eq!(dx, 127);
                assert_eq!(dy, -128);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_mouse_click_roundtrip() {
        let packet = InputPacket::MouseClick {
            button: 1,
            pressed: true,
        };
        let data = packet.encode();
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::MouseClick { button, pressed } => {
                assert_eq!(button, 1);
                assert!(pressed);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_key_event_roundtrip() {
        let packet = InputPacket::KeyEvent {
            key: 42,
            pressed: false,
        };
        let data = packet.encode();
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::KeyEvent { key, pressed } => {
                assert_eq!(key, 42);
                assert!(!pressed);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_text_roundtrip() {
        let packet = InputPacket::Text("Hello 世界".to_string());
        let data = packet.encode();
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::Text(text) => {
                assert_eq!(text, "Hello 世界");
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_empty_data() {
        assert!(InputPacket::decode(&[]).is_err());
    }

    #[test]
    fn test_unknown_tag() {
        assert!(InputPacket::decode(&[0xFF]).is_err());
    }

    #[test]
    fn test_truncated_packet() {
        // MouseMove needs 5 bytes total, we give 2
        assert!(InputPacket::decode(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn test_gamepad_roundtrip() {
        let packet = InputPacket::Gamepad {
            axes: [0, 32767, -32768, 100, -100, 0],
            buttons: 0b1010_0101,
        };
        let data = packet.encode();
        assert_eq!(data.len(), 15); // 1 tag + 12 axes + 2 buttons
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::Gamepad { axes, buttons } => {
                assert_eq!(axes[0], 0);
                assert_eq!(axes[1], 32767);
                assert_eq!(axes[2], -32768);
                assert_eq!(axes[3], 100);
                assert_eq!(axes[4], -100);
                assert_eq!(axes[5], 0);
                assert_eq!(buttons, 0b1010_0101);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_gamepad_truncated() {
        // Need 15 bytes, give 3
        assert!(InputPacket::decode(&[5, 0, 1]).is_err());
    }

    #[test]
    fn test_gamepad_all_buttons() {
        let packet = InputPacket::Gamepad {
            axes: [0; 6],
            buttons: 0xFFFF,
        };
        let data = packet.encode();
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::Gamepad { axes, buttons } => {
                assert_eq!(buttons, 0xFFFF);
                assert!(axes.iter().all(|&a| a == 0));
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_from_trait() {
        let packet = InputPacket::MouseMove { dx: 10, dy: -5 };
        let bytes: Vec<u8> = packet.into();
        assert_eq!(bytes.len(), 5);
    }
}
