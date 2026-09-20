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
const TAG_MOUSE_MOVE_ABS: u8 = 6;
const TAG_REQUEST_KEYFRAME: u8 = 7;
const TAG_WINDOW_CROP: u8 = 8;
const TAG_VIEW_ONLY: u8 = 9;
const TAG_FULL_QUALITY: u8 = 10;

/// A compact binary input event for real-time remote control.
///
/// Each variant is encoded as a single tag byte followed by a fixed-size
/// or length-prefixed payload.
#[derive(Debug, Clone)]
pub enum InputPacket {
    /// Relative mouse movement.
    MouseMove { dx: i16, dy: i16 },
    /// Absolute pointer position, normalized to the remote screen:
    /// 0..=65535 maps to the full width/height (resolution-independent,
    /// so the client never needs the pixel dimensions).
    MouseMoveAbs { x_norm: u16, y_norm: u16 },
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
    /// Client detected a video sequence gap and asks the server to emit an
    /// IDR frame immediately.
    RequestKeyframe,
    /// Restrict the stream to a region of the desktop (window-crop mode).
    /// `None` fields mean 0; an all-`None` packet clears the crop and
    /// restores the full desktop.
    WindowCrop {
        x: Option<u32>,
        y: Option<u32>,
        width: Option<u32>,
        height: Option<u32>,
    },
    /// R4 D1 view-only mode: while enabled the **server** drops every
    /// injected-input packet from this session (mouse, keyboard, gamepad,
    /// text). Control packets (keyframe requests, crops, further view-only
    /// toggles) keep flowing, and video is unaffected.
    ViewOnly { enabled: bool },
    /// R4 A3: opt OUT of the server's relay bitrate floor — stream at the
    /// configured bitrate even while the path is a relay (user override,
    /// default false). `true` disables the clamp for this session; video
    /// quality then depends on relay capacity. Control-plane, never injected.
    FullQuality { enabled: bool },
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
            InputPacket::MouseMoveAbs { x_norm, y_norm } => {
                let mut buf = vec![TAG_MOUSE_MOVE_ABS];
                buf.extend_from_slice(&x_norm.to_le_bytes());
                buf.extend_from_slice(&y_norm.to_le_bytes());
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
            InputPacket::RequestKeyframe => vec![TAG_REQUEST_KEYFRAME],
            InputPacket::ViewOnly { enabled } => {
                vec![TAG_VIEW_ONLY, if *enabled { 1 } else { 0 }]
            }
            InputPacket::FullQuality { enabled } => {
                vec![TAG_FULL_QUALITY, if *enabled { 1 } else { 0 }]
            }
            InputPacket::WindowCrop {
                x,
                y,
                width,
                height,
            } => {
                let mut buf = Vec::with_capacity(17);
                buf.push(TAG_WINDOW_CROP);
                for v in [x, y, width, height] {
                    buf.extend_from_slice(&v.unwrap_or(0).to_le_bytes());
                }
                buf
            }
        }
    }

    /// For a `WindowCrop` packet: the crop rectangle it establishes, or
    /// `None` when the packet clears the crop (no width/height set).
    /// Coordinates default to 0 when absent.
    pub fn crop_rect(&self) -> Option<(u32, u32, u32, u32)> {
        match self {
            InputPacket::WindowCrop {
                x,
                y,
                width,
                height,
            } => match (*width, *height) {
                (Some(w), Some(h)) if w > 0 && h > 0 => {
                    Some((x.unwrap_or(0), y.unwrap_or(0), w, h))
                }
                _ => None,
            },
            _ => None,
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
            TAG_MOUSE_MOVE_ABS => {
                anyhow::ensure!(data.len() >= 5, "MouseMoveAbs packet too short");
                let x_norm = u16::from_le_bytes(data[1..3].try_into().unwrap());
                let y_norm = u16::from_le_bytes(data[3..5].try_into().unwrap());
                Ok(InputPacket::MouseMoveAbs { x_norm, y_norm })
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
            TAG_REQUEST_KEYFRAME => {
                anyhow::ensure!(data.len() == 1, "RequestKeyframe packet must be 1 byte");
                Ok(InputPacket::RequestKeyframe)
            }
            TAG_VIEW_ONLY => {
                anyhow::ensure!(data.len() == 2, "ViewOnly packet must be 2 bytes");
                Ok(InputPacket::ViewOnly {
                    enabled: data[1] != 0,
                })
            }
            TAG_FULL_QUALITY => {
                anyhow::ensure!(data.len() == 2, "FullQuality packet must be 2 bytes");
                Ok(InputPacket::FullQuality {
                    enabled: data[1] != 0,
                })
            }
            TAG_WINDOW_CROP => {
                anyhow::ensure!(
                    data.len() == 17,
                    "WindowCrop packet must be 17 bytes, got {}",
                    data.len()
                );
                let field = |i: usize| {
                    let v = u32::from_le_bytes(data[1 + i * 4..5 + i * 4].try_into().unwrap());
                    (v > 0).then_some(v)
                };
                Ok(InputPacket::WindowCrop {
                    x: field(0),
                    y: field(1),
                    width: field(2),
                    height: field(3),
                })
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
    fn test_mouse_move_abs_roundtrip() {
        let packet = InputPacket::MouseMoveAbs {
            x_norm: 0,
            y_norm: 65535,
        };
        let data = packet.encode();
        assert_eq!(data.len(), 5);
        let decoded = InputPacket::decode(&data).unwrap();
        match decoded {
            InputPacket::MouseMoveAbs { x_norm, y_norm } => {
                assert_eq!(x_norm, 0);
                assert_eq!(y_norm, 65535);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_mouse_move_abs_truncated() {
        assert!(InputPacket::decode(&[6, 0, 1]).is_err());
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
    fn test_request_keyframe_roundtrip() {
        let packet = InputPacket::RequestKeyframe;
        let data = packet.encode();
        assert_eq!(data.len(), 1);
        let decoded = InputPacket::decode(&data).unwrap();
        assert!(matches!(decoded, InputPacket::RequestKeyframe));
        // Trailing garbage must be rejected so a stats/input framing bug
        // is caught loudly instead of silently mis-parsed.
        assert!(InputPacket::decode(&[7, 0]).is_err());
    }

    #[test]
    fn test_window_crop_roundtrip() {
        let packet = InputPacket::WindowCrop {
            x: Some(100),
            y: Some(60),
            width: Some(1280),
            height: Some(720),
        };
        let data = packet.encode();
        assert_eq!(data.len(), 17);
        let decoded = InputPacket::decode(&data).unwrap();
        assert_eq!(decoded.crop_rect(), Some((100, 60, 1280, 720)));
    }

    #[test]
    fn test_window_crop_origin_and_clear() {
        // x/y of 0 are legitimate positions: crop_rect must default them to 0.
        let packet = InputPacket::WindowCrop {
            x: None,
            y: None,
            width: Some(800),
            height: Some(600),
        };
        let decoded = InputPacket::decode(&packet.encode()).unwrap();
        assert_eq!(decoded.crop_rect(), Some((0, 0, 800, 600)));

        // All-zero payload clears the crop.
        let clear = InputPacket::WindowCrop {
            x: None,
            y: None,
            width: None,
            height: None,
        };
        let data = clear.encode();
        assert_eq!(&data[1..], &[0u8; 16]);
        assert_eq!(InputPacket::decode(&data).unwrap().crop_rect(), None);
    }

    #[test]
    fn test_window_crop_bad_length() {
        assert!(InputPacket::decode(&[8, 0, 1]).is_err());
        let mut full = InputPacket::WindowCrop {
            x: Some(1),
            y: Some(2),
            width: Some(3),
            height: Some(4),
        }
        .encode();
        full.push(0);
        assert!(InputPacket::decode(&full).is_err());
        assert_eq!(
            InputPacket::decode(&full[..17]).unwrap().crop_rect(),
            Some((1, 2, 3, 4))
        );
    }

    #[test]
    fn test_crop_rect_ignores_other_variants() {
        assert_eq!(InputPacket::RequestKeyframe.crop_rect(), None);
    }

    #[test]
    fn test_view_only_roundtrip() {
        for enabled in [true, false] {
            let data = InputPacket::ViewOnly { enabled }.encode();
            assert_eq!(data.len(), 2);
            let decoded = InputPacket::decode(&data).unwrap();
            assert!(
                matches!(decoded, InputPacket::ViewOnly { enabled: e } if e == enabled),
                "wrong variant for {enabled}"
            );
        }
        // Framing is strict like RequestKeyframe: payload size must be exact.
        assert!(InputPacket::decode(&[9]).is_err());
        assert!(InputPacket::decode(&[9, 1, 0]).is_err());
    }

    #[test]
    fn test_full_quality_roundtrip() {
        for enabled in [true, false] {
            let data = InputPacket::FullQuality { enabled }.encode();
            assert_eq!(data, vec![10, u8::from(enabled)]);
            let decoded = InputPacket::decode(&data).unwrap();
            assert!(matches!(decoded, InputPacket::FullQuality { enabled: e } if e == enabled));
        }
        assert!(InputPacket::decode(&[10]).is_err());
        assert!(InputPacket::decode(&[10, 1, 1]).is_err());
    }

    #[test]
    fn test_from_trait() {
        let packet = InputPacket::MouseMove { dx: 10, dy: -5 };
        let bytes: Vec<u8> = packet.into();
        assert_eq!(bytes.len(), 5);
    }
}
