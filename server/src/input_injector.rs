//! Native input injection with fallback chain: enigo (X11/XWayland) -> uinput (kernel-level)
//!
//! Tries enigo first (works on X11 and XWayland sessions).
//! Falls back to evdev/uinput (works on ALL compositors, requires /dev/uinput access).
//! uinput creates virtual HID devices at the kernel level, so every compositor sees them as real input devices.

use anyhow::{Context, Result};
use enigo::{Coordinate, Enigo, Key, Keyboard, Mouse, Settings};
use evdev::uinput::{VirtualDevice, VirtualDeviceBuilder};
use evdev::{
    AbsInfo, AbsoluteAxisCode, AttributeSet, InputEvent, KeyCode, PropType, RelativeAxisCode,
    UinputAbsSetup,
};
use linux_link_core::streaming::input_packet::InputPacket;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

/// Event type constants from evdev kernel API
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_SYN: u16 = 0x00;
const SYN_REPORT: u16 = 0;

/// Canonical mapping between Linux evdev keycodes and enigo Key values.
/// This is the single source of truth for key translation between backends.
/// `keycode_to_enigo` and `key_to_evdev` must both derive from this table.
const KEYCODE_MAP: &[(u16, Key)] = &[
    // Functional keys
    (1, Key::Escape),     // KEY_ESC
    (14, Key::Backspace), // KEY_BACKSPACE
    (15, Key::Tab),       // KEY_TAB
    (28, Key::Return),    // KEY_ENTER
    (57, Key::Space),     // KEY_SPACE
    // Navigation
    (102, Key::Home),       // KEY_HOME
    (103, Key::UpArrow),    // KEY_UP
    (104, Key::PageUp),     // KEY_PAGEUP
    (105, Key::LeftArrow),  // KEY_LEFT
    (106, Key::RightArrow), // KEY_RIGHT
    (107, Key::End),        // KEY_END
    (108, Key::DownArrow),  // KEY_DOWN
    (109, Key::PageDown),   // KEY_PAGEDOWN
    (110, Key::Insert),     // KEY_INSERT
    (111, Key::Delete),     // KEY_DELETE
    // Function keys
    (59, Key::F1),  // KEY_F1
    (60, Key::F2),  // KEY_F2
    (61, Key::F3),  // KEY_F3
    (62, Key::F4),  // KEY_F4
    (63, Key::F5),  // KEY_F5
    (64, Key::F6),  // KEY_F6
    (65, Key::F7),  // KEY_F7
    (66, Key::F8),  // KEY_F8
    (67, Key::F9),  // KEY_F9
    (68, Key::F10), // KEY_F10
    (87, Key::F11), // KEY_F11
    (88, Key::F12), // KEY_F12
];

/// Backend for input injection.
#[derive(Debug)]
enum InputBackend {
    /// enigo (X11/XWayland via XTEST)
    Enigo(Box<Mutex<Enigo>>),
    /// uinput (universal, kernel-level)
    Uinput(Mutex<UinputState>),
}

/// Kernel-level backend state: the keyboard/mouse device plus an on-demand
/// direct-touch device used for absolute (normalized) pointer injection.
#[derive(Debug)]
struct UinputState {
    main: VirtualDevice,
    /// Single-touch virtual device, created lazily on first absolute motion.
    touch: Option<VirtualDevice>,
    /// Whether the virtual finger is currently down.
    touch_down: bool,
}

const EV_ABS: u16 = 0x03;
const BTN_TOUCH: u16 = 330;
const BTN_TOOL_DOUBLETAP: u16 = 333;
/// Direct-touch axis range; normalized wire coordinates (0..=65535) map 1:1.
const ABS_MAX_COORD: i32 = 65535;

/// Cross-distro input injector.
///
/// Tries enigo (X11) first, falls back to uinput (kernel-level virtual device).
/// uinput works on ALL compositors but requires /dev/uinput access (root or uinput group).
pub struct InputInjector {
    backend: InputBackend,
}

impl Drop for InputInjector {
    fn drop(&mut self) {
        let backend_type = match &self.backend {
            InputBackend::Enigo(_) => "enigo",
            InputBackend::Uinput(_) => "uinput",
        };
        info!(backend = %backend_type, "InputInjector dropped, closing backend resources");
    }
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
                backend: InputBackend::Enigo(Box::new(Mutex::new(enigo))),
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
        // Mouse buttons BTN_LEFT..BTN_EXTRA (272..=276): undeclared codes are
        // rejected by the kernel, so mouse clicks need explicit registration.
        for keycode in 272..=276u16 {
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
            .context(
                "Failed to build virtual device. \
                     Ensure /dev/uinput is accessible (add user to 'uinput' group).",
            )?;

        info!("Input injector: using uinput (kernel-level, works on all compositors)");
        Ok(Self {
            backend: InputBackend::Uinput(Mutex::new(UinputState {
                main: device,
                touch: None,
                touch_down: false,
            })),
        })
    }

    /// Move mouse by relative delta
    pub fn move_mouse_relative(&mut self, dx: i32, dy: i32) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let e = enigo.get_mut().unwrap();
                e.move_mouse(dx, dy, Coordinate::Rel)
                    .context("enigo mouse move failed")?;
                Ok(())
            }
            InputBackend::Uinput(state) => {
                let dev = &mut state.get_mut().unwrap().main;
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

    /// Move the pointer to a normalized absolute position (0..=65535 per axis).
    ///
    /// uinput injects through a lazily-created direct-touch device, so no
    /// display resolution is needed on either side of the wire.
    pub fn move_mouse_normalized_abs(&mut self, x_norm: u16, y_norm: u16) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let e = enigo.get_mut().unwrap();
                let (w, h) = e.main_display().context("enigo main_display failed")?;
                e.move_mouse(
                    x_norm as i32 * w / ABS_MAX_COORD,
                    y_norm as i32 * h / ABS_MAX_COORD,
                    Coordinate::Abs,
                )
                .context("enigo absolute mouse move failed")?;
                Ok(())
            }
            InputBackend::Uinput(state) => {
                let mut state = state.get_mut().unwrap();
                let mut events = Vec::with_capacity(7);
                events.push(InputEvent::new(EV_ABS, AbsoluteAxisCode::ABS_MT_SLOT.0, 0));
                if !state.touch_down {
                    events.push(InputEvent::new(
                        EV_ABS,
                        AbsoluteAxisCode::ABS_MT_TRACKING_ID.0,
                        0,
                    ));
                    events.push(InputEvent::new(EV_KEY, BTN_TOUCH, 1));
                    events.push(InputEvent::new(EV_KEY, BTN_TOOL_DOUBLETAP, 1));
                }
                events.push(InputEvent::new(
                    EV_ABS,
                    AbsoluteAxisCode::ABS_MT_POSITION_X.0,
                    x_norm as i32,
                ));
                events.push(InputEvent::new(
                    EV_ABS,
                    AbsoluteAxisCode::ABS_MT_POSITION_Y.0,
                    y_norm as i32,
                ));
                events.push(InputEvent::new(EV_SYN, SYN_REPORT, 0));
                emit_touch(&mut state, &events)?;
                state.touch_down = true;
                Ok(())
            }
        }
    }

    /// Lift the virtual finger if a direct-touch sequence is in progress.
    fn release_touch_if_down(&mut self) -> Result<()> {
        if let InputBackend::Uinput(state) = &mut self.backend {
            let mut state = state.get_mut().unwrap();
            if state.touch_down {
                let events = [
                    InputEvent::new(EV_ABS, AbsoluteAxisCode::ABS_MT_SLOT.0, 0),
                    InputEvent::new(
                        EV_ABS,
                        AbsoluteAxisCode::ABS_MT_TRACKING_ID.0,
                        -1, // end of contact
                    ),
                    InputEvent::new(EV_KEY, BTN_TOUCH, 0),
                    InputEvent::new(EV_KEY, BTN_TOOL_DOUBLETAP, 0),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                emit_touch(&mut state, &events)?;
                state.touch_down = false;
            }
        }
        Ok(())
    }

    /// Press or release a mouse button
    pub fn mouse_button(&mut self, button: MouseKey, pressed: bool) -> Result<()> {
        // In direct-touch mode the client signals tap-end as a left release.
        if matches!(button, MouseKey::Left) && !pressed {
            self.release_touch_if_down()?;
        }
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let e = enigo.get_mut().unwrap();
                if pressed {
                    e.button(button.as_enigo_button(), enigo::Direction::Press)
                        .context("enigo mouse press failed")?;
                } else {
                    e.button(button.as_enigo_button(), enigo::Direction::Release)
                        .context("enigo mouse release failed")?;
                }
                Ok(())
            }
            InputBackend::Uinput(state) => {
                let dev = &mut state.get_mut().unwrap().main;
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
    pub fn scroll(&mut self, x: i32, y: i32) -> Result<()> {
        match &mut self.backend {
            InputBackend::Enigo(enigo) => {
                let e = enigo.get_mut().unwrap();
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
            InputBackend::Uinput(state) => {
                let dev = &mut state.get_mut().unwrap().main;
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
                let e = enigo.get_mut().unwrap();
                if pressed {
                    e.key(key, enigo::Direction::Press)
                        .context("enigo key press failed")?;
                } else {
                    e.key(key, enigo::Direction::Release)
                        .context("enigo key release failed")?;
                }
                Ok(())
            }
            InputBackend::Uinput(state) => {
                let dev = &mut state.get_mut().unwrap().main;
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
                let e = enigo.get_mut().unwrap();
                e.text(text).context("enigo text input failed")?;
                Ok(())
            }
            InputBackend::Uinput(state) => {
                // For uinput, fall back to keycode simulation for ASCII.
                // This is a best-effort approach and does not handle Unicode.
                for ch in text.chars() {
                    if let Some(keycode) = char_to_keycode(ch) {
                        let key = KeyCode(keycode);
                        let dev = &mut state.get_mut().unwrap().main;
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

    /// Handle an `InputPacket` by dispatching to the appropriate injection method.
    ///
    /// Supports mouse, keyboard, scroll, text, and gamepad events.
    /// Gamepad events are mapped to keyboard/mouse input for broad compatibility.
    pub fn handle_input_packet(&mut self, packet: &InputPacket) -> Result<()> {
        match packet {
            InputPacket::MouseMove { dx, dy } => self.move_mouse_relative(*dx as i32, *dy as i32),
            InputPacket::MouseMoveAbs { x_norm, y_norm } => {
                self.move_mouse_normalized_abs(*x_norm, *y_norm)
            }
            InputPacket::MouseClick { button, pressed } => {
                let mouse_key = match button {
                    0 => MouseKey::Left,
                    1 => MouseKey::Middle,
                    2 => MouseKey::Right,
                    3 => MouseKey::Button4,
                    4 => MouseKey::Button5,
                    _ => MouseKey::Left,
                };
                self.mouse_button(mouse_key, *pressed)
            }
            InputPacket::MouseScroll { dx, dy } => self.scroll(*dx as i32, *dy as i32),
            InputPacket::KeyEvent { key, pressed } => {
                // Key events arrive as Linux evdev keycodes over the QUIC channel.
                // Map to enigo Key and delegate to self.key() which handles both backends.
                let enigo_key = keycode_to_enigo(*key);
                self.key(enigo_key, *pressed)
            }
            InputPacket::Text(text) => self.text(text),
            // Control-plane request, intercepted by the streaming server before
            // the input channel; nothing to inject.
            InputPacket::RequestKeyframe => Ok(()),
            // Likewise: crop rects are consumed by the streaming pipeline, and
            // the client pre-maps absolute input into desktop space itself.
            InputPacket::WindowCrop { .. } => Ok(()),
            // View-only toggles are enforced in the streaming server's input
            // relay (which simply stops forwarding); nothing to inject.
            InputPacket::ViewOnly { .. } => Ok(()),
            InputPacket::Gamepad { axes, buttons } => {
                // Map gamepad axes/buttons to keyboard/mouse for broad compatibility.
                // Left stick -> mouse movement
                let mx = axes[0] as i32 / 256; // Scale from [-32768,32767] to [-128,127]
                let my = axes[1] as i32 / 256;
                if mx != 0 || my != 0 {
                    self.move_mouse_relative(mx, my)?;
                }

                // A button -> Enter
                if *buttons & 0x01 != 0 {
                    self.key(Key::Return, true)?;
                }

                // B button -> Escape
                if *buttons & 0x02 != 0 {
                    self.key(Key::Escape, true)?;
                }

                // Start -> trigger click
                if *buttons & 0x80 != 0 {
                    self.mouse_button(MouseKey::Left, true)?;
                }

                // DPad -> arrow keys
                if *buttons & (1 << 11) != 0 {
                    self.key(Key::UpArrow, true)?;
                }
                if *buttons & (1 << 12) != 0 {
                    self.key(Key::DownArrow, true)?;
                }
                if *buttons & (1 << 13) != 0 {
                    self.key(Key::LeftArrow, true)?;
                }
                if *buttons & (1 << 14) != 0 {
                    self.key(Key::RightArrow, true)?;
                }

                // SYN_REPORT
                if let InputBackend::Uinput(state) = &mut self.backend {
                    let dev = &mut state.get_mut().unwrap().main;
                    dev.emit(&[InputEvent::new(EV_SYN, SYN_REPORT, 0)])
                        .context("gamepad SYN_REPORT failed")?;
                }

                Ok(())
            }
        }
    }
}

/// Emit events on the direct-touch device, creating it lazily on first use.
fn emit_touch(state: &mut UinputState, events: &[InputEvent]) -> Result<()> {
    if state.touch.is_none() {
        state.touch = Some(build_touch_device()?);
    }
    state
        .touch
        .as_mut()
        .unwrap()
        .emit(events)
        .context("uinput direct-touch emit failed")
}

/// Build a single-touch `MT` device. Coordinates arrive normalized
/// 0..=65535 from the client, so the axis ranges map the wire values 1:1 and
/// libinput scales them to the screen (DIRECT property).
fn build_touch_device() -> Result<VirtualDevice> {
    let mut keys = AttributeSet::<KeyCode>::new();
    keys.insert(KeyCode(BTN_TOUCH));
    keys.insert(KeyCode(BTN_TOOL_DOUBLETAP));

    let mut props = AttributeSet::<PropType>::new();
    props.insert(PropType::DIRECT);

    let slot = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_MT_SLOT,
        AbsInfo::new(0, 0, 1, 0, 0, 0),
    );
    // Kernel requires TRACKING_ID minimum of -1 (release sentinel).
    let tracking = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_MT_TRACKING_ID,
        AbsInfo::new(0, -1, 10, 0, 0, 0),
    );
    let abs_x = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_MT_POSITION_X,
        AbsInfo::new(0, 0, ABS_MAX_COORD, 0, 0, 0),
    );
    let abs_y = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_MT_POSITION_Y,
        AbsInfo::new(0, 0, ABS_MAX_COORD, 0, 0, 0),
    );

    #[allow(deprecated)]
    let device = VirtualDeviceBuilder::new()
        .context("Failed to create touch device builder")?
        .with_keys(&keys)
        .context("Failed to set up touch keys")?
        .with_absolute_axis(&slot)
        .context("Failed to set up ABS_MT_SLOT")?
        .with_absolute_axis(&tracking)
        .context("Failed to set up ABS_MT_TRACKING_ID")?
        .with_absolute_axis(&abs_x)
        .context("Failed to set up ABS_MT_POSITION_X")?
        .with_absolute_axis(&abs_y)
        .context("Failed to set up ABS_MT_POSITION_Y")?
        .with_properties(&props)
        .context("Failed to set up touch properties")?
        .name(b"Linux Link Virtual Touch")
        .build()
        .context("Failed to build uinput direct-touch device")?;

    Ok(device)
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
            MouseKey::Button4 => KeyCode::BTN_SIDE, // Side button (back)
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
/// Uses KEYCODE_MAP as the single source of truth.
fn keycode_to_enigo(code: u16) -> Key {
    KEYCODE_MAP
        .iter()
        .find(|&&(k, _)| k == code)
        .map(|&(_, key)| key)
        .unwrap_or_else(|| Key::Unicode(std::char::from_u32(code as u32).unwrap_or('?')))
}

/// Map an enigo Key to an evdev KeyCode for uinput backend.
/// Uses KEYCODE_MAP as the single source of truth (reverse lookup).
fn key_to_evdev(key: Key) -> KeyCode {
    // Check the canonical table first
    if let Some(&(code, _)) = KEYCODE_MAP.iter().find(|&(_, k)| *k == key) {
        return KeyCode(code);
    }
    // Fall back to character-based mapping for Unicode keys
    match key {
        Key::Unicode(ch) => char_to_keycode(ch)
            .map(KeyCode)
            .unwrap_or(KeyCode::KEY_UNKNOWN),
        _ => KeyCode::KEY_UNKNOWN,
    }
}

/// Map a character to a Linux evdev keycode.
/// Only handles basic ASCII. Returns None for unsupported characters.
/// Uses evdev KeyCode constants for readability and correctness.
fn char_to_keycode(ch: char) -> Option<u16> {
    match ch {
        // QWERTY layout keycodes (evdev standard)
        'q' | 'Q' => Some(KeyCode::KEY_Q.0),
        'w' | 'W' => Some(KeyCode::KEY_W.0),
        'e' | 'E' => Some(KeyCode::KEY_E.0),
        'r' | 'R' => Some(KeyCode::KEY_R.0),
        't' | 'T' => Some(KeyCode::KEY_T.0),
        'y' | 'Y' => Some(KeyCode::KEY_Y.0),
        'u' | 'U' => Some(KeyCode::KEY_U.0),
        'i' | 'I' => Some(KeyCode::KEY_I.0),
        'o' | 'O' => Some(KeyCode::KEY_O.0),
        'p' | 'P' => Some(KeyCode::KEY_P.0),
        'a' | 'A' => Some(KeyCode::KEY_A.0),
        's' | 'S' => Some(KeyCode::KEY_S.0),
        'd' | 'D' => Some(KeyCode::KEY_D.0),
        'f' | 'F' => Some(KeyCode::KEY_F.0),
        'g' | 'G' => Some(KeyCode::KEY_G.0),
        'h' | 'H' => Some(KeyCode::KEY_H.0),
        'j' | 'J' => Some(KeyCode::KEY_J.0),
        'k' | 'K' => Some(KeyCode::KEY_K.0),
        'l' | 'L' => Some(KeyCode::KEY_L.0),
        'z' | 'Z' => Some(KeyCode::KEY_Z.0),
        'x' | 'X' => Some(KeyCode::KEY_X.0),
        'c' | 'C' => Some(KeyCode::KEY_C.0),
        'v' | 'V' => Some(KeyCode::KEY_V.0),
        'b' | 'B' => Some(KeyCode::KEY_B.0),
        'n' | 'N' => Some(KeyCode::KEY_N.0),
        'm' | 'M' => Some(KeyCode::KEY_M.0),
        // Numbers
        '0' => Some(KeyCode::KEY_0.0),
        '1' => Some(KeyCode::KEY_1.0),
        '2' => Some(KeyCode::KEY_2.0),
        '3' => Some(KeyCode::KEY_3.0),
        '4' => Some(KeyCode::KEY_4.0),
        '5' => Some(KeyCode::KEY_5.0),
        '6' => Some(KeyCode::KEY_6.0),
        '7' => Some(KeyCode::KEY_7.0),
        '8' => Some(KeyCode::KEY_8.0),
        '9' => Some(KeyCode::KEY_9.0),
        // Special
        ' ' => Some(KeyCode::KEY_SPACE.0),
        '\n' => Some(KeyCode::KEY_ENTER.0),
        '\t' => Some(KeyCode::KEY_TAB.0),
        _ => None,
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

    #[test]
    fn test_char_to_keycode_lowercase() {
        use evdev::KeyCode;
        assert_eq!(char_to_keycode('a'), Some(KeyCode::KEY_A.0));
        assert_eq!(char_to_keycode('z'), Some(KeyCode::KEY_Z.0));
    }

    #[test]
    fn test_char_to_keycode_uppercase() {
        use evdev::KeyCode;
        assert_eq!(char_to_keycode('A'), Some(KeyCode::KEY_A.0));
        assert_eq!(char_to_keycode('Z'), Some(KeyCode::KEY_Z.0));
    }

    #[test]
    fn test_char_to_keycode_numbers() {
        use evdev::KeyCode;
        assert_eq!(char_to_keycode('0'), Some(KeyCode::KEY_0.0));
        assert_eq!(char_to_keycode('1'), Some(KeyCode::KEY_1.0));
        assert_eq!(char_to_keycode('9'), Some(KeyCode::KEY_9.0));
    }

    #[test]
    fn test_char_to_keycode_space() {
        assert_eq!(char_to_keycode(' '), Some(KeyCode::KEY_SPACE.0));
    }

    #[test]
    fn test_char_to_keycode_special() {
        use evdev::KeyCode;
        assert_eq!(char_to_keycode('\n'), Some(KeyCode::KEY_ENTER.0));
        assert_eq!(char_to_keycode('\t'), Some(KeyCode::KEY_TAB.0));
    }

    #[test]
    fn test_char_to_keycode_unsupported() {
        assert_eq!(char_to_keycode('\u{00e9}'), None);
        assert_eq!(char_to_keycode('\u{4e2d}'), None);
    }

    #[test]
    fn test_keycode_to_enigo_function_keys() {
        // F1-F12 must map individually (previously all mapped to F1)
        assert_eq!(keycode_to_enigo(59), Key::F1);
        assert_eq!(keycode_to_enigo(60), Key::F2);
        assert_eq!(keycode_to_enigo(61), Key::F3);
        assert_eq!(keycode_to_enigo(62), Key::F4);
        assert_eq!(keycode_to_enigo(63), Key::F5);
        assert_eq!(keycode_to_enigo(64), Key::F6);
        assert_eq!(keycode_to_enigo(65), Key::F7);
        assert_eq!(keycode_to_enigo(66), Key::F8);
        assert_eq!(keycode_to_enigo(67), Key::F9);
        assert_eq!(keycode_to_enigo(68), Key::F10);
        assert_eq!(keycode_to_enigo(87), Key::F11);
        assert_eq!(keycode_to_enigo(88), Key::F12);
    }

    #[test]
    fn test_keycode_to_enigo_common() {
        assert_eq!(keycode_to_enigo(28), Key::Return); // KEY_ENTER
        assert_eq!(keycode_to_enigo(14), Key::Backspace); // KEY_BACKSPACE
        assert_eq!(keycode_to_enigo(57), Key::Space); // KEY_SPACE
        assert_eq!(keycode_to_enigo(15), Key::Tab); // KEY_TAB
        assert_eq!(keycode_to_enigo(1), Key::Escape); // KEY_ESC
    }

    #[test]
    fn test_keycode_to_enigo_navigation() {
        assert_eq!(keycode_to_enigo(102), Key::Home); // KEY_HOME
        assert_eq!(keycode_to_enigo(103), Key::UpArrow); // KEY_UP
        assert_eq!(keycode_to_enigo(104), Key::PageUp); // KEY_PAGEUP
        assert_eq!(keycode_to_enigo(105), Key::LeftArrow); // KEY_LEFT
        assert_eq!(keycode_to_enigo(106), Key::RightArrow); // KEY_RIGHT
        assert_eq!(keycode_to_enigo(107), Key::End); // KEY_END
        assert_eq!(keycode_to_enigo(108), Key::DownArrow); // KEY_DOWN
        assert_eq!(keycode_to_enigo(109), Key::PageDown); // KEY_PAGEDOWN
        assert_eq!(keycode_to_enigo(110), Key::Insert); // KEY_INSERT
        assert_eq!(keycode_to_enigo(111), Key::Delete); // KEY_DELETE
    }

    #[test]
    fn test_keycode_to_enigo_fallback() {
        // Unknown keycodes fall back to Unicode char mapping
        assert!(matches!(keycode_to_enigo(999), Key::Unicode(_)));
    }

    #[test]
    fn test_key_to_evdev_common() {
        assert_eq!(key_to_evdev(Key::Return), KeyCode::KEY_ENTER);
        assert_eq!(key_to_evdev(Key::Backspace), KeyCode::KEY_BACKSPACE);
        assert_eq!(key_to_evdev(Key::Space), KeyCode::KEY_SPACE);
        assert_eq!(key_to_evdev(Key::Escape), KeyCode::KEY_ESC);
        assert_eq!(key_to_evdev(Key::Tab), KeyCode::KEY_TAB);
    }

    #[test]
    fn test_key_to_evdev_function_keys() {
        assert_eq!(key_to_evdev(Key::F1), KeyCode::KEY_F1);
        assert_eq!(key_to_evdev(Key::F6), KeyCode::KEY_F6);
        assert_eq!(key_to_evdev(Key::F10), KeyCode::KEY_F10);
        assert_eq!(key_to_evdev(Key::F11), KeyCode::KEY_F11);
        assert_eq!(key_to_evdev(Key::F12), KeyCode::KEY_F12);
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

    #[test]
    fn test_keycode_roundtrip_common() {
        // Verify keycode_to_enigo and key_to_evdev are inverses
        // for all entries in KEYCODE_MAP
        for &(evdev_code, enigo_key) in KEYCODE_MAP {
            assert_eq!(
                keycode_to_enigo(evdev_code),
                enigo_key,
                "keycode_to_enigo({}) should be {:?}",
                evdev_code,
                enigo_key
            );
            assert_eq!(
                key_to_evdev(enigo_key),
                KeyCode(evdev_code),
                "key_to_evdev({:?}) should be KeyCode({})",
                enigo_key,
                evdev_code
            );
        }
    }
}
