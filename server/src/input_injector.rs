//! Native input injection with fallback chain: enigo (X11/XWayland) -> uinput (kernel-level)
//!
//! Tries enigo first (works on X11 and XWayland sessions).
//! Falls back to evdev/uinput (works on ALL compositors, requires /dev/uinput access).
//! uinput creates virtual HID devices at the kernel level, so every compositor sees them as real input devices.

use anyhow::{Context, Result};
use enigo::{Coordinate, Enigo, Key, Keyboard, Mouse, Settings};
use evdev::uinput::{VirtualDevice, VirtualDeviceBuilder};
use evdev::{
    AbsInfo, AbsoluteAxisCode, AttributeSet, InputEvent, KeyCode, RelativeAxisCode, UinputAbsSetup,
};
use linux_link_core::streaming::input_packet::InputPacket;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, warn};

/// Event type constants from evdev kernel API
const EV_KEY: u16 = 0x01;
const EV_REL: u16 = 0x02;
const EV_SYN: u16 = 0x00;
const SYN_REPORT: u16 = 0;

/// Canonical mapping between Linux evdev keycodes and enigo `Key` values.
///
/// This is the single source of truth for key translation between backends:
/// `keycode_to_enigo` and `key_to_evdev` read it in opposite directions, and
/// `tests::every_key_the_phone_can_send_has_a_mapping` fails the moment it stops
/// covering `core::input::keys`, the set the Android client emits.
///
/// Codes are named through `evdev::KeyCode` instead of written as numbers
/// because a wrong number here silently injects a different key than the one the
/// phone pressed; a wrong *name* is a compile error.
///
/// Letters, digits and punctuation map to `Key::Unicode`: enigo has no
/// per-letter variant on Linux (`Key::A` and friends are Windows-only) and its
/// X11 backend resolves `Unicode(c)` through that character's keysym, which is
/// what the evdev code stands for anyway. Capitalisation is not this table's
/// problem — the phone sends Shift as its own key event and X applies it.
const KEYCODE_MAP: &[(u16, Key)] = &[
    // Editing and control
    (KeyCode::KEY_ESC.0, Key::Escape),
    (KeyCode::KEY_BACKSPACE.0, Key::Backspace),
    (KeyCode::KEY_TAB.0, Key::Tab),
    (KeyCode::KEY_ENTER.0, Key::Return),
    (KeyCode::KEY_SPACE.0, Key::Space),
    (KeyCode::KEY_CAPSLOCK.0, Key::CapsLock),
    (KeyCode::KEY_NUMLOCK.0, Key::Numlock),
    (KeyCode::KEY_INSERT.0, Key::Insert),
    (KeyCode::KEY_DELETE.0, Key::Delete),
    // Navigation
    (KeyCode::KEY_HOME.0, Key::Home),
    (KeyCode::KEY_UP.0, Key::UpArrow),
    (KeyCode::KEY_PAGEUP.0, Key::PageUp),
    (KeyCode::KEY_LEFT.0, Key::LeftArrow),
    (KeyCode::KEY_RIGHT.0, Key::RightArrow),
    (KeyCode::KEY_END.0, Key::End),
    (KeyCode::KEY_DOWN.0, Key::DownArrow),
    (KeyCode::KEY_PAGEDOWN.0, Key::PageDown),
    // Modifiers. evdev names left and right separately; enigo has a right-hand
    // variant only for Shift and Control, so Right Alt and Right Super ride
    // `Key::Other`, which its X11 backend reads as a raw keysym.
    (KeyCode::KEY_LEFTSHIFT.0, Key::LShift),
    (KeyCode::KEY_RIGHTSHIFT.0, Key::RShift),
    (KeyCode::KEY_LEFTCTRL.0, Key::LControl),
    (KeyCode::KEY_RIGHTCTRL.0, Key::RControl),
    (KeyCode::KEY_LEFTALT.0, Key::Alt),
    (KeyCode::KEY_RIGHTALT.0, Key::Other(0xFFEA)), // XK_Alt_R
    (KeyCode::KEY_LEFTMETA.0, Key::Meta),          // Super
    (KeyCode::KEY_RIGHTMETA.0, Key::Other(0xFFEC)), // XK_Super_R
    // Function keys. F11/F12 are 87/88, not the two numbers after F10, because
    // 69 and 70 are Num Lock and Scroll Lock. F13-F24 stay in this table so the
    // X11 rung is no weaker than uinput, which will emit any code it declares.
    (KeyCode::KEY_F1.0, Key::F1),
    (KeyCode::KEY_F2.0, Key::F2),
    (KeyCode::KEY_F3.0, Key::F3),
    (KeyCode::KEY_F4.0, Key::F4),
    (KeyCode::KEY_F5.0, Key::F5),
    (KeyCode::KEY_F6.0, Key::F6),
    (KeyCode::KEY_F7.0, Key::F7),
    (KeyCode::KEY_F8.0, Key::F8),
    (KeyCode::KEY_F9.0, Key::F9),
    (KeyCode::KEY_F10.0, Key::F10),
    (KeyCode::KEY_F11.0, Key::F11),
    (KeyCode::KEY_F12.0, Key::F12),
    (KeyCode::KEY_F13.0, Key::F13),
    (KeyCode::KEY_F14.0, Key::F14),
    (KeyCode::KEY_F15.0, Key::F15),
    (KeyCode::KEY_F16.0, Key::F16),
    (KeyCode::KEY_F17.0, Key::F17),
    (KeyCode::KEY_F18.0, Key::F18),
    (KeyCode::KEY_F19.0, Key::F19),
    (KeyCode::KEY_F20.0, Key::F20),
    (KeyCode::KEY_F21.0, Key::F21),
    (KeyCode::KEY_F22.0, Key::F22),
    (KeyCode::KEY_F23.0, Key::F23),
    (KeyCode::KEY_F24.0, Key::F24),
    // Keys the phone's system bar and shortcut sheet send. The Print key arrives
    // as KEY_SYSRQ, which is the code XKB binds to the `Print` keysym.
    (KeyCode::KEY_SYSRQ.0, Key::PrintScr),
    (KeyCode::KEY_VOLUMEDOWN.0, Key::VolumeDown),
    (KeyCode::KEY_VOLUMEUP.0, Key::VolumeUp),
    (KeyCode::KEY_NEXTSONG.0, Key::MediaNextTrack),
    (KeyCode::KEY_PLAYPAUSE.0, Key::MediaPlayPause),
    (KeyCode::KEY_PREVIOUSSONG.0, Key::MediaPrevTrack),
    // enigo calls the X `Menu` keysym `LMenu`; the application-keys key has no
    // left/right form. (evdev KEY_COMPOSE is 127, a different key.)
    (KeyCode::KEY_MENU.0, Key::LMenu),
    // The dialpad's star and plus are keypad codes, so they get the keypad
    // keysyms; the plain '*' and '+' characters reach the same codes through
    // `char_to_keycode`.
    (KeyCode::KEY_KPASTERISK.0, Key::Multiply),
    (KeyCode::KEY_KPPLUS.0, Key::Add),
    // Digits, in the order they are printed rather than their codes.
    (KeyCode::KEY_1.0, Key::Unicode('1')),
    (KeyCode::KEY_2.0, Key::Unicode('2')),
    (KeyCode::KEY_3.0, Key::Unicode('3')),
    (KeyCode::KEY_4.0, Key::Unicode('4')),
    (KeyCode::KEY_5.0, Key::Unicode('5')),
    (KeyCode::KEY_6.0, Key::Unicode('6')),
    (KeyCode::KEY_7.0, Key::Unicode('7')),
    (KeyCode::KEY_8.0, Key::Unicode('8')),
    (KeyCode::KEY_9.0, Key::Unicode('9')),
    (KeyCode::KEY_0.0, Key::Unicode('0')),
    // Letters, QWERTY rows.
    (KeyCode::KEY_Q.0, Key::Unicode('q')),
    (KeyCode::KEY_W.0, Key::Unicode('w')),
    (KeyCode::KEY_E.0, Key::Unicode('e')),
    (KeyCode::KEY_R.0, Key::Unicode('r')),
    (KeyCode::KEY_T.0, Key::Unicode('t')),
    (KeyCode::KEY_Y.0, Key::Unicode('y')),
    (KeyCode::KEY_U.0, Key::Unicode('u')),
    (KeyCode::KEY_I.0, Key::Unicode('i')),
    (KeyCode::KEY_O.0, Key::Unicode('o')),
    (KeyCode::KEY_P.0, Key::Unicode('p')),
    (KeyCode::KEY_A.0, Key::Unicode('a')),
    (KeyCode::KEY_S.0, Key::Unicode('s')),
    (KeyCode::KEY_D.0, Key::Unicode('d')),
    (KeyCode::KEY_F.0, Key::Unicode('f')),
    (KeyCode::KEY_G.0, Key::Unicode('g')),
    (KeyCode::KEY_H.0, Key::Unicode('h')),
    (KeyCode::KEY_J.0, Key::Unicode('j')),
    (KeyCode::KEY_K.0, Key::Unicode('k')),
    (KeyCode::KEY_L.0, Key::Unicode('l')),
    (KeyCode::KEY_Z.0, Key::Unicode('z')),
    (KeyCode::KEY_X.0, Key::Unicode('x')),
    (KeyCode::KEY_C.0, Key::Unicode('c')),
    (KeyCode::KEY_V.0, Key::Unicode('v')),
    (KeyCode::KEY_B.0, Key::Unicode('b')),
    (KeyCode::KEY_N.0, Key::Unicode('n')),
    (KeyCode::KEY_M.0, Key::Unicode('m')),
    // Punctuation the phone's symbol sheet reaches for most often.
    (KeyCode::KEY_MINUS.0, Key::Unicode('-')),
    (KeyCode::KEY_EQUAL.0, Key::Unicode('=')),
    (KeyCode::KEY_LEFTBRACE.0, Key::Unicode('[')),
    (KeyCode::KEY_RIGHTBRACE.0, Key::Unicode(']')),
    (KeyCode::KEY_SEMICOLON.0, Key::Unicode(';')),
    (KeyCode::KEY_APOSTROPHE.0, Key::Unicode('\'')),
    (KeyCode::KEY_GRAVE.0, Key::Unicode('`')),
    (KeyCode::KEY_COMMA.0, Key::Unicode(',')),
    (KeyCode::KEY_DOT.0, Key::Unicode('.')),
    (KeyCode::KEY_SLASH.0, Key::Unicode('/')),
];

/// Backend for input injection.
#[derive(Debug)]
enum InputBackend {
    /// enigo (X11/XWayland via XTEST)
    Enigo(Box<Mutex<Enigo>>),
    /// uinput (universal, kernel-level)
    Uinput(Mutex<UinputState>),
}

/// Kernel-level backend state: the keyboard/mouse device plus an
/// absolute-pointer device used for absolute (normalized) pointer injection.
#[derive(Debug)]
struct UinputState {
    main: VirtualDevice,
    /// `ABS_X`/`ABS_Y` virtual pointer. Hyprland's libinput drops uinput MT
    /// touchscreens on this box, but an ABS pointer maps 1:1 onto the layout
    /// and moves the real cursor (verified with `hyprctl cursorpos`).
    abs: Option<VirtualDevice>,
}

const EV_ABS: u16 = 0x03;
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
    /// Under a Wayland compositor uinput is tried first: enigo's XTEST only
    /// reaches XWayland's internal pointer, so native clients never see it
    /// (verified on Hyprland — cursor warps logged fine, real cursor stuck).
    /// Otherwise (bare X11) or if /dev/uinput is inaccessible, enigo is
    /// tried first with uinput as the fallback.
    pub fn new() -> Result<Self> {
        let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
        if wayland {
            match Self::new_uinput() {
                Ok(inj) => return Ok(inj),
                Err(e) => {
                    warn!(error = %e, "uinput unavailable under Wayland, falling back to enigo (XWayland-only injection)");
                }
            }
        }

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
        // The abs pointer is built eagerly: libinput opens new devices
        // asynchronously after UI_DEV_CREATE, so a device created on the
        // first absolute motion loses that very event (the phone's first
        // tap silently no-op'd).
        Ok(Self {
            backend: InputBackend::Uinput(Mutex::new(UinputState {
                main: device,
                abs: Some(build_abs_device()?),
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
    /// uinput injects through the ABS pointer device, so no
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
                let state = state.get_mut().unwrap();
                let events = [
                    InputEvent::new(EV_ABS, AbsoluteAxisCode::ABS_X.0, x_norm as i32),
                    InputEvent::new(EV_ABS, AbsoluteAxisCode::ABS_Y.0, y_norm as i32),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                emit_abs(state, &events)?;
                Ok(())
            }
        }
    }

    /// Press or release a mouse button
    pub fn mouse_button(&mut self, button: MouseKey, pressed: bool) -> Result<()> {
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

    /// Inject one Linux evdev keycode — what the wire actually carries.
    ///
    /// The uinput backend emits the code straight to the kernel. Routing it
    /// through enigo's `Key` first (as this used to) made every key depend on a
    /// table that exists for the X11 rung's benefit: an unmapped code became a
    /// control character, that control character became `KEY_UNKNOWN`, and a
    /// letter, a digit or Shift arriving from the phone was simply never seen by
    /// the desktop. The virtual keyboard declares codes 0..255, so anything the
    /// phone can name is already registrable here.
    fn inject_keycode(&mut self, code: u16, pressed: bool) -> Result<()> {
        match &mut self.backend {
            InputBackend::Uinput(state) => {
                let dev = &mut state.get_mut().unwrap().main;
                let events = [
                    InputEvent::new(EV_KEY, code, i32::from(pressed)),
                    InputEvent::new(EV_SYN, SYN_REPORT, 0),
                ];
                dev.emit(&events).context("uinput keycode failed")
            }
            InputBackend::Enigo(_) => match keycode_to_enigo(code) {
                Some(key) => self.key(key, pressed),
                None => {
                    debug!(code, "no enigo key for this evdev keycode, not injecting");
                    Ok(())
                }
            },
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
            InputPacket::KeyEvent { key, pressed } => self.inject_keycode(*key, *pressed),
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
            // Likewise: the relay bitrate floor is server-side quality
            // control, never an input event.
            InputPacket::FullQuality { .. } => Ok(()),
            // Link-profile preset (R4 E5) is server-side bitrate control,
            // handled by the streaming server's arbiter, never injected.
            InputPacket::QualityPreset { .. } => Ok(()),
            // Mic audio is consumed by the streaming server's mic relay task
            // (R4 E2) before the input channel; never injected.
            InputPacket::Mic { .. } => Ok(()),
            // The client's own link reading and latency samples are consumed by
            // the streaming server's connection monitor and folded into the
            // session record; never injected.
            InputPacket::LinkFeedback { .. } | InputPacket::ClientSamples { .. } => Ok(()),
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

/// Emit events on the absolute-pointer device, creating it lazily on first use.
fn emit_abs(state: &mut UinputState, events: &[InputEvent]) -> Result<()> {
    if state.abs.is_none() {
        state.abs = Some(build_abs_device()?);
    }
    state
        .abs
        .as_mut()
        .unwrap()
        .emit(events)
        .context("uinput absolute-pointer emit failed")
}

/// Build an `ABS_X`/`ABS_Y` virtual pointer. Coordinates arrive normalized
/// 0..=65535 from the client, so the axis ranges map the wire values 1:1 and
/// libinput scales them onto the layout. (An MT touchscreen device is the
/// other obvious choice, but Hyprland's libinput silently drops uinput
/// touchscreens on this box; the ABS pointer path is what verifiably moves
/// the real cursor.)
fn build_abs_device() -> Result<VirtualDevice> {
    let mut keys = AttributeSet::<KeyCode>::new();
    // Buttons registered so the device classifies as a full pointer;
    // clicks are emitted on the main device (same merged core pointer).
    for keycode in 272..=276u16 {
        keys.insert(KeyCode(keycode));
    }

    let abs_x = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_X,
        AbsInfo::new(0, 0, ABS_MAX_COORD, 0, 0, 0),
    );
    let abs_y = UinputAbsSetup::new(
        AbsoluteAxisCode::ABS_Y,
        AbsInfo::new(0, 0, ABS_MAX_COORD, 0, 0, 0),
    );

    #[allow(deprecated)]
    let device = VirtualDeviceBuilder::new()
        .context("Failed to create abs pointer builder")?
        .with_keys(&keys)
        .context("Failed to set up abs pointer buttons")?
        .with_absolute_axis(&abs_x)
        .context("Failed to set up ABS_X")?
        .with_absolute_axis(&abs_y)
        .context("Failed to set up ABS_Y")?
        .name(b"Linux Link Virtual Abs Pointer")
        .build()
        .context("Failed to build uinput absolute pointer device")?;

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
///
/// `None` means "this backend cannot express that key". It must stay `None`:
/// inventing a `Key::Unicode` from the raw code number yields the control
/// character that code happens to be (KEY_A = 30 is U+001E), which XTEST then
/// injects as garbage, and the table's own reverse lookup turns it into
/// `KEY_UNKNOWN` on the uinput path.
fn keycode_to_enigo(code: u16) -> Option<Key> {
    KEYCODE_MAP
        .iter()
        .find(|&&(k, _)| k == code)
        .map(|&(_, key)| key)
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

/// Map a character to the Linux evdev keycode that produces it.
///
/// Reads [`KEYCODE_MAP`] so the table stays the one place a character's key is
/// named, then handles the few characters the table spells as a named key rather
/// than as themselves. Case is folded because this runs on the `text()` path,
/// which sends no Shift, so an uppercase letter shares the lowercase key.
fn char_to_keycode(ch: char) -> Option<u16> {
    if let Some(&(code, _)) = KEYCODE_MAP
        .iter()
        .find(|&&(_, key)| key == Key::Unicode(ch.to_ascii_lowercase()))
    {
        return Some(code);
    }
    match ch {
        ' ' => Some(KeyCode::KEY_SPACE.0),
        '\n' => Some(KeyCode::KEY_ENTER.0),
        '\t' => Some(KeyCode::KEY_TAB.0),
        '*' => Some(KeyCode::KEY_KPASTERISK.0),
        '+' => Some(KeyCode::KEY_KPPLUS.0),
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
        let function_keys: [(u16, Key); 12] = [
            (59, Key::F1),
            (60, Key::F2),
            (61, Key::F3),
            (62, Key::F4),
            (63, Key::F5),
            (64, Key::F6),
            (65, Key::F7),
            (66, Key::F8),
            (67, Key::F9),
            (68, Key::F10),
            (87, Key::F11),
            (88, Key::F12),
        ];
        for (code, key) in function_keys {
            assert_eq!(keycode_to_enigo(code), Some(key), "evdev {code}");
        }
    }

    #[test]
    fn test_keycode_to_enigo_common() {
        assert_eq!(keycode_to_enigo(28), Some(Key::Return)); // KEY_ENTER
        assert_eq!(keycode_to_enigo(14), Some(Key::Backspace)); // KEY_BACKSPACE
        assert_eq!(keycode_to_enigo(57), Some(Key::Space)); // KEY_SPACE
        assert_eq!(keycode_to_enigo(15), Some(Key::Tab)); // KEY_TAB
        assert_eq!(keycode_to_enigo(1), Some(Key::Escape)); // KEY_ESC
    }

    #[test]
    fn test_keycode_to_enigo_navigation() {
        let navigation: [(u16, Key); 10] = [
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
        ];
        for (code, key) in navigation {
            assert_eq!(keycode_to_enigo(code), Some(key), "evdev {code}");
        }
    }

    #[test]
    fn an_unmapped_keycode_is_not_injected_as_a_control_character() {
        // A code the table does not name is refused rather than turned into the
        // control character its number happens to be: KEY_SCROLLLOCK = 70 would
        // otherwise reach XTEST as U+0046, the letter 'F'.
        assert_eq!(keycode_to_enigo(70), None, "KEY_SCROLLLOCK");
        assert_eq!(keycode_to_enigo(999), None, "beyond the evdev range");
    }

    /// The server half of the key contract in `core::input::keys`: every code the
    /// Android client can put on the wire must name a key on the X11 rung too, so
    /// a phone without /dev/uinput access degrades the same way as one with it.
    #[test]
    fn every_key_the_phone_can_send_has_a_mapping() {
        for code in linux_link_core::input::keys::phone_emittable_codes() {
            assert!(
                keycode_to_enigo(code).is_some(),
                "evdev code {code} is emittable but unmapped"
            );
        }
    }

    #[test]
    fn modifiers_locks_and_media_keys_map_to_their_named_keys() {
        let named: [(u16, Key); 19] = [
            (42, Key::LShift),          // KEY_LEFTSHIFT
            (54, Key::RShift),          // KEY_RIGHTSHIFT
            (29, Key::LControl),        // KEY_LEFTCTRL
            (97, Key::RControl),        // KEY_RIGHTCTRL
            (56, Key::Alt),             // KEY_LEFTALT
            (100, Key::Other(0xFFEA)),  // KEY_RIGHTALT, via XK_Alt_R
            (125, Key::Meta),           // KEY_LEFTMETA
            (126, Key::Other(0xFFEC)),  // KEY_RIGHTMETA, via XK_Super_R
            (58, Key::CapsLock),        // KEY_CAPSLOCK
            (69, Key::Numlock),         // KEY_NUMLOCK
            (99, Key::PrintScr),        // KEY_SYSRQ, the Print key
            (139, Key::LMenu),          // KEY_MENU, the application key
            (114, Key::VolumeDown),     // KEY_VOLUMEDOWN
            (115, Key::VolumeUp),       // KEY_VOLUMEUP
            (163, Key::MediaNextTrack), // KEY_NEXTSONG
            (164, Key::MediaPlayPause), // KEY_PLAYPAUSE
            (165, Key::MediaPrevTrack), // KEY_PREVIOUSSONG
            (55, Key::Multiply),        // KEY_KPASTERISK
            (78, Key::Add),             // KEY_KPPLUS
        ];
        for (code, key) in named {
            assert_eq!(keycode_to_enigo(code), Some(key), "evdev {code}");
        }
    }

    #[test]
    fn letters_digits_and_punctuation_map_to_their_own_characters() {
        let characters: [(u16, char); 12] = [
            (30, 'a'),  // KEY_A
            (44, 'z'),  // KEY_Z
            (50, 'm'),  // KEY_M
            (2, '1'),   // KEY_1
            (11, '0'),  // KEY_0
            (12, '-'),  // KEY_MINUS
            (41, '`'),  // KEY_GRAVE
            (40, '\''), // KEY_APOSTROPHE
            (51, ','),  // KEY_COMMA
            (52, '.'),  // KEY_DOT
            (53, '/'),  // KEY_SLASH
            (26, '['),  // KEY_LEFTBRACE
        ];
        for (code, ch) in characters {
            assert_eq!(
                keycode_to_enigo(code),
                Some(Key::Unicode(ch)),
                "evdev {code} should be '{ch}'"
            );
            assert_eq!(char_to_keycode(ch), Some(code), "'{ch}'");
        }
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
                Some(enigo_key),
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
