/// Detected session type for screen capture and input injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// Wayland compositor is active.
    Wayland,
    /// X11 display server is active.
    X11,
    /// Virtual console (TTY) — no graphical capture available.
    Tty,
    /// Could not determine session type.
    Unknown,
}

/// Detect the current display session type.
///
/// Checks environment variables in priority order:
/// 1. `XDG_SESSION_TYPE` — set by systemd-logind (most reliable)
/// 2. `WAYLAND_DISPLAY` — always set by compliant Wayland compositors
/// 3. `DISPLAY` — set by X server (may also be set under XWayland)
///
/// Returns [`SessionType`] indicating the detected session.
pub fn detect_session_type() -> SessionType {
    // Priority 1: XDG_SESSION_TYPE (most reliable, set by systemd-logind)
    if let Ok(session_type) = std::env::var("XDG_SESSION_TYPE") {
        return match session_type.as_str() {
            "wayland" => SessionType::Wayland,
            "x11" => SessionType::X11,
            "tty" => SessionType::Tty,
            _ => SessionType::Unknown,
        };
    }

    // Priority 2: Check display server env vars directly.
    // Always check WAYLAND_DISPLAY first — DISPLAY can be set under XWayland
    // even in Wayland sessions, so WAYLAND_DISPLAY is the definitive indicator.
    let has_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();
    let has_x11 = std::env::var("DISPLAY").is_ok();

    match (has_wayland, has_x11) {
        (true, _) => SessionType::Wayland,
        (_, true) => SessionType::X11,
        _ => SessionType::Unknown,
    }
}

impl SessionType {
    /// Returns true if a Wayland compositor is detected.
    pub fn is_wayland(self) -> bool {
        self == SessionType::Wayland
    }

    /// Returns true if an X11 display server is detected.
    pub fn is_x11(self) -> bool {
        self == SessionType::X11
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_wayland() {
        assert!(SessionType::Wayland.is_wayland());
        assert!(!SessionType::X11.is_wayland());
        assert!(!SessionType::Tty.is_wayland());
        assert!(!SessionType::Unknown.is_wayland());
    }

    #[test]
    fn test_is_x11() {
        assert!(!SessionType::Wayland.is_x11());
        assert!(SessionType::X11.is_x11());
        assert!(!SessionType::Tty.is_x11());
        assert!(!SessionType::Unknown.is_x11());
    }

    #[test]
    fn test_session_type_equality() {
        assert_eq!(SessionType::Wayland, SessionType::Wayland);
        assert_eq!(SessionType::X11, SessionType::X11);
        assert_eq!(SessionType::Tty, SessionType::Tty);
        assert_eq!(SessionType::Unknown, SessionType::Unknown);

        assert_ne!(SessionType::Wayland, SessionType::X11);
    }

    #[test]
    fn test_session_type_copy_clone() {
        let s = SessionType::Wayland;
        let s2 = s;
        assert_eq!(s, s2); // both still valid due to Copy
    }
}
