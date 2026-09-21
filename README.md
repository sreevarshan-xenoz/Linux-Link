# Linux Link

**Remote desktop for Linux with Wayland-native screen streaming + full KDE Connect feature set — all over Tailscale. No port forwarding required.**

[![Rust](https://img.shields.io/badge/Rust-Pure%20Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](LICENSE)
[![CI](https://github.com/sreevarshan-xenoz/Linux-Link/actions/workflows/ci.yml/badge.svg)](https://github.com/sreevarshan-xenoz/Linux-Link/actions)
[![Issues](https://img.shields.io/github/issues/sreevarshan-xenoz/Linux-Link)](https://github.com/sreevarshan-xenoz/Linux-Link/issues)
[![Phase](https://img.shields.io/badge/Phase-6%20Complete%20--%20Release%20Ready-brightgreen)](plan.md)

> **Target:** Sub-100ms latency screen streaming + KDE Connect integration + zero-config Tailscale connectivity

## What is Linux Link?

Linux Link is a **pure Rust** remote desktop solution built specifically for Linux (Wayland/Hyprland). It combines:

- **Low-latency screen streaming** — wlroots/PipeWire capture → FFmpeg H.264 encoding → QUIC transport → Android MediaCodec decode
- **Full KDE Connect feature parity** — clipboard sync, file transfer, notifications, input control, battery info, remote file browsing
- **Tailscale-native connectivity** — No manual port forwarding or NAT traversal; just pair and connect

### Key Differentiators

| Feature | Linux Link | RustDesk | Sunshine/Moonlight | KDE Connect |
|---------|:----------:|:--------:|:-------------------:|:-----------:|
| Tailscale-native | ✅ | ❌ | ❌ | ❌ |
| Wayland-native | ✅ | ⚠️ Partial | ⚠️ Partial | ✅ |
| Hyprland optimized | ✅ | ❌ | ⚠️ Limited | ⚠️ Limited |
| Full KDE Connect | ✅ | ⚠️ Partial | ❌ | ✅ |
| Screen streaming | ✅ | ✅ | ✅ | ❌ |
| Pure Rust | ✅ | ✅ | ❌ (C++) | ❌ (C++) |
| Open Source | ✅ | ✅ | ✅ | ✅ |

## Features

### Screen Streaming
- **Native wlroots capture** — direct `zwlr_screencopy` on Hyprland (no portal grant dialog), damage-driven variable frame rate; automatic fallback to **PipeWire capture** via XDG Desktop Portal on any other Wayland compositor, X11 grab last
- **FFmpeg H.264 encoding** with persistent sidecar process for low latency
- **QUIC transport** (datagram mode) with self-signed TLS certificates
- **Adaptive bitrate** — 3 presets (LAN/internet/low-bandwidth) with RTT-based congestion control
- **MediaCodec hardware decode** on the native Android client via JNI
- **Single-window streaming** (Hyprland) — pick any window on the phone and the server crops + re-encodes to just that window

### KDE Connect Integration
- **Clipboard sync** — bidirectional clipboard sharing via `wl-clipboard`
- **File transfer** — send files from Android to Linux via KDE Share protocol
- **Remote file browsing** — browse and navigate Linux directories from Android
- **Notifications** — receive Android notifications on your Linux desktop
- **Notification reply** — answer desktop notifications from the phone; the desktop records the reply, copies it to the clipboard and shows a confirmation
- **Find my device** — ring the desktop from the phone, or ring the phone from the desktop
- **PIN pairing** — 6-digit PIN pairing (shown on the desktop or printed by `linux-link pair`); unpaired connections are locked out — the control channel (TCP and v2/QUIC) and the video/input stream all enforce it — unless `pairing_required = false`
- **Privacy mode** — block the desktop's physical keyboard+mouse while remote (EVIOCGRAB with a 10-min auto-release TTL), lock the desktop from the phone or its session notification; uinput remote input keeps flowing
- **View-only mode** — one tap makes the phone a pure viewer: the *server* drops all remote input for the session (video, clipboard and HUDs keep working), so nothing slips through from a stale tap queue; re-arms automatically after a stream reconnect
- **Relay bandwidth courtesy** — a WAN session riding a relay automatically drops to a conservative video bitrate (relay bandwidth is shared, not ours to saturate) and restores full quality the moment it punches through to direct; one tap on the "Full quality" toggle overrides the floor if you want every bit of it
- **Desktop audio control** — adjust the desktop's volume, mute, and default output device (headphones/speakers) from the phone (wpctl/pactl under the hood)
- **Phone mic share** — one tap turns the phone's microphone into a desktop input device ("Linux Link Mic" PipeWire source, Opus over the session stream): take calls on the PC from the phone; stays live in view-only mode and dies with the session
- **Wake-on-LAN relay** — wake a sleeping desktop from WAN by asking an always-on Linux peer on its LAN to emit the magic packet ("Send Wake-on-LAN" in the app)
- **Input control** — remote mouse/keyboard via trackpad gestures
- **Battery info** — monitor Android device battery from Linux
- **Presenter mode** — play/pause/next/previous from Android

### Android Client
- **Native Kotlin app** (Jetpack Compose, Material 3 dark theme)
- **Rust core** reused via a JNI/UniFFI bridge (no Flutter)
- **Connection screen** with peer discovery over Tailscale
- **Remote desktop** with tap/drag/double-tap gesture input
- **Link status** — connecting/LAN/WAN indicator on the video surface, with failure reasons and one-tap retry
- **Session resilience** — QUIC keepalive + bounded idle timeout hold the link through NAT stalls; a wake-locked foreground service keeps screen-off sessions alive
- **Picture-in-picture** — shrink the live session into a video-only PiP window (desktop aspect ratio, chrome hidden) and keep working in other apps; also enables DeX/docked windows
- **Blackout / pocket mode** — black, touch-locked screen while the session keeps streaming: the phone and its video surface go secure (no screenshots or Recents leakage), brightness drops; double-tap or back to unlock
- **Localized UI** — English, Spanish and Tamil; pick per-app language from the "Language" button on the connect screen (Android 13+)
- **File browser** with local and remote file tabs
- **Settings** with DataStore persistence

### Server
- **CLI** with start/stop/status/list/watch/connect/pair/capabilities commands
- **systemd service** for auto-start on boot
- **TOML configuration** with video quality presets (low/balanced/high)
- **52 passing tests** across core and server crates

## Installation

### Quick Install (Recommended)

```bash
# Install latest release
curl -fsSL https://raw.githubusercontent.com/sreevarshan-xenoz/Linux-Link/main/scripts/install.sh | bash

# Install specific version
curl -fsSL https://raw.githubusercontent.com/sreevarshan-xenoz/Linux-Link/main/scripts/install.sh | bash -s -- v0.1.0

# Non-interactive install (no prompts)
curl -fsSL https://raw.githubusercontent.com/sreevarshan-xenoz/Linux-Link/main/scripts/install.sh | bash -s -- --yes

# Install to custom prefix
curl -fsSL https://raw.githubusercontent.com/sreevarshan-xenoz/Linux-Link/main/scripts/install.sh | bash -s -- --prefix /opt

# Preview without changes
curl -fsSL https://raw.githubusercontent.com/sreevarshan-xenoz/Linux-Link/main/scripts/install.sh | bash -s -- --dry-run
```

### Install Script Options

| Flag | Description |
|------|-------------|
| `--yes`, `-y` | Non-interactive; accept all defaults |
| `--dry-run` | Preview actions without making changes |
| `--verbose` | Show detailed debug output |
| `--force` | Force reinstall even if same version |
| `--no-service` | Skip systemd service installation |
| `--no-config` | Skip config file creation |
| `--no-docs` | Skip documentation installation |
| `--no-man` | Skip man page installation |
| `--prefix PATH` | Install prefix (default: `/usr`) |
| `--check-updates` | Check if installed version is current |
| `--list-versions` | List all available releases |
| `--status` | Show installation status |
| `--rollback` | Roll back to previous version |
| `--uninstall` | Remove installation |

**Management commands** (after install):

```bash
linux-link --status           # Show installed version and config
linux-link --check-updates    # Check for available updates
linux-link --list-versions    # List all available releases
linux-link --rollback         # Roll back to previous version
linux-link --uninstall        # Remove installation
```

### Build from Source

```bash
# Clone the repo
git clone https://github.com/sreevarshan-xenoz/Linux-Link.git
cd Linux-Link

# Build the workspace
cargo build --release

# Run tests
cargo test --workspace

# Run lints
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

### AUR (Arch Linux)

```bash
# Using an AUR helper
yay -S linux-link

# Or manually
git clone https://aur.archlinux.org/linux-link.git
cd linux-link
makepkg -si
```

## Usage

### Start the Server

```bash
# Using the installed binary
linux-link start

# Or with cargo
cargo run --release --bin linux-link -- start

# With custom config
linux-link --config ~/.config/linux-link/config.toml start
```

### Configuration

Copy the example config and customize:

```bash
mkdir -p ~/.config/linux-link
cp config.toml.example ~/.config/linux-link/config.toml
```

```toml
# ~/.config/linux-link/config.toml
control_port = 1716        # KDE Connect compatible
streaming_port = 4716      # QUIC streaming port
log_level = "info"         # trace/debug/info/warn/error
video_quality = "balanced" # low/balanced/high
pairing_required = true    # PIN-pair devices before the control channel or streaming serves requests
# allow_hevc = false       # let negotiating phones drive an H.265/HEVC stream (R4 C1)
```

### systemd Service

```bash
sudo systemctl enable --now linux-link
systemctl status linux-link
journalctl -u linux-link -f
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `linux-link start` | Start the server daemon |
| `linux-link stop` | Stop the running daemon |
| `linux-link status` | Show connection status |
| `linux-link list` | List available peers on tailnet |
| `linux-link watch` | Watch for peer discovery events |
| `linux-link connect <peer>` | Connect to a specific peer |
| `linux-link pair [pin] [--grant 15m]` | Print a 5-minute pairing PIN for the phone (generate or set); `--grant` time-boxes the trust pairing stores (`s/m/h/d`, e.g. `45s`, `15m`, `2h`, `1h30m`) for one-off support sessions |
| `linux-link unpair [device-id]` | Remove a paired device from the trust store (all if omitted) |
| `linux-link sessions [--count N]` | Show recorded streaming-session outcomes (LAN/WAN-punched/WAN-relayed tally + recent log tail) |
| `linux-link capabilities` | Show KDE Connect capabilities |

### Man Page

```bash
man linux-link
```

## Android Client

The Android client is a native Kotlin app in `android/`, bridged to the shared Rust core via JNI/UniFFI.

```bash
cd android
./gradlew assembleDebug   # Debug build
./gradlew assembleRelease # Release build
```

Requires JDK 17+ and Android SDK/NDK.

## Architecture

```
┌─────────────────────────┐         Tailscale          ┌─────────────────────────┐
│   Android Client        │◄──── Encrypted P2P ────────│   Linux Server          │
│   (Kotlin + Rust FFI)   │        (Tailscale IP)      │   (Hyprland)            │
├─────────────────────────┤                            ├─────────────────────────┤
│  UI Layer (Compose)     │                            │  Rust Daemon (tokio)    │
│  ├── Connection Screen  │                            │  ├── Screen Capture     │
│  ├── Remote Desktop     │                            │  ├── FFmpeg H.264 Enc.  │
│  ├── File Browser       │                            │  ├── QUIC Transport     │
│  └── Settings           │                            │  └── Adaptive Bitrate   │
├─────────────────────────┤                            ├─────────────────────────┤
│  Rust Backend (FFI)     │                            │  KDE Connect Plugins    │
│  ├── Connection Mgr     │                            │  ├── Battery            │
│  ├── Video Decoder      │                            │  ├── Clipboard          │
│  ├── File Transfer      │                            │  ├── Notification       │
│  └── Input Handler      │                            │  ├── Share              │
└─────────────────────────┘                            │  ├── File Browse        │
                                                       │  └── Input              │
                                                       └─────────────────────────┘
```

**Data Flow (Streaming):**
```
PipeWire → BGRA Frame → FFmpeg H.264 → QUIC Datagram → MediaCodec → SurfaceView
```

**Data Flow (Input):**
```
Touch Gesture → Rust FFI → QUIC/TCP → KDE mousepad packet → enigo → Wayland
```

## Project Structure

```
Linux-Link/
├── core/                   # Shared Rust library
│   └── src/
│       ├── protocol/       # KDE Connect protocol + connection handling
│       ├── streaming/      # Capture, encoder, QUIC transport, adaptive bitrate
│       └── tailscale/      # Tailscale integration
├── server/                 # Linux server daemon
│   └── src/
│       ├── plugins/        # KDE plugins (5 + file browse)
│       ├── cli.rs          # CLI argument parsing
│       ├── config.rs       # TOML configuration
│       ├── kde.rs          # Plugin registry + service setup
│       └── service.rs      # Main server loop
├── android/                # Android client (native Kotlin)
│   ├── app/                # Kotlin app module (UI, services, MediaCodec decode)
│   └── bridge/             # Rust cdylib crate (UniFFI/JNI bindings to core)
├── aur/                    # AUR packaging (PKGBUILD)
├── docs/                   # Design specs and plans
├── man/                    # Man pages
├── scripts/                # Install script
├── .github/workflows/      # CI/CD (build, test, release, audit)
├── CHANGELOG.md            # Project changelog
├── CONTRIBUTING.md         # Contributor guidelines
├── config.toml.example     # Example configuration
├── linux-link.service      # systemd service file
└── plan.md                 # Full development plan
```

## Quality Gates

| Check | Status |
|-------|--------|
| `cargo fmt` | ✅ Pass |
| `cargo clippy -D warnings` | ✅ Pass (0 warnings) |
| `cargo test --workspace` | ✅ 52 tests pass |
| `cargo check --workspace` | ✅ Clean compilation |

## Contributing

Linux Link is actively developed and looking for contributors!

### Prerequisites

- Rust 1.80+ (edition 2024)
- JDK 17+ and Android SDK/NDK (for the Kotlin client)
- Tailscale (for testing)
- FFmpeg (runtime **and** dev libraries — the server encodes in-process via
  `ffmpeg-next`), PipeWire, xdg-desktop-portal (for streaming)

### Development Workflow

```bash
# Build + test
cargo build --workspace && cargo test --workspace

# Format + lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Android build
cd android && ./gradlew assembleDebug
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## Roadmap

All 6 phases are **complete**. Remaining items are environmental:

- [ ] Native Kotlin client: Rust↔JNI bridge + MediaCodec decode
- [ ] `assembleDebug` verification (requires Android SDK on CI machine)
- [ ] E2E testing on live Hyprland + PipeWire + Tailscale setup
- [ ] First release tag (`v0.1.0`) pushed to GitHub

See [plan.md](plan.md) for the full development plan.

---

**Stars, forks, and PRs are welcome!** If Linux Link sounds interesting to you, drop a ⭐ and say hi.
