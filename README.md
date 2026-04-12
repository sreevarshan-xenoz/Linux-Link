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

- **Low-latency screen streaming** — PipeWire capture → FFmpeg H.264 encoding → QUIC transport → Android MediaCodec decode
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
- **PipeWire capture** via XDG Desktop Portal — works on any Wayland compositor
- **FFmpeg H.264 encoding** with persistent sidecar process for low latency
- **QUIC transport** (datagram mode) with self-signed TLS certificates
- **Adaptive bitrate** — 3 presets (LAN/internet/low-bandwidth) with RTT-based congestion control
- **MediaCodec hardware decode** on Android via Flutter platform channels

### KDE Connect Integration
- **Clipboard sync** — bidirectional clipboard sharing via `wl-clipboard`
- **File transfer** — send files from Android to Linux via KDE Share protocol
- **Remote file browsing** — browse and navigate Linux directories from Android
- **Notifications** — receive Android notifications on your Linux desktop
- **Input control** — remote mouse/keyboard via trackpad gestures
- **Battery info** — monitor Android device battery from Linux
- **Presenter mode** — play/pause/next/previous from Android

### Android Client
- **Flutter UI** with Material 3 dark theme
- **Rust FFI bridge** via flutter_rust_bridge (2.12)
- **Connection screen** with peer discovery over Tailscale
- **Remote desktop** with tap/drag/double-tap gesture input
- **File browser** with local and remote file tabs
- **Settings** with SharedPreferences persistence

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
| `linux-link pair <pin>` | Pair with a new device |
| `linux-link capabilities` | Show KDE Connect capabilities |

### Man Page

```bash
man linux-link
```

## Android Client

The Android client is located in `android/` and uses Flutter + Rust FFI.

```bash
cd android
flutter pub get
flutter build apk --debug   # Debug build
flutter build apk --release # Release build
```

Requires Flutter 3.24+ and Android SDK/NDK.

## Architecture

```
┌─────────────────────────┐         Tailscale          ┌─────────────────────────┐
│   Android Client        │◄──── Encrypted P2P ────────│   Linux Server          │
│   (Flutter + Rust FFI)  │        (Tailscale IP)      │   (Hyprland)            │
├─────────────────────────┤                            ├─────────────────────────┤
│  UI Layer (Flutter)     │                            │  Rust Daemon (tokio)    │
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
PipeWire → BGRA Frame → FFmpeg H.264 → QUIC Datagram → MediaCodec → Texture Widget
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
├── android/                # Android client
│   ├── lib/                # Flutter app (screens, providers, services)
│   │   ├── screens/        # Connection, Remote Desktop, File Browser, Settings
│   │   ├── providers/      # Riverpod state management
│   │   ├── services/       # Video player, clipboard, background service
│   │   └── models/         # PeerInfo, RemoteFile
│   ├── rust/               # Rust FFI library (flutter_rust_bridge)
│   └── android/            # Android native code (MediaCodec plugin)
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
- Flutter 3.24+ (for Android client)
- Tailscale (for testing)
- FFmpeg, PipeWire, xdg-desktop-portal (for streaming)

### Development Workflow

```bash
# Build + test
cargo build --workspace && cargo test --workspace

# Format + lint
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# Android build
cd android && flutter build apk --debug
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## Roadmap

All 6 phases are **complete**. Remaining items are environmental:

- [ ] `flutter build apk` verification (requires Flutter SDK on CI machine)
- [ ] E2E testing on live Hyprland + PipeWire + Tailscale setup
- [ ] First release tag (`v0.1.0`) pushed to GitHub

See [plan.md](plan.md) for the full development plan.

---

**Stars, forks, and PRs are welcome!** If Linux Link sounds interesting to you, drop a ⭐ and say hi.
