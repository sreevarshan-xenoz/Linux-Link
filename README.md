# Linux Link

**Remote desktop for Linux with Wayland-native screen streaming + full KDE Connect feature set — all over Tailscale. No port forwarding required.**

[![Rust](https://img.shields.io/badge/Rust-Pure%20Rust-orange?logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT%2FApache--2.0-blue)](LICENSE)
[![Issues](https://img.shields.io/github/issues/sreevarshan-xenoz/Linux-Link)](https://github.com/sreevarshan-xenoz/Linux-Link/issues)
[![Phase](https://img.shields.io/badge/Phase-6%20Complete-brightgreen)](plan.md)

> **Target:** Sub-100ms latency screen streaming + KDE Connect integration + zero-config Tailscale connectivity

## What is Linux Link?

Linux Link is a **pure Rust** remote desktop solution built specifically for Linux (Wayland/Hyprland). It combines:

- **Low-latency screen streaming** — PipeWire capture → FFmpeg H.264 encoding → QUIC transport → Android decode
- **Full KDE Connect feature parity** — clipboard sync, file transfer, notifications, input control, battery info
- **Tailscale-native connectivity** — No manual port forwarding or NAT traversal; just pair and connect

### Key Differentiators

| Feature | Linux Link | RustDesk | Sunshine/Moonlight | KDE Connect |
|---------|:----------:|:--------:|:-------------------:|:-----------:|
| Tailscale-native | ✅ | ❌ | ❌ | ❌ |
| Wayland-native | ✅ | ⚠️ Partial | ⚠️ Partial | ✅ |
| Hyprland optimized | ✅ | ❌ | ⚠️ Limited | ⚠️ Limited |
| Full KDE Connect | ✅ | ⚠️ Partial | ❌ | ✅ |
| Pure Rust | ✅ | ✅ | ❌ (C++) | ❌ (C++) |
| Open Source | ✅ | ✅ | ✅ | ✅ |

## Project Status

**Phase 0-3 Complete** — Streaming foundation is done with 50 tests passing.

### What's Working

| Component | Status |
|-----------|--------|
| CLI + Tailscale handshake | ✅ Complete |
| Device discovery | ✅ Complete |
| KDE Connect protocol runtime (all 5 plugins) | ✅ Complete |
| PipeWire screen capture | ✅ Complete |
| FFmpeg H.264 encoder | ✅ Complete |
| QUIC streaming transport | ✅ Complete |
| Adaptive bitrate controller | ✅ Complete |
| Native input injection (enigo) | ✅ Complete |
| Quality gates (`fmt`, `clippy`, `test`) | ✅ 50 tests passing |

### What's Next

- **Phase 4:** Android client with Flutter + Rust FFI
- **Phase 5:** Polish, performance optimization, E2E testing
- **Phase 6:** Release packaging (AUR, APK)

## Architecture

```
┌─────────────────────┐         Tailscale          ┌─────────────────────┐
│   Android Client    │◄──── Encrypted P2P ────────│   Linux Server      │
│   (Flutter + Rust)  │                            │   (Hyprland)        │
├─────────────────────┤                            ├─────────────────────┤
│  UI Layer           │                            │  Rust Daemon        │
│  ├── Connection Mgr │                            │  ├── Screen Capture │
│  ├── Video Player   │                            │  ├── FFmpeg Encoder  │
│  ├── File Browser   │                            │  ├── QUIC Transport │
│  └── Settings       │                            │  └── KDE Plugins    │
├─────────────────────┤                            └─────────────────────┘
│  Rust Backend (FFI) │
│  ├── Protocol       │
│  ├── Video Decoder  │
│  └── Input Handler  │
└─────────────────────┘
```

## Tech Stack

**Server:** Rust (Tokio async runtime) + PipeWire + FFmpeg + QUIC (quinn) + Tailscale local API + Hyprland IPC + enigo

**Client:** Flutter (Dart) + flutter_rust_bridge + MediaCodec

**Protocol:** KDE Connect TCP packets + custom QUIC streaming channel

## Getting Started

### Prerequisites

- Linux with Wayland compositor (Hyprland recommended)
- Tailscale installed and authenticated
- Android device for client (Phase 4 in progress)

### Build from Source

```bash
# Clone the repo
git clone https://github.com/sreevarshan-xenoz/Linux-Link.git
cd Linux-Link

# Build the workspace
cargo build --workspace

# Run tests
cargo test --workspace

# Format check
cargo fmt --check
cargo clippy -- -D warnings
```

### Quick Start

```bash
# Start the server daemon
cargo run --bin linux-link-server

# View available capabilities
cargo run --bin linux-link capabilities

# Connect from Android (Phase 4)
# App coming soon!
```

### systemd Service (Auto-start on Boot)

To have Linux Link start automatically on boot:

1. Build the release binary:
   ```bash
   cargo build --release --bin linux-link
   ```

2. Install the binary:
   ```bash
   sudo cp target/release/linux-link /usr/bin/linux-link
   ```

3. Install the systemd service:
   ```bash
   sudo cp linux-link.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

4. Enable and start the service:
   ```bash
   sudo systemctl enable --now linux-link
   ```

5. Verify it's running:
   ```bash
   systemctl status linux-link
   ```

The service depends on `tailscaled.service` and `network-online.target`.
Configuration is read from `~/.config/linux-link/config.toml`.

## Contributing

Linux Link is actively developed and **looking for contributors**! Whether you're into Rust, Flutter, Wayland internals, or just want to help test — all contributions are welcome.

### Ways to Contribute

- **Android Client (Phase 4)** — Flutter + Rust FFI expertise needed
- **Testing & Feedback** — Run it on different Wayland compositors
- **Performance** — Profiling, latency optimization, FPS improvements
- **Documentation** — Improving docs, writing guides
- **Code** — Any of the existing modules can use help

### Good First Issues

- `good first issue` — Easy wins to get started
- `help wanted` — Features that need extra attention
- `documentation` — Docs that need writing

### Contributing Guidelines

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Ensure code passes `cargo fmt`, `cargo clippy`, and `cargo test`
4. Submit a pull request with a clear description

## Project Structure

```
Linux-Link/
├── core/               # Shared Rust library
│   ├── src/
│   │   ├── kde/        # KDE Connect protocol implementation
│   │   └── streaming/  # Screen capture, encoding, transport
├── server/             # Linux server daemon
│   └── src/
│       └── plugins/    # KDE plugins (battery, clipboard, input, etc.)
├── android/            # Android client (Phase 4)
│   └── lib/            # Flutter app
├── docs/               # Additional documentation
├── .github/            # CI/CD workflows
└── plan.md             # Full development plan
```



---

**Stars, forks, and PRs are welcome!** If Linux Link sounds interesting to you, drop a ⭐ and say hi.
