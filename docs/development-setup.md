# Linux Link Development Setup

This guide covers the Rust workspace and the native Android (Kotlin) client.

## 1. Prerequisites

- Rust toolchain (stable, edition 2024)
- JDK 17+ and Android SDK/NDK (for the Android client)
- Gradle (to generate the wrapper once: `cd android && gradle wrapper`)
- FFmpeg, PipeWire, xdg-desktop-portal (for the server/streaming)

## 2. Rust Workspace Validation

From repository root:

```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p linux-link-core --no-default-features --features client -- -D warnings
```

The second clippy command matters: the Android bridge builds `core` with
`default-features = false, features = ["client"]`, and that profile has
code paths the server build never compiles.

## 3. Server Run

```bash
cargo run --bin linux-link -- start
```

Optional config file location:

- `~/.config/linux-link/config.toml` (see `config.toml.example`)

## 4. Android Client (Kotlin + Rust JNI bridge)

- `android/app` — Kotlin/Compose app. Build with `cd android && ./gradlew assembleDebug`
  (requires Android SDK; the Gradle wrapper must be generated first).
- `android/bridge` — Rust cdylib (`liblinux_link_android_bridge.so`) loaded via JNI by
  `dev.linuxlink.android.bridge.RustCore`. Cross-compile for device with cargo-ndk:
  `cargo ndk -t arm64-v8a build -p linux-link-android-bridge --release`
  (then point Gradle at the output, or wire a full NDK build task).

The bridge currently exposes only a version round-trip; the session/streaming/input
API port from the old Flutter bridge is in progress — see AGENTS.md *Current Status*.
