# Linux Link Development Setup

This guide covers the Rust workspace and the native Android (Kotlin) client.

## 1. Prerequisites

- Rust toolchain (stable, edition 2024) + `cargo-ndk`
- JDK 17+ and Android SDK/NDK (for the Android client)
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

- `android/app` — Kotlin/Compose app.
- `android/bridge` — Rust cdylib (`liblinux_link_android_bridge.so`) loaded via JNI by
  `dev.linuxlink.android.bridge.RustCore`.

Full local build (verified working: SDK Platform 36/37, Build-Tools 36/37, NDK 29):

```bash
# 1. Cross-compile the bridge into the app's jniLibs
cd android/bridge
cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build

# 2. Build the APK (picks the .so up automatically)
cd android
./gradlew assembleDebug   # APK: app/build/outputs/apk/debug/app-debug.apk
```

Notes:

- Gradle finds the SDK via `android/local.properties` (`sdk.dir=...`, gitignored) or
  `ANDROID_HOME`.
- The generated `.so` under `jniLibs/` is gitignored (`*.so`) — every Android build
  must run step 1 first, or the APK will crash at `System.loadLibrary`.
- Add more ABIs with extra `-t` flags (`x86_64-linux-android` target is installed for
  emulator testing).

The bridge currently exposes only a version round-trip; the session/streaming/input
API port from the old Flutter bridge is in progress — see AGENTS.md *Current Status*.
