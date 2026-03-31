# Linux Link Development Setup

This guide covers the current Rust workspace setup and the next commands needed to continue Phase 0.

## 1. Prerequisites

- Rust toolchain (stable)
- Cargo
- Git
- Flutter SDK (for Android client steps)
- Android SDK/NDK (for Flutter Android builds)

## 2. Rust Workspace Validation

From repository root:

```bash
cargo fmt --all
cargo check --workspace
cargo test --workspace
cargo build --workspace
```

## 3. Server Run (Current Scaffold)

Run the server daemon skeleton:

```bash
cargo run -p linux-link-server
```

Optional config file location:

- `~/.config/linux-link/config.toml`

Example:

```toml
control_port = 1716
```

## 4. Flutter + Android Setup (Pending)

The Android Flutter client is not scaffolded yet in this repository. Once Flutter is installed:

```bash
cd android
flutter create --org com.linuxlink --project-name linux_link_client .
flutter pub get
```

Then integrate `android/rust` through `flutter_rust_bridge` codegen.

## 5. Suggested Next Implementation Target

Phase 1 from plan:

- Implement real Tailscale status/peer discovery in `core/src/tailscale/mod.rs`
- Add connection/discovery commands in server CLI
- Wire incoming control-channel protocol handling
