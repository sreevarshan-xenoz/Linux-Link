# AGENTS.md

This file provides guidance to the AI agent when working with code in this repository.

## Workflow rules

- Commit each completed, verified logical change as you go — don't batch a whole task into one commit at the end, and don't wait to be asked. Conventional commits with scope: `feat(android): ...`, `fix(core): ...`, `docs: ...`. Never push unless explicitly asked.
- Update the docs a change touches (README.md, CONTRIBUTING.md, docs/) in the same commit.
- Keep the *Current Status* section at the bottom accurate whenever project state changes — this file is the dev-agent context anchor for Linux Link.

## Build / test / lint

- Rust workspace members: `core`, `server`, `android/bridge` (edition 2024).
- The bridge builds `linux-link-core` with `default-features = false, features = ["client"]`. Every change in `core` must compile and pass clippy under BOTH profiles:
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo clippy -p linux-link-core --no-default-features --features client -- -D warnings`
- Tests: `cargo test --workspace`.
- Kotlin app: `cd android && ./gradlew assembleDebug`. Android SDK (Platform 37, Build-Tools 37, NDK 29) and Gradle wrapper are configured and buildable on host.

## Gotchas

- `android/bridge` is a cdylib producing `liblinux_link_android_bridge.so`, loaded by `RustCore.kt`. JNI exports must match the Kotlin package exactly: `Java_dev_linuxlink_android_bridge_<Class>_<method>`.
- Edition 2024 requires `#[unsafe(no_mangle)]`, not `#[no_mangle]`.
- `main` carries pre-existing fmt/clippy debt in files untouched by current work (new clippy 1.98 lints, ~35 files not rustfmt-clean). Format or fix only files your change actually touches; never reformat wholesale.
- `cargo clippy --workspace` unifies features across members, so it catches client+server cfg conflicts that per-package checks miss. Run it after changing feature gates in `core`.
- Server runtime needs Linux desktop libs (PipeWire, Wayland, xdg-desktop-portal); CI installs `libpipewire-0.3-dev libwayland-dev libegl1-mesa-dev libgbm-dev`.

## Current Status (keep this up to date)

- 2026-09-19: Native Kotlin scaffold (`android/app`, AGP 9.4 / Compose with `compileSdk = 37`) and Rust JNI bridge crate (`android/bridge`) are verified and buildable locally on host using OpenJDK 21 LTS, Android SDK 37, NDK 29, and `cargo-ndk`. Gradle wrapper generated and tested (`assembleDebug` succeeds).
- Next: port the client API surface from the deleted `android/rust/src/api.rs` (recoverable from git history) onto `android/bridge` using `core`'s `client` feature; MediaCodec decode via JNI Surface; Compose screens (connection, remote desktop, file browser, settings).
- `FIX_PLAN.md`, `ARCHITECTURE.html`, and `CHANGELOG.md` describe the Flutter-era design — historical reference, not current truth. (`plan.md` was updated 2026-09-19 to reflect the Kotlin client; its Flutter snippets remain under an explicit historical banner.)
