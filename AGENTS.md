# AGENTS.md

This file provides guidance to the AI agent when working with code in this repository.

## Workflow rules

- Commit each completed, verified logical change as you go — don't batch a whole task into one commit at the end, and don't wait to be asked. Conventional commits with scope: `feat(android): ...`, `fix(core): ...`, `docs: ...`. Never push unless explicitly asked.
- Update the docs a change touches (README.md, CONTRIBUTING.md, docs/) in the same commit.
- Keep the *Current Status* section at the bottom accurate whenever project state changes — this file is the dev-agent context anchor for Linux Link.

## Build / test / lint

- Rust workspace members: `core`, `server`, `android/bridge`, `spike/iroh` (edition 2024; the spike is a throwaway research crate, `publish = false`).
- The bridge builds `linux-link-core` with `default-features = false, features = ["client"]`. Every change in `core` must compile and pass clippy under BOTH profiles:
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo clippy -p linux-link-core --no-default-features --features client -- -D warnings`
- Tests: `cargo test --workspace`.
- Kotlin app: `cd android && ./gradlew assembleDebug`. Android SDK (Platform 37, Build-Tools 37, NDK 29) and Gradle wrapper are configured and buildable on host. The APK needs the bridge `.so` in `android/app/src/main/jniLibs/<abi>/` first (gitignored): `cd android/bridge && cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build`. See docs/development-setup.md §4.

## Gotchas

- `android/bridge` is a cdylib producing `liblinux_link_android_bridge.so`, loaded by `RustCore.kt`. JNI exports must match the Kotlin package exactly: `Java_dev_linuxlink_android_bridge_<Class>_<method>`.
- Edition 2024 requires `#[unsafe(no_mangle)]`, not `#[no_mangle]`.
- `main` carries pre-existing fmt/clippy debt in files untouched by current work (new clippy 1.98 lints, ~35 files not rustfmt-clean). Format or fix only files your change actually touches; never reformat wholesale.
- `cargo clippy --workspace` unifies features across members, so it catches client+server cfg conflicts that per-package checks miss. Run it after changing feature gates in `core`.
- Server runtime needs Linux desktop libs (PipeWire, Wayland, xdg-desktop-portal); the server *build* also links system FFmpeg (`ffmpeg-next` under the `encode` feature) — install the libav* dev packages, not just the `ffmpeg` binary.
- iroh lives behind the NON-DEFAULT `wan` feature (core); the Android bridge builds core with `client,wan`. WAN code paths are only compiled/tested with an explicit `--features wan` (e.g. `cargo test -p linux-link-core --features wan`).
- Hyprland 0.56's socket1 IPC write dispatchers (`dispatch`/`keyword`/`setoption`) are broken upstream (hyprwm/Hyprland#16224) — never use them. All window/workspace actions ride the uinput injection path (Super+N hotkeys, etc.). Read-side `j/…` queries work fine.
- VAAPI init fails on this box (`Failed to initialise VAAPI connection`) even though `renderD128` exists — environment, not code. The direct-FFmpeg `--ignored` encoder tests and any HW-encode work are unverifiable here.
- Every UI/transport feature is gated on `assembleDebug` + `lintDebug` (Kotlin) and both clippy profiles + `cargo test --workspace` (Rust), but **almost nothing has been run on a real device** — treat on-device behavior as unverified unless the bullet says otherwise. `docs/` carries the on-device verification checklist (commit 4469e83).

## Current Status (keep this up to date)

The detailed build journal lives in `git log` — one conventional commit per logical change, so status bullets here must stay at the milestone level, not the file/function level.

- 2026-09-20: Tiers 1–3 of the roadmap are fully implemented: native Kotlin client + Rust JNI bridge (~54 exports), streaming/encode/transport pipeline, absolute touch input, session shell, clipboard, single-window + per-monitor streaming, Hyprland workspace HUD, PIN pairing (TCP **and** QUIC paths), battery/siren/WoL relay/notification reply, privacy grab + blackout, audio control, PiP, roaming hardening, WAN (iroh) connect with LAN-first fallback, i18n (en/es/ta). **All pending on-device verification (no device attached).**
- 2026-09-21: R4 (plan: `docs/rustdesk-research-roadmap.md`) — landed: A1 link-path reporting, A2 session outcome telemetry (`linux-link sessions`), A3/E5 relay bitrate floor + full-quality override, B1 wlroots `zwlr_screencopy` capture backend, B2 window-granular capture via `hyprland_toplevel_export_v1` (B1+B2 are the two items verified live on this Hyprland box), D1 server-enforced view-only mode. WindowCrop wire is now 25 bytes (u64 Hyprland address appended) — pre-B2 17-byte frames are rejected; both ends ship together, no compat shim.
- Next: R4 D3 (roadmap phase D — one-time scoped PINs). Parked: R2#3 remainder (in-process VAAPI/NVENC — untestable on this box).
- Licensing rule (from the R4 research): RustDesk (AGPL-3.0) and Sunshine (GPL-3.0) contribute architecture/technique only, never code; scrcpy (Apache-2.0) and IronRDP (MIT/Apache-2.0) are the sole code-borrowable projects.
- Working tree routinely carries the user's parallel in-progress edits across core/server/bridge — never revert, stash, or reformat uncommitted work that isn't yours.
- `FIX_PLAN.md`, `ARCHITECTURE.html`, and `CHANGELOG.md` describe the Flutter-era design — historical reference, not current truth. (`plan.md` was updated 2026-09-19 to reflect the Kotlin client; its Flutter snippets remain under an explicit historical banner.)
