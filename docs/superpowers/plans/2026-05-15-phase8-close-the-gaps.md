# Phase 8: Close the Gaps

> **Date:** 2026-05-15
> **Status:** Ready
> **Scope:** Complete the 3 partial features + deliver the 6 missing features + fix 2 integration gaps found during Phase 7 audit
> **Target:** 4-6 weeks

---

## 1. Sprint Plan

| Sprint | Focus | Features | Effort |
|--------|-------|----------|--------|
| **Sprint 1** | Low-hanging fruit (3 partials) | F10, F12, F19 | 1 week |
| **Sprint 2** | Quality foundations | F27, F28, F31 | 1.5 weeks |
| **Sprint 3** | Platform expansion | F22, F23 | 2 weeks |
| **Sprint 4** | Advanced features | F30, F32 | 1.5 weeks |

---

## 2. Feature Specifications

### Sprint 1 — Complete the Partials

#### F10: Gamepad Input — Flutter FFI + Android Connection

**Status:** Partial — `InputPacket::Gamepad` encode/decode done, injector mapping done. Missing: Android gamepad capture and FFI send.

**Changes:**
- **`android/rust/src/api.rs`** — Add `send_gamepad_event(axes: Vec<f32>, buttons: u32)` FFI that encodes an `InputPacket::Gamepad` and sends over the QUIC streaming channel (same pattern as `send_mouse_event`)
- **`android/lib/services/gamepad_service.dart`** — New file. Connect to Android `InputDevice` API via MethodChannel, poll gamepad state every 16ms (60Hz), call FFI
- **`android/lib/screens/remote_desktop_screen.dart`** — Optional gamepad overlay button to toggle capture mode

**Test:** Connect Bluetooth gamepad, verify axes/buttons reach server injector

---

#### F12: Drag-and-Drop File Transfer — Drag Source

**Status:** Partial — `DragTarget` on video display accepts drops but nothing initiates a drag from the file browser.

**Changes:**
- **`android/lib/screens/file_browser_screen.dart`** — Add `LongPressDraggable<RemoteFile>` wrapping each file list tile. On long press, show drag preview (file icon + name overlay). On drop onto the remote desktop, call existing `sendFile` FFI
- **`android/lib/widgets/draggable_file_tile.dart`** — New widget, reusable file tile with drag support and visual feedback

**Test:** Long-press file in browser, drag onto remote desktop, verify file arrives in server's Downloads

---

#### F19: Notification Mirroring — Forward Integration

**Status:** Partial — D-Bus capture on server works, Android notification service exists. Missing: wiring to actually deliver captured notifications to the Android client.

Note: FIX-2 in our previous work added the `ACTIVE_CLIENTS` broadcast mechanism on the server. The notification captured data is now broadcast. But the Android `notification_service.dart` needs to consume these.

**Changes:**
- **`android/lib/rust_api_bridge.dart`** — The `pollIncomingPackets()` FFI already delivers raw JSON strings. Add dispatch in the existing polling loop to route `kdeconnect.notification` packets to `NotificationMirrorService`
- **`android/lib/services/notification_service.dart`** — Connect to the packet polling loop in `remote_desktop_screen.dart`, parse incoming notification JSON, call `_showNotification()`
- **`android/lib/screens/settings_screen.dart`** — Add "Notification Mirroring" toggle with per-app filter list (optional, "All apps" by default)

**Test:** Send a notification on the PC (e.g., `notify-send "Test" "Hello"`), verify it appears on Android within 2 seconds

---

### Sprint 2 — Quality Foundations

#### F27: Integration Test Suite

**Changes:**
- **`core/tests/`** — New directory. Integration tests that spin up a real TCP server with mock KDE Connect behavior, connect from Android FFI layer, verify handshake + packet exchange
- **`server/tests/`** — Spawn a real `linux-link` server in test mode, connect a test client, verify plugin dispatch for all 9 plugins
- **`scripts/test-integration.sh`** — Orchestrate: build → start mock server → run FFI tests → stop

**Success:** All plugins respond correctly to their capability packets over a real TCP connection.

---

#### F28: Benchmarking Suite

**Changes:**
- **`core/benches/`** — Criterion benchmarks for:
  - `input_packet` encode/decode throughput (millions/sec)
  - Audio encode latency (p50/p99)
  - QUIC transport serialization
- **`scripts/benchmark.sh`** — Runs benchmarks and compares against previous run (stored in `benches/latest.json`)
- **`docs/benchmarks/`** — Published results table

**Success:** Known baseline latency for all hot paths, regression detection in CI.

---

#### F31: FRB Lifetime Annotation

**Warned during Phase 7 codegen:** `"To handle some types, enable_lifetime: true may need to be set"`

**Changes:**
- **`android/frb_config.yaml`** — Add `enable_lifetime: true`
- Re-run `flutter_rust_bridge_codegen generate`
- Verify all FFI functions still compile on both Rust and Dart sides

---

### Sprint 3 — Platform Expansion

#### F22: Tauri Desktop Client (MVP)

**Scope:** Lightweight desktop client for Linux to connect to another Linux Link server. NOT a full replacement for the Android app — focused on quick remote access from another Linux machine.

**Changes:**
- **`desktop/`** — New directory with Tauri v2 project scaffold
- **`desktop/src-tauri/`** — Rust side: depends on `linux-link-core` (client feature), implements `StreamingClient` + video rendering via `winit`/`wgpu` or embedded `vlc`
- **`desktop/src/`** — TypeScript/React frontend: minimal UI (peer list, connect, view stream, keyboard shortcuts)
- Focus on: Tailscale discovery, H.264 decode via `ffmpeg` or system GStreamer, keyboard input forwarding

**Deferred:** Audio, recording, file transfer, gamepad — these already work from Android

---

#### F23: Localization (i18n)

**Changes:**
- **`android/pubspec.yaml`** — Add `flutter_localizations` + `intl`
- **`android/lib/l10n/`** — Generate via `flutter gen-l10n`
- **`android/lib/l10n/app_en.arb`** — Extract all hardcoded strings (~150 across 8 screens + 3 widgets)
- **`android/lib/l10n/app_ja.arb`** — Add Japanese as second locale (or `es`/`de`/`zh`)
- **`android/lib/main.dart`** — Add `localizationsDelegates` + `supportedLocales`

**Success:** App renders in English or Japanese based on system locale. Zero hardcoded strings remain.

---

### Sprint 4 — Advanced Features

#### F30: Clipboard Sync — Bidirectional Fix

**Current:** Clipboard sync is one-directional (PC → Android) and has no conflict resolution.

**Changes:**
- **`android/lib/services/clipboard_sync_service.dart`** — Add two-way sync:
  - On Android clipboard change → encode as `kdeconnect.clipboard` → send via `CONTROL_WRITER`
  - On receive from PC → update Android clipboard with hash dedup (already works partially)
- Handle conflicts: last-writer-wins with timestamp comparison
- Add debounce (500ms) to avoid echo loops

---

#### F32: Connection Quality Indicators

**Current:** Health provider shows latency/FPS but there's no persistent quality history.

**Changes:**
- **`android/lib/providers/health_provider.dart`** — Add session quality log (timestamp, latency, fps, bitrate — sampled every 5s)
- **`android/lib/screens/connection_history_screen.dart`** — Add quality timeline for past sessions: mini sparkline chart showing latency + FPS over session duration
- **`android/lib/services/history_service.dart`** — Extend `ConnectionRecord` with quality samples array

---

## 3. Effort Summary

| Feature | Effort | Priority | Dependencies |
|---------|--------|----------|-------------|
| F10: Gamepad FFI + Flutter | 2 days | P1 | Phase 7 core |
| F12: Drag source | 1 day | P2 | Phase 7 |
| F19: Notification wiring | 2 days | P1 | FIX-2 (done) |
| F27: Integration tests | 5 days | P1 | none |
| F28: Benchmarks | 3 days | P2 | none |
| F31: FRB lifetime | 0.5 day | P0 | Phase 7 FFI |
| F22: Tauri desktop (MVP) | 10 days | P3 | core crate |
| F23: i18n | 3 days | P2 | none |
| F30: Clipboard bidirectional | 1.5 days | P2 | Phase 7 |
| F32: Quality indicators | 2 days | P3 | F18 history |

**Total:** ~30 days (6 weeks) for all 10 features

## 4. Recommended Order

```
Sprint 1: F31 → F19 → F10 → F12   (week 1)
Sprint 2: F27 → F28               (weeks 2-3)
Sprint 3: F23 → F22               (weeks 3-5)
Sprint 4: F30 → F32               (week 6)
```
