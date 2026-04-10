# Phase 4: Android Client Completion — Design Spec

> **Date:** 2026-04-10
> **Status:** Draft — awaiting review
> **Scope:** Complete Phase 4 Android client: video pipeline, FRB codegen, FFI wiring, background service

---

## 1. Objective

Complete the Android client so that end-to-end remote desktop streaming works:
H.264 frames flow from the Rust QUIC streaming client → Flutter → MediaCodec → Texture widget,
and all FFI functions are wired into Flutter screens. Includes a background service to keep
streaming alive when the app is backgrounded.

---

## 2. Current State Summary

### What Works
- 14 Rust FFI functions in `android/rust/src/lib.rs` (clipboard, peers, connection, file send,
  streaming connect/stop, mouse/keyboard, RTT query)
- QUIC streaming client in `core/src/streaming/client.rs` (connect, receive frames, stats feedback)
- `VideoPlayerPlugin.kt` — full MediaCodec H.264 decoder with Flutter texture channel
- `VideoPlayerService` Dart wrapper with `feedFrame()` method
- Connection screen, settings screen, peer list UI
- Riverpod providers for connection state

### Critical Gap
- **`StreamingHandle.packet_rx` is never drained.** The `connect_streaming` FFI function creates
  a `StreamingHandle` with a `mpsc::Receiver<EncodedPacket>`, but there is no FFI function
  that reads from it. Frames accumulate and are dropped at capacity (8). Flutter/MediaCodec
  never receives any video data.

### Stubbed
- `rust_api_bridge.dart` — all methods are stubs (simulated responses, no actual Rust calls)
- `streaming_provider.dart` — latency is never populated
- `file_browser_screen.dart` — remote file list is hardcoded sample data
- `clipboard_service.dart` — exists but not wired into remote desktop screen

### Missing
1. `receive_frame(s)` FFI function to drain `packet_rx` and deliver H.264 NAL data to Flutter
2. FRB codegen has never been run — no generated bindings
3. Android foreground service — streaming dies when app is backgrounded
4. Remote file browsing FFI and UI
5. Clipboard integration in remote desktop screen
6. Latency feedback loop (`get_streaming_rtt` exists but is never polled)

---

## 3. Architecture

### 3.1 Video Pipeline Fix

The core issue is that `packet_rx` (an `mpsc::Receiver<EncodedPacket>`) lives inside a
`Mutex<Option<StreamingHandle>>` in Rust and is never consumed. The fix adds two FFI functions:

#### `receive_frames(timeout_ms: u64) -> Vec<FrameDto>`
- Non-blocking drain of `packet_rx` with a timeout
- Returns up to 16 packets per call (batch delivery for efficiency; at 60fps with 8ms polling
  interval, ~1 frame is expected per poll — 16 provides headroom for burst delivery)
- Each `FrameDto` contains: `data: Vec<u8>` (H.264 NAL), `is_keyframe: bool`, `sequence: u64`
- Uses `tokio::time::timeout` + batch recv pattern for collection
- Returns empty vec if no frames available (polling model compatible with Flutter timers)

#### `poll_streaming_rtt() -> u64`
- Already exists as `get_streaming_rtt()` — this just connects it to the streaming provider
- Called periodically from Dart (every 1 second) to update latency display
- **Issue:** Currently reads from `Mutex<Option<StreamingHandle>>` which holds a `quinn::Connection`.
  The `connection.stats()` call is fast but the mutex lock could block the Flutter main thread
  if the async `stop_streaming` holds the lock. **Fix:** Add a separate `AtomicU64` for the last
  known RTT, updated by the background stats task. `poll_streaming_rtt` reads this atomic (O(1),
  no lock). The FFI function becomes `#[frb(sync)]` — safe for main thread.

**Data Flow After Fix:**
```
QUIC Server → StreamingClient.recv_with_cancel() → packet_rx (mpsc)
    → receive_frames() FFI → FrameDto[] → Dart List
    → VideoPlayerService.feedFrame() → MediaCodec via MethodChannel
    → SurfaceTexture → Flutter Texture widget
```

**Why polling instead of streaming callback?**
- FRB supports stream types, but they add complexity and require `StreamSink` setup
- Polling is simpler, more debuggable, and sufficient for video (60fps = 16ms budget,
  polling every 8ms gives ample headroom)
- The `receive_frames` batch approach (grab all available per poll) avoids frame backlog

### 3.2 FRB Codegen

Running `flutter_rust_bridge_codegen generate` will:
1. Scan `android/rust/src/lib.rs` for `#[frb]` annotations
2. Generate `android/rust/src/frb_generated.rs` (Rust side)
3. Generate `android/lib/frb_generated.dart` and `android/lib/frb_generated.io.dart` (Dart side)
4. Generate `android/lib/api/` directory with typed Dart wrappers

**After codegen**, the `rust_api_bridge.dart` file is replaced:
- Import generated `RustApi` class
- The existing stub class is removed
- Screens already calling `rustApi.*` will start working once the import is updated

**Potential issues:**
- FRB requires all types used in `#[frb]` functions to be serializable — our types
  (`PeerInfoDto`, `ConnectionState`, `DiscoveryEvent`, `FrameDto`) are all simple
  structs/enums, so this should be clean
- The `android/rust/Cargo.toml` already has `flutter_rust_bridge = "2.12.0"`
- Flutter SDK and Android NDK must be installed and configured

### 3.3 Flutter Screen Wiring

After FRB codegen, each screen needs its stub calls replaced:

| Screen | Current Stub | After Wiring |
|--------|-------------|--------------|
| `connection_screen.dart` | `rustApi.getPeers()`, `rustApi.connectToPeer()` | Same calls, now real |
| `remote_desktop_screen.dart` | `startStreaming()`, `VideoPlayerService.feedFrame()` | Add `receiveFrames()` polling loop |
| `file_browser_screen.dart` | Hardcoded `_remoteFiles` | Add `listRemoteFiles()` FFI + real data |
| `settings_screen.dart` | Already wired to `rustApi.version()` | No change needed |
| `streaming_provider.dart` | Static defaults | Poll `getStreamingRtt()` every 1s |

**Remote Desktop Screen — Frame Polling Loop:**
```dart
// In RemoteDesktopScreenState
Timer? _frameTimer;

void _startFramePolling() {
  _frameTimer = Timer.periodic(const Duration(milliseconds: 8), (_) async {
    final frames = await rustApi.receiveFrames(timeoutMs: 5);
    if (frames.isNotEmpty) {
      await _videoService!.feedFrames(frames.map(_toFrame).toList());
    }
    // Update latency
    final rtt = rustApi.getStreamingRtt();
    ref.read(latencyProvider.notifier).state = rtt;
  });
}
```

### 3.4 Background Service

**Goal:** Keep streaming alive when the app is backgrounded (e.g., user switches to another app).

**Approach:** Android Foreground Service with persistent notification.

**Components:**
1. **`<service>` declaration** in `AndroidManifest.xml` with `FOREGROUND_SERVICE` type
2. **Dart initialization** — call `FlutterBackgroundService.initializeService()` at app start
3. **Service configuration** — notification title, description, icon
4. **Keep-alive logic** — the Rust streaming loop runs in a `tokio::spawn` task within the
   same process as the Flutter activity. The foreground service keeps the process alive.

**What the service does NOT do:**
- It does not run a separate native Android service process
- It does not start streaming on its own — streaming is still initiated by the Flutter UI
- It simply prevents Android from killing the process when backgrounded

**Implementation:**
```dart
// In main.dart or a service initializer
Future<void> initBackgroundService() async {
  final service = FlutterBackgroundService();
  await service.configure(
    androidConfiguration: AndroidConfiguration(
      onStart: _onStart,
      autoStart: false,
      isForegroundMode: true,
      notificationChannelId: 'linux_link_streaming',
      initialNotificationTitle: 'Linux Link',
      initialNotificationContent: 'Streaming active',
      foregroundServiceNotificationId: 888,
    ),
  );
}

@pragma('vm:entry-point')
Future<void> onStart(ServiceInstance service) async {
  // Called when the foreground service starts
  // The Rust tokio runtime continues running in the background
}
```

**When to start/stop:**
- Start foreground service when `connect_streaming` succeeds
- Stop when `stop_streaming` is called or connection is lost

### 3.5 Remote File Browsing (Deferred)

The plan lists remote file browsing, but this requires:
1. A new server-side plugin or extension for directory listing
2. New FFI functions: `list_remote_files(path)`, `download_file(remote_path, local_path)`
3. Flutter UI updates for the remote file list

**Decision:** Defer to Phase 5. The `send_file` FFI already works, and the file browser screen
has a functional UI. The hardcoded remote list is cosmetic. Adding full remote browsing
requires server-side changes that are outside the MVP scope.

**What we DO for file browser:**
- Replace the hardcoded `_remoteFiles` with an empty list + "Remote browsing coming soon"
- Keep the local file selection and sending fully functional
- This is cleaner than a fake list that does nothing

---

## 4. Implementation Order

Two parallel tracks, then integration:

### Track 1: Streaming Pipeline (Rust)
1. Add `FrameDto` struct to `android/rust/src/lib.rs`
2. Add `receive_frames(timeout_ms: u64) -> Vec<FrameDto>` FFI function
3. Verify `cargo check --workspace` passes

### Track 2: FRB Codegen + Flutter Wiring
1. Install `flutter_rust_bridge_codegen` if not present
2. Run `flutter_rust_bridge_codegen generate` from `android/`
3. Fix any codegen errors
4. Replace `rust_api_bridge.dart` imports to use generated `RustApi`
5. Update screens to call real FFI functions

### Integration (after both tracks)
1. Wire `receive_frames` → `VideoPlayerService.feedFrame()` in `RemoteDesktopScreen`
2. Wire `get_streaming_rtt` → `latencyProvider` with periodic polling
3. Add clipboard sync to remote desktop screen (optional on connect)
4. Start/stop foreground service with streaming lifecycle
5. Fix file browser screen (remove hardcoded data)

### Verification
1. `cargo fmt && cargo clippy -D warnings && cargo test`
2. `flutter analyze` in `android/`
3. `flutter build apk --debug` (debug build to test on device)

---

## 5. Error Handling

### Video Pipeline
- If `receive_frames` is called with no active streaming session, return empty vec (not error)
- If MediaCodec fails to decode a frame, log and continue (don't crash the render loop)
- If QUIC connection drops, `StreamingClient.start()` exits — `is_streaming_active` becomes false
- Flutter should detect `is_streaming_active() == false` and show disconnected UI

### FRB Codegen
- If codegen fails due to type issues, the `#[frb]` annotations may need adjustment
- Types like `Vec<u8>` are supported by FRB v2
- If `quinn::Connection` causes issues (it's not serializable), `get_streaming_rtt` may
  need to be marked as `#[frb(sync)]` since it only reads an atomic value

### Background Service
- If foreground service fails to start, streaming continues but may be killed when backgrounded
- This is a degradation, not a hard failure — log and notify user

---

## 6. Testing

### Rust Tests
- Unit test `receive_frames` returns empty vec when no streaming active
- Unit test `FrameDto` serialization

### Flutter Tests
- Widget test: connection screen shows peers list (mocked)
- Widget test: remote desktop screen renders Texture widget after streaming starts
- Unit test: streaming provider updates latency on poll

### Manual E2E Test
1. Start `linux-link` server on Hyprland machine
2. Launch Android app on device connected to same Tailscale network
3. Discover peer → Connect → Start streaming
4. Verify video renders on Android screen
5. Test mouse/keyboard input from Android → Linux
6. Background the app → verify streaming continues (foreground service)
7. Return to app → video still rendering

---

## 7. Dependencies

No new Rust dependencies needed. All required crates are already in `Cargo.toml`.

Flutter dependencies already in `pubspec.yaml`:
- `flutter_background_service` — already listed, just needs to be used

---

## 8. Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| FRB codegen fails | Medium | High | Types are simple; fallback to manual FFI if needed |
| MediaCodec decode fails on device | Medium | High | Test on target device; check NAL format compatibility |
| Foreground service permission denied | Low | Medium | Request permission at runtime; degrade gracefully |
| Frame polling too slow | Low | Medium | 8ms interval is well within 60fps budget; batch delivery |
