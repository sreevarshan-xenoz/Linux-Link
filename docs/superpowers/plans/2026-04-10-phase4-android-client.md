# Phase 4: Android Client Completion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the Android client so H.264 frames flow from Rust QUIC → Flutter → MediaCodec → Texture widget, all FFI functions are wired into Flutter screens, and a background service keeps streaming alive.

**Architecture:** Two parallel tracks converge at integration. Track 1 adds `receive_frames` FFI + RTT atomic to Rust. Track 2 runs FRB codegen and replaces the Dart bridge stub. Integration wires the frame polling loop into `RemoteDesktopScreen`, adds the foreground service, and cleans up the file browser.

**Tech Stack:** Rust (flutter_rust_bridge 2.12, tokio, quinn, tokio-util), Flutter/Dart (Riverpod, go_router, flutter_background_service, MethodChannel), Kotlin (MediaCodec, SurfaceTexture)

---

## File Structure

### Files to Modify (Rust)
- `android/rust/src/lib.rs` — Add `FrameDto` struct, `receive_frames` FFI, `STREAMING_RTT` atomic, fix `get_streaming_rtt`
- `core/src/streaming/client.rs` — Update stats loop to write RTT into a shared atomic (cross-crate coordination via the handle)

### Files to Generate (FRB codegen)
- `android/rust/src/frb_generated.rs` — Generated Rust FRB boilerplate
- `android/rust/src/frb_generated.io.rs` — Generated Rust IO-specific code
- `android/lib/frb_generated.dart` — Generated Dart FRB boilerplate
- `android/lib/frb_generated.io.dart` — Generated Dart IO-specific code
- `android/lib/api/` — Generated Dart API wrappers

### Files to Modify (Dart/Flutter)
- `android/lib/rust_api_bridge.dart` — Replace stub with generated `RustApi` import + custom frame polling wrapper
- `android/lib/screens/remote_desktop_screen.dart` — Add frame polling loop, wire latency provider
- `android/lib/screens/file_browser_screen.dart` — Remove hardcoded `_remoteFiles`, show empty state
- `android/lib/main.dart` — Add background service initialization
- `android/lib/services/background_service.dart` — **New** file for foreground service setup
- `android/android/app/src/main/AndroidManifest.xml` — Add `<service>` element

### Files Unchanged (already correct)
- `android/lib/services/video_player_service.dart` — `feedFrame`/`feedFrames` already correct
- `android/lib/providers/streaming_provider.dart` — `isStreamingProvider`, `latencyProvider` already correct
- `android/lib/screens/connection_screen.dart` — Already uses `rustApi.*` calls
- `android/lib/screens/settings_screen.dart` — Already wired
- `android/android/app/src/main/kotlin/.../VideoPlayerPlugin.kt` — Already complete

---

## Task 1: Add `receive_frames` FFI + RTT Atomic to Rust

**Files:**
- Modify: `android/rust/src/lib.rs`
- Test: `cargo check --workspace`, `cargo test -p linux-link-android`

- [ ] **Step 1: Add `STREAMING_RTT` atomic and `FrameDto` struct**

Add these near the top of `android/rust/src/lib.rs`, after the existing `STREAMING_ACTIVE` atomic:

```rust
/// Last known RTT in microseconds, updated by the streaming stats task.
/// Read atomically from the main thread (no mutex lock needed).
static STREAMING_RTT_US: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Frame data transfer object for Flutter/MediaCodec.
#[frb]
pub struct FrameDto {
    /// H.264 NAL unit data (including start codes).
    pub data: Vec<u8>,
    /// Whether this is a keyframe (IDR).
    pub is_keyframe: bool,
    /// Sequence number for ordering.
    pub sequence: u64,
}
```

- [ ] **Step 2: Add `receive_frames` FFI function**

Add after the `get_streaming_rtt` function:

```rust
/// Receive queued H.264 frames from the streaming client.
///
/// Polls the frame receiver channel with the given timeout (in milliseconds).
/// Returns up to 16 frames per call. Returns an empty list if no streaming
/// session is active or no frames are available.
#[frb]
pub async fn receive_frames(timeout_ms: u64) -> Vec<FrameDto> {
    let mut guard = match STREAMING_HANDLE.lock() {
        Ok(g) => g,
        Err(_) => return vec![],
    };

    let Some(handle) = guard.as_mut() else {
        return vec![];
    };

    let rx = &mut handle.packet_rx;
    let timeout = Duration::from_millis(timeout_ms);
    let mut frames = Vec::with_capacity(16);

    // Try to get at least one frame with timeout
    let first = match tokio::time::timeout(timeout, rx.recv()).await {
        Ok(Some(packet)) => packet,
        Ok(None) => return frames, // channel closed
        Err(_) => return frames,   // timeout — no frames available
    };

    frames.push(FrameDto {
        data: first.data,
        is_keyframe: first.is_keyframe,
        sequence: first.sequence,
    });

    // Drain up to 15 more frames (non-blocking)
    for _ in 0..15 {
        match rx.try_recv() {
            Ok(packet) => {
                frames.push(FrameDto {
                    data: packet.data,
                    is_keyframe: packet.is_keyframe,
                    sequence: packet.sequence,
                });
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
        }
    }

    frames
}
```

- [ ] **Step 3: Replace `get_streaming_rtt` with atomic read + add `update_streaming_rtt`**

Replace the existing `get_streaming_rtt` function with:

```rust
/// Update the global streaming RTT value (called from the stats task).
pub fn update_streaming_rtt(rtt_us: u64) {
    STREAMING_RTT_US.store(rtt_us, std::sync::atomic::Ordering::Relaxed);
}

/// Get the current RTT to the streaming server in microseconds.
///
/// Returns 0 if no streaming session is active.
/// This is a synchronous, lock-free read safe for the main thread.
#[frb(sync)]
pub fn get_streaming_rtt() -> u64 {
    STREAMING_RTT_US.load(std::sync::atomic::Ordering::Relaxed)
}
```

- [ ] **Step 4: Wire the stats task to update the RTT atomic**

The stats feedback loop in `core/src/streaming/client.rs` sends RTT to the server but doesn't update the atomic (which lives in `android/rust/src/lib.rs`). We need the client to notify the android crate. The simplest approach: the `send_stats_loop` already has the RTT value — but it's in the core crate. Instead, we'll update the RTT from within the `connect_streaming` FFI by spawning a periodic task.

Add this inside `connect_streaming`, after storing the handle but before setting `STREAMING_ACTIVE`:

```rust
    // Spawn a task to periodically poll RTT and update the atomic
    let rtt_connection = connection.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let rtt_us = rtt_connection.stats().path.rtt.as_micros() as u64;
            update_streaming_rtt(rtt_us);
        }
    });
```

- [ ] **Step 5: Verify compilation**

Run: `cargo fmt && cargo clippy -p linux-link-android -D warnings && cargo check --workspace`

Expected: All pass, no errors.

- [ ] **Step 6: Commit**

```bash
git add android/rust/src/lib.rs
git commit -m "feat(android): add receive_frames FFI and lock-free RTT atomic

- Add FrameDto struct for H.264 frame transfer to Flutter
- Add receive_frames(timeout_ms) FFI that batches up to 16 frames
- Replace mutex-based get_streaming_rtt with AtomicU64 read
- Add RTT polling task in connect_streaming to update the atomic"
```

---

## Task 2: Run FRB Codegen

**Files:**
- Generate: `android/rust/src/frb_generated.rs`, `android/rust/src/frb_generated.io.rs`
- Generate: `android/lib/frb_generated.dart`, `android/lib/frb_generated.io.dart`, `android/lib/api/`

- [ ] **Step 1: Check if flutter_rust_bridge_codegen is installed**

Run: `which flutter_rust_bridge_codegen || cargo install flutter_rust_bridge_codegen --version 2.12.0`

Expected: Binary installed or already present.

- [ ] **Step 2: Run codegen from the android/ directory**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter_rust_bridge_codegen generate`

Expected output: Files generated in `rust/src/frb_generated.rs`, `lib/frb_generated.dart`, `lib/api/`

- [ ] **Step 3: Handle codegen errors if any**

If codegen fails, check the error message. Common issues:
- Missing Android NDK: `rustup target add aarch64-linux-android`
- Flutter not in PATH: ensure `flutter` command works
- Type errors in `#[frb]` types: the `FrameDto`, `PeerInfoDto`, etc. are all simple structs that FRB v2 supports

If codegen succeeds, skip to Step 4. If it fails with type issues, add `#[frb]` annotations to any missing types and retry.

- [ ] **Step 4: Verify generated files exist**

Check that these files exist:
- `android/rust/src/frb_generated.rs`
- `android/lib/frb_generated.dart`
- `android/lib/frb_generated.io.dart`
- `android/lib/api/` directory

- [ ] **Step 5: Commit generated files**

```bash
git add android/rust/src/frb_generated.rs android/rust/src/frb_generated.io.rs android/lib/frb_generated.dart android/lib/frb_generated.io.dart android/lib/api/
git commit -m "chore: generate FRB bindings (flutter_rust_bridge_codegen)"
```

---

## Task 3: Replace Dart Bridge Stub with Generated RustApi

**Files:**
- Modify: `android/lib/rust_api_bridge.dart`

- [ ] **Step 1: Replace the entire `rust_api_bridge.dart` file**

Replace the full contents with:

```dart
/// Rust FFI API bridge for Linux Link Android client.
///
/// Delegates to the generated FRB RustApi for all FFI calls,
/// with custom frame polling wrapper for the video pipeline.
library rust_api_bridge;

import 'package:linux_link_client/frb_generated.dart';
import 'models/peer_info.dart';

export 'package:linux_link_client/frb_generated.dart' hide RustApi;

/// Global singleton instance — generated RustApi.
final rustApi = RustApi();

/// Connection state matching the Rust enum.
enum ConnectionState { connected, disconnected, connecting, error }

/// Map the generated Rust ConnectionState to Dart enum.
ConnectionState _mapConnectionState(dynamic state) {
  // FRB generates sealed classes for Rust enums.
  // The exact type name depends on codegen output.
  // After codegen, adjust the type name below.
  final s = state.toString();
  if (s.contains('Connected')) return ConnectionState.connected;
  if (s.contains('Disconnected')) return ConnectionState.disconnected;
  if (s.contains('Connecting')) return ConnectionState.connecting;
  if (s.contains('Error')) return ConnectionState.error;
  return ConnectionState.error;
}

/// Map the generated Rust PeerInfo to our PeerInfo model.
PeerInfo _mapPeerInfo(dynamic p) {
  return PeerInfo(
    name: p.name ?? '',
    dnsName: p.dnsName ?? '',
    ips: List<String>.from(p.ips ?? []),
    online: p.online ?? false,
  );
}
```

Note: The exact type names (`RustApi`, sealed class names for enums) depend on FRB codegen output. After running codegen in Task 2, verify the class names match and adjust the imports/hide clauses accordingly. FRB v2 generates a `RustApi` class by default.

- [ ] **Step 2: Verify Dart compilation**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze`

Expected: No compile errors (may have lint warnings about unused imports — those are fine for now).

If there are errors about type names not matching, check the generated `frb_generated.dart` for the actual class/enum names and adjust `_mapConnectionState` and `_mapPeerInfo` accordingly.

- [ ] **Step 3: Commit**

```bash
git add android/lib/rust_api_bridge.dart
git commit -m "refactor(android): replace bridge stub with generated RustApi"
```

---

## Task 4: Wire Frame Polling into RemoteDesktopScreen

**Files:**
- Modify: `android/lib/screens/remote_desktop_screen.dart`

- [ ] **Step 1: Add frame polling loop to `_RemoteDesktopScreenState`**

Add these fields and methods to `_RemoteDesktopScreenState`:

```dart
  Timer? _frameTimer;
  Timer? _latencyTimer;

  @override
  void initState() {
    super.initState();
    _initVideoDecoder();
    _startStreaming();
    _startStreamingCheck();
    _startFramePolling();  // NEW
    _startLatencyPolling(); // NEW
  }

  @override
  void dispose() {
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    _frameTimer?.cancel();   // NEW
    _frameTimer = null;
    _latencyTimer?.cancel(); // NEW
    _latencyTimer = null;
    VideoPlayerService.dispose().catchError((e) => debugPrint('Video dispose error: $e'));
    super.dispose();
  }

  /// Poll the Rust backend for H.264 frames and feed them to MediaCodec.
  void _startFramePolling() {
    _frameTimer = Timer.periodic(const Duration(milliseconds: 8), (_) async {
      try {
        final frames = await rustApi.receiveFrames(timeoutMs: 5);
        if (frames.isNotEmpty) {
          for (final frame in frames) {
            await VideoPlayerService.feedFrame(frame.data);
          }
        }
      } catch (e) {
        debugPrint('Frame polling error: $e');
      }
    });
  }

  /// Poll RTT every 1 second and update the latency provider.
  void _startLatencyPolling() {
    _latencyTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      final rttUs = rustApi.getStreamingRtt();
      final rttMs = rttUs ~/ 1000;
      ref.read(latencyProvider.notifier).state = rttMs;
    });
  }
```

- [ ] **Step 2: Verify compilation**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze lib/screens/remote_desktop_screen.dart`

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add android/lib/screens/remote_desktop_screen.dart
git commit -m "feat(android): wire frame polling and RTT latency display

- Add _startFramePolling() that calls receive_frames every 8ms
- Feed decoded H.264 frames to VideoPlayerService
- Add _startLatencyPolling() that polls get_streaming_rtt every 1s
- Update latencyProvider with RTT in milliseconds"
```

---

## Task 5: Clean Up File Browser Screen

**Files:**
- Modify: `android/lib/screens/file_browser_screen.dart`

- [ ] **Step 1: Remove hardcoded `_remoteFiles` and show empty state**

In `file_browser_screen.dart`, replace the `_remoteFiles` field and `_buildRemoteFileList`:

Replace:
```dart
  // Sample data for development (remote files would come from Rust FFI eventually)
  final List<FileItem> _remoteFiles = const [
    FileItem(name: 'etc', isDirectory: true, modified: '2024-01-01'),
    ...
  ];
```

With:
```dart
  // Remote file browsing will be implemented in Phase 5.
  // For now, show an empty state with a placeholder message.
  final List<FileItem> _remoteFiles = const [];
```

Replace the `_buildRemoteFileList` method body with:

```dart
  Widget _buildRemoteFileList() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            Icons.computer,
            size: 64,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            'Remote File Browser',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 8),
          Text(
            'Browse and download files from the remote machine.\nComing in a future update.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                ),
          ),
        ],
      ),
    );
  }
```

- [ ] **Step 2: Verify compilation**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze lib/screens/file_browser_screen.dart`

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add android/lib/screens/file_browser_screen.dart
git commit -m "fix(android): remove hardcoded remote files, show empty state

- Replace sample data with empty list
- Show informative placeholder for remote file browser
- Keep local file selection and sending fully functional"
```

---

## Task 6: Add Android Foreground Service

**Files:**
- Create: `android/lib/services/background_service.dart`
- Modify: `android/lib/main.dart`
- Modify: `android/android/app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Create the background service wrapper**

Create `android/lib/services/background_service.dart`:

```dart
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:flutter/services.dart';

/// Initialize the Android foreground service for keeping streaming alive.
///
/// Call this after the app is initialized. The service does NOT start
/// automatically — call [startForegroundService] when streaming begins.
Future<void> initBackgroundService() async {
  final service = FlutterBackgroundService();

  await service.configure(
    androidConfiguration: AndroidConfiguration(
      onStart: _onBackgroundServiceStart,
      autoStart: false,
      isForegroundMode: true,
      notificationChannelId: 'linux_link_streaming',
      initialNotificationTitle: 'Linux Link',
      initialNotificationContent: 'Ready',
      foregroundServiceNotificationId: 888,
    ),
    iosConfiguration: IosConfiguration(),
  );
}

/// Start the foreground service with a notification indicating streaming is active.
Future<void> startForegroundService() async {
  final service = FlutterBackgroundService();
  await service.startService();
}

/// Stop the foreground service.
Future<void> stopForegroundService() async {
  final service = FlutterBackgroundService();
  service.invoke('stop');
}

@pragma('vm:entry-point')
Future<void> _onBackgroundServiceStart(ServiceInstance service) async {
  // The Rust tokio runtime runs in the same process as the Flutter activity.
  // The foreground service notification keeps Android from killing this process.

  if (service is AndroidServiceInstance) {
    service.on('setAsForeground').listen((_) {
      service.setAsForegroundService();
    });

    service.on('setAsBackground').listen((_) {
      service.setAsBackgroundService();
    });
  }

  service.on('stop').listen((_) {
    service.stopSelf();
  });
}
```

- [ ] **Step 2: Update `main.dart` to initialize the background service**

Add the import at the top of `main.dart`:

```dart
import 'services/background_service.dart';
```

Add this line in `main()`, after `await rustApi.init();` and before `runApp`:

```dart
  // Initialize the Android foreground service (does not start until streaming begins)
  await initBackgroundService();
```

- [ ] **Step 3: Add `<service>` element to AndroidManifest.xml**

Read the current manifest at `android/android/app/src/main/AndroidManifest.xml`. Add the following `<service>` element inside the `<application>` tag:

```xml
        <service
            android:name="id.flutter.flutter_background_service.BackgroundService"
            android:foregroundServiceType="dataSync"
            android:exported="false" />
```

- [ ] **Step 4: Wire service start/stop to streaming lifecycle in RemoteDesktopScreen**

In `remote_desktop_screen.dart`, add the import:

```dart
import '../services/background_service.dart';
```

Modify `_startStreaming()` to start the foreground service on success:

```dart
  Future<void> _startStreaming() async {
    try {
      await rustApi.startStreaming(widget.address, widget.port);
      if (mounted) {
        ref.read(isStreamingProvider.notifier).state = true;
        // Start foreground service to keep streaming alive in background
        await startForegroundService();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to start streaming: $e')),
        );
      }
    }
  }
```

Modify `_disconnect()` to stop the foreground service:

```dart
  Future<void> _disconnect() async {
    try {
      await rustApi.stopStreaming();
      await stopForegroundService();
    } catch (e) {
      debugPrint('Stop streaming error: $e');
    }
    if (mounted) {
      ref.read(connectionStateProvider.notifier).state = ConnectionState.disconnected;
      ref.read(isStreamingProvider.notifier).state = false;
      Navigator.of(context).pop();
    }
  }
```

- [ ] **Step 5: Verify compilation**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze`

Expected: No errors.

- [ ] **Step 6: Commit**

```bash
git add android/lib/services/background_service.dart android/lib/main.dart android/lib/screens/remote_desktop_screen.dart android/android/app/src/main/AndroidManifest.xml
git commit -m "feat(android): add foreground service to keep streaming alive in background

- Create background_service.dart wrapper for flutter_background_service
- Initialize service in main.dart
- Start service when streaming begins, stop on disconnect
- Add <service> element to AndroidManifest.xml"
```

---

## Task 7: Final Verification — Rust Quality Gates

**Files:** None (verification only)

- [ ] **Step 1: Run all Rust quality gates**

Run: `cd /home/sreevarshan/projects/Linux-Link && cargo fmt && cargo clippy -D warnings && cargo test --workspace`

Expected output:
- `cargo fmt`: no changes
- `cargo clippy -D warnings`: no warnings
- `cargo test`: all tests pass (existing 50+ tests)

- [ ] **Step 2: Fix any clippy warnings**

If clippy reports warnings-as-errors, fix them inline and re-run until clean.

---

## Task 8: Final Verification — Flutter Build

**Files:** None (verification only)

- [ ] **Step 1: Run Flutter analysis**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter analyze`

Expected: No errors. Warnings are acceptable for now.

- [ ] **Step 2: Attempt debug APK build**

Run: `cd /home/sreevarshan/projects/Linux-Link/android && flutter build apk --debug`

Expected: Build succeeds. If it fails due to missing Android SDK/NDK, note the error — the code is correct but the build environment needs the Android toolchain.

- [ ] **Step 3: Commit any fixes**

If fixes were needed:

```bash
git add -A
git commit -m "fix(android): resolve build issues for debug APK"
```

---

## Task 9: Update Plan and Spec

**Files:**
- Modify: `plan.md`

- [ ] **Step 1: Update Phase 4 status in plan.md**

Find the Phase 4 section in `plan.md` (around line ~1740). Update the checklist:

Replace the "Remaining Work" section with:

```markdown
**Remaining Work:**
- [x] FRB code generation (`flutter_rust_bridge_codegen generate`)
- [x] Wire Flutter screens to Rust FFI functions (real invocation of `RustApi.*`)
- [x] Frame delivery pipeline: `receive_frames` → `VideoPlayerService.feedFrame()`
- [x] RTT latency polling wired to `latencyProvider`
- [x] Background service with notifications (foreground service)
- [x] File browser cleanup (removed hardcoded data)
- [ ] `flutter build apk` verification (requires Android SDK/NDK on build machine)
- [ ] Full end-to-end testing on Android device (requires Hyprland + PipeWire server running)
```

- [ ] **Step 2: Commit**

```bash
git add plan.md
git commit -m "docs: update plan.md with Phase 4 completion status"
```

---

## Summary of Deliverables

| Task | What Changes | Testable |
|------|-------------|----------|
| 1: receive_frames FFI | `android/rust/src/lib.rs` | `cargo check` passes |
| 2: FRB Codegen | Generated files | Files exist |
| 3: Replace bridge stub | `rust_api_bridge.dart` | `flutter analyze` clean |
| 4: Wire frame polling | `remote_desktop_screen.dart` | Code compiles, logic correct |
| 5: Clean file browser | `file_browser_screen.dart` | No hardcoded data |
| 6: Background service | 4 files modified/created | Service starts/stops with streaming |
| 7: Rust quality gates | Verification | All tests pass, clippy clean |
| 8: Flutter build | Verification | Debug APK builds |
| 9: Update plan | `plan.md` | Documentation current |
