import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../providers/connection_provider.dart' as conn;
import '../providers/streaming_provider.dart';
import '../providers/health_provider.dart';
import '../widgets/stream_stats_overlay.dart';
import '../widgets/shortcuts_overlay.dart';
import '../widgets/remote_desktop_control_bar.dart';
import '../widgets/remote_desktop_keyboard_handler.dart';
import '../widgets/remote_desktop_gesture_handler.dart';
import '../widgets/clipboard_history_overlay.dart';
import '../providers/clipboard_history_provider.dart';
import 'lock_screen.dart';
import '../rust_api_bridge.dart' as bridge;
import 'package:shared_preferences/shared_preferences.dart';
import '../services/background_service.dart';
import '../services/video_player_service.dart';
import '../services/recording_service.dart';
import '../services/audio_service.dart';
import '../services/history_service.dart';

class RemoteDesktopScreen extends ConsumerStatefulWidget {
  final String address;
  final int port;

  const RemoteDesktopScreen({
    super.key,
    required this.address,
    required this.port,
  });

  @override
  ConsumerState<RemoteDesktopScreen> createState() =>
      _RemoteDesktopScreenState();
}

class _RemoteDesktopScreenState extends ConsumerState<RemoteDesktopScreen> {
  bool _isFullscreen = false;
  final bool _showControls = true;
  bool _keyboardMode = false;
  bool _showStats = false;
  bool _isDisconnecting = false;
  final FocusNode _keyboardFocusNode = FocusNode();
  Timer? _streamingCheckTimer;
  Timer? _frameTimer;
  Timer? _audioTimer;
  Timer? _latencyTimer;
  Timer? _statsTimer;

  final TransformationController _transformController =
      TransformationController();
  final DateTime _connectTime = DateTime.now();
  bool _showShortcuts = false;
  bool _isLocked = false;
  bool _lockEnabled = false;

  // F5: Recording state
  Timer? _recordingDurationTimer;
  int _recordingDuration = 0;

  @override
  void initState() {
    super.initState();
    _initVideoDecoder();
    _startStreaming();
    _startStreamingCheck();
    _startFramePolling();
    _startAudioPolling();
    _startLatencyPolling();
    _startStatsPolling();
    _checkLockEnabled();
  }

  Future<void> _toggleRecording() async {
    if (RecordingService.isRecording) {
      final path = await RecordingService.stopRecording();
      _recordingDurationTimer?.cancel();
      _recordingDurationTimer = null;
      if (mounted) {
        ref.read(isRecordingProvider.notifier).state = false;
        ref.read(recordingDurationProvider.notifier).state = 0;
        if (path != null) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Recording saved: $path'),
              duration: const Duration(seconds: 4),
              action: SnackBarAction(
                label: 'Share',
                onPressed: () => RecordingService.shareLastRecording(),
              ),
            ),
          );
        }
      }
    } else {
      final path = await RecordingService.startRecording();
      if (mounted && path != null) {
        ref.read(isRecordingProvider.notifier).state = true;
        _recordingDuration = 0;
        _recordingDurationTimer = Timer.periodic(
          const Duration(seconds: 1),
          (_) {
            if (mounted) {
              _recordingDuration++;
              ref.read(recordingDurationProvider.notifier).state =
                  _recordingDuration;
            }
          },
        );
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Recording started'),
            duration: Duration(seconds: 1),
          ),
        );
      }
    }
  }

  Future<void> _checkLockEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    final enabled = prefs.getBool('screen_lock_enabled') ?? false;
    final pin = prefs.getString('screen_lock_pin');
    if (mounted) {
      setState(() {
        _lockEnabled = enabled && pin != null && pin.isNotEmpty;
        _isLocked = _lockEnabled;
      });
    }
  }

  @override
  void dispose() {
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    _frameTimer?.cancel();
    _frameTimer = null;
    _audioTimer?.cancel();
    _audioTimer = null;
    _latencyTimer?.cancel();
    _latencyTimer = null;
    _statsTimer?.cancel();
    _statsTimer = null;
    _recordingDurationTimer?.cancel();
    _recordingDurationTimer = null;
    _keyboardFocusNode.dispose();
    _transformController.dispose();
    AudioService.stopAudio();
    RecordingService.stopRecording();
    VideoPlayerService.dispose()
        .catchError((e) => debugPrint('Video dispose error: $e'));
    super.dispose();
  }

  Future<void> _initVideoDecoder() async {
    try {
      final codecType = ref.read(videoCodecTypeProvider);
      final monitorIdx = ref.read(monitorIndexProvider);
      debugPrint(
          'Initializing video decoder: codec=$codecType, monitor=$monitorIdx');
      await VideoPlayerService.initialize(
          width: 1920, height: 1080, codecType: codecType);
    } catch (e) {
      debugPrint('Video decoder init error: $e');
    }
  }

  Future<void> _startStreaming() async {
    try {
      // F2: Multi-monitor selection logic
      final monitors =
          await bridge.rustApi.getMonitors(widget.address, widget.port);
      int? selectedIndex;

      if (monitors.length > 1 && mounted) {
        selectedIndex = await showDialog<int>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Select Monitor'),
            content: SizedBox(
              width: double.maxFinite,
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: monitors.length,
                itemBuilder: (context, i) => ListTile(
                  leading:
                      Icon(monitors[i].isPrimary ? Icons.star : Icons.monitor),
                  title: Text(monitors[i].name),
                  subtitle: Text(monitors[i].resolution),
                  onTap: () => Navigator.pop(context, monitors[i].index),
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: const Text('Cancel'),
              ),
            ],
          ),
        );

        if (selectedIndex == null) {
          _disconnect();
          return;
        }
      } else if (monitors.isNotEmpty) {
        selectedIndex = monitors[0].index;
      }

      final int monitorIndex = selectedIndex ?? ref.read(monitorIndexProvider);
      ref.read(monitorIndexProvider.notifier).state = monitorIndex;
      // Reset clipboard history overlay visibility for new session
      ref.read(clipboardHistoryVisibleProvider.notifier).state = false;

      await bridge.rustApi.startStreaming(widget.address, widget.port,
          monitorIndex: monitorIndex);
      if (mounted) {
        ref.read(isStreamingProvider.notifier).state = true;
        ref.read(reconnectStateProvider.notifier).state =
            const ReconnectState.idle();
        // Start clipboard sync FIRST (with ref for history recording)
        // before foreground service, so the ref is set before the
        // background service's duplicate start call (which will be a no-op).
        clipboardSyncService.start(widget.address, widget.port, ref: ref);
        await startForegroundServiceWithPeer(widget.address, widget.port);
        // F1: Start audio playback
        AudioService.startAudio();
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to start streaming: $e')),
        );
      }
    }
  }

  /// Attempt to reconnect using the Rust-managed state machine.
  Future<void> _attemptReconnect(int attempt) async {
    try {
      final monitorIndex = ref.read(monitorIndexProvider);
      await bridge.rustApi.reconnectStreaming(
        widget.address,
        widget.port,
        monitorIndex: monitorIndex,
        attempt: attempt,
      );
    } catch (e) {
      debugPrint('Reconnect attempt $attempt failed: $e');
    }
  }

  void _startStreamingCheck() {
    _streamingCheckTimer = Timer.periodic(
      const Duration(seconds: 1),
      (_) async {
        if (!mounted) return;

        final status = bridge.rustApi.getSessionStatus();

        status.when(
          active: () {
            if (!ref.read(isStreamingProvider)) {
              ref.read(isStreamingProvider.notifier).state = true;
            }
          },
          stale: (rttMs) {
            debugPrint('Session STALE (RTT: ${rttMs}ms)');
            if (mounted) {
               ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Unstable connection (${rttMs}ms)'),
                  duration: const Duration(seconds: 1),
                ),
              );
            }
          },
          reconnecting: (attempt, nextRetryMs) {
            debugPrint('Session RECONNECTING (Attempt $attempt, next in ${nextRetryMs}ms)');
            _frameTimer?.cancel();
            _frameTimer = null;
            _audioTimer?.cancel();
            _audioTimer = null;
          },
          disconnected: () {
            if (!_isDisconnecting && ref.read(isStreamingProvider)) {
               debugPrint('Session disconnected unexpectedly, triggering reconnect');
               _attemptReconnect(1);
            }
          },
          error: (dto) {
            debugPrint('Session FATAL ERROR: ${dto.message}');
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(content: Text('Fatal streaming error: ${dto.message}')),
              );
            }
            _disconnect();
          },
          connecting: () {},
        );
      },
    );
  }

  void _startAudioPolling() {
    _audioTimer = Timer.periodic(const Duration(milliseconds: 20), (_) async {
      if (!mounted) return;
      try {
        final packets = await bridge.rustApi.receiveAudio(10);
        for (final packet in packets) {
          await AudioService.feedPacket(packet);
        }
      } catch (e) {
        debugPrint('Audio polling error: $e');
      }
    });
  }

  void _startFramePolling() {
    _frameTimer = Timer.periodic(const Duration(milliseconds: 8), (_) async {
      if (!mounted) return;
      try {
        final frames = await bridge.rustApi.receiveFrames(5);
        if (frames.isNotEmpty) {
          for (final frame in frames) {
            await VideoPlayerService.feedFrame(frame.data);
            await RecordingService.feedFrame(
              frame.data,
              isKeyframe: frame.isKeyframe,
            );
          }
        }
      } catch (e) {
        debugPrint('Frame polling error: $e');
      }
    });
  }

  void _startLatencyPolling() {
    _latencyTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      final rttUs = bridge.rustApi.getStreamingRtt();
      final rttMs = rttUs ~/ 1000;
      ref.read(latencyProvider.notifier).state = rttMs;
      ref.read(healthProvider.notifier).update(latencyMs: rttMs);
    });
  }

  void _startStatsPolling() {
    _statsTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      if (!mounted) return;
      try {
        final stats = bridge.rustApi.getStreamingStats();
        if (stats != null) {
          ref.read(healthProvider.notifier).update(
                fps: stats.fps,
                bitrateKbps: stats.bitrateKbps,
                frameDrops: stats.frameDrops,
              );
        }
      } catch (e) {
        // Silently continue — stats are non-critical
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Gesture event handlers — forward to Rust bridge
  // ---------------------------------------------------------------------------

  Future<void> _handleTap(double x, double y) async {
    try {
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, x, y, 1, true);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, x, y, 1, false);
    } catch (e) {
      debugPrint('Mouse event error: $e');
    }
  }

  Future<void> _handleDoubleTap(double x, double y) async {
    try {
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 1, true);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 1, false);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 1, true);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 1, false);
    } catch (e) {
      debugPrint('Double tap mouse event error: $e');
    }
  }

  Future<void> _handlePanUpdate(double dx, double dy) async {
    try {
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, dx, dy, 0, false);
    } catch (e) {
      debugPrint('Drag mouse event error: $e');
    }
  }

  Future<void> _handleRightClick(double x, double y) async {
    try {
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, x, y, 0, false);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 3, true);
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, 0, 0, 3, false);
    } catch (e) {
      debugPrint('Right click error: $e');
    }
  }

  Future<void> _handleScroll(double dx, double dy) async {
    try {
      await bridge.rustApi.sendMouseEvent(widget.address, widget.port, dx, dy, 2, false);
    } catch (e) {
      debugPrint('Scroll error: $e');
    }
  }

  // ---------------------------------------------------------------------------
  // Keyboard event handlers
  // ---------------------------------------------------------------------------

  void _toggleKeyboardMode() {
    setState(() {
      _keyboardMode = !_keyboardMode;
      if (_keyboardMode) {
        _keyboardFocusNode.requestFocus();
      } else {
        _keyboardFocusNode.unfocus();
      }
    });
  }

  void _sendText(String text) {
    bridge.rustApi
        .sendKeyboardEvent(widget.address, widget.port, 0, text)
        .catchError((e) => debugPrint('Text input error: $e'));
  }

  void _sendKeyEvent(int keyCode) {
    bridge.rustApi
        .sendKeyboardEvent(widget.address, widget.port, keyCode, '')
        .catchError((e) => debugPrint('Key event error: $e'));
  }

  Future<void> _handleFileDrop(String filePath) async {
    bridge.rustApi
        .sendFile(widget.address, widget.port, filePath)
        .catchError((e) => debugPrint('Drag-drop send failed: $e'));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Transferring: $filePath'),
          duration: const Duration(seconds: 2),
        ),
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Control bar actions
  // ---------------------------------------------------------------------------

  void _resetZoom() {
    _transformController.value = Matrix4.identity();
  }

  void _cycleRotation() {
    final current = ref.read(rotationModeProvider);
    final next = switch (current) {
      RotationMode.auto => RotationMode.portrait,
      RotationMode.portrait => RotationMode.landscape,
      RotationMode.landscape => RotationMode.rotated180,
      RotationMode.rotated180 => RotationMode.auto,
    };
    ref.read(rotationModeProvider.notifier).state = next;
  }

  void _executeShortcut(String shortcut) {
    debugPrint('Executing shortcut: $shortcut');
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Sent: $shortcut'),
        duration: const Duration(seconds: 1),
      ),
    );
  }

  Future<void> _sendPowerCommand(String action) async {
    final actionLabel = switch (action) {
      'sleep' => 'Send to sleep',
      'shutdown' => 'Shut down',
      'restart' => 'Restart',
      'hibernate' => 'Hibernate',
      _ => action,
    };
    final actionIcon = switch (action) {
      'sleep' => Icons.bedtime_outlined,
      'shutdown' => Icons.power_settings_new,
      'restart' => Icons.restart_alt,
      'hibernate' => Icons.nightlight_outlined,
      _ => Icons.power_settings_new,
    };
    final actionDescription = switch (action) {
      'sleep' => 'Suspend the remote PC to RAM',
      'shutdown' => 'Power off the remote PC',
      'restart' => 'Reboot the remote PC',
      'hibernate' => 'Save state to disk and power off',
      _ => 'Perform power action: $action',
    };

    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Row(
          children: [
            Icon(actionIcon, size: 24, color: Colors.redAccent),
            const SizedBox(width: 8),
            Text(actionLabel),
          ],
        ),
        content: Text(actionDescription),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton.icon(
            onPressed: () => Navigator.pop(ctx, true),
            icon: const Icon(Icons.check),
            label: const Text('Confirm'),
            style: FilledButton.styleFrom(
              backgroundColor: Colors.redAccent,
            ),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    try {
      await bridge.rustApi.sendPowerCommand(widget.address, widget.port, action);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('$actionLabel command sent'),
            duration: const Duration(seconds: 3),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to send power command: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _disconnect() async {
    _isDisconnecting = true;
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    _frameTimer?.cancel();
    _frameTimer = null;
    _audioTimer?.cancel();
    _audioTimer = null;
    _latencyTimer?.cancel();
    _latencyTimer = null;
    _statsTimer?.cancel();
    _statsTimer = null;
    AudioService.stopAudio();
    try {
      await bridge.rustApi.stopStreaming();
      await stopForegroundService();
      HistoryService.updateLastConnection(
        duration: DateTime.now().difference(_connectTime),
      );
    } catch (e) {
      debugPrint('Stop streaming error: $e');
    }
    if (mounted) {
      ref.read(conn.connectionStateProvider.notifier).state =
          conn.ConnectionState.disconnected;
      ref.read(isStreamingProvider.notifier).state = false;
      ref.read(healthProvider.notifier).reset();
      context.go('/');
    }
  }

  @override
  Widget build(BuildContext context) {
    final latency = ref.watch(latencyProvider);
    final isStreaming = ref.watch(isStreamingProvider);
    final health = ref.watch(healthProvider);
    final reconnectState = ref.watch(reconnectStateProvider);
    final healthColor = switch (health.health) {
      ConnectionHealth.excellent => Colors.green,
      ConnectionHealth.good => Colors.lightGreen,
      ConnectionHealth.fair => Colors.orange,
      ConnectionHealth.poor => Colors.red,
      ConnectionHealth.disconnected => Colors.grey,
    };

    return Scaffold(
      body: Stack(
        children: [
          // Main video display with keyboard + gesture handling
          RemoteDesktopKeyboardHandler(
            enabled: _keyboardMode,
            focusNode: _keyboardFocusNode,
            onKeyCode: _sendKeyEvent,
            onText: _sendText,
            child: RemoteDesktopGestureHandler(
              transformController: _transformController,
              isStreaming: isStreaming,
              onTap: _handleTap,
              onDoubleTap: _handleDoubleTap,
              onPanUpdate: _handlePanUpdate,
              onRightClick: _handleRightClick,
              onScroll: _handleScroll,
              onFileDrop: _handleFileDrop,
            ),
          ),

          // Connection health indicator
          Positioned(
            top: 16,
            right: 16,
            child: GestureDetector(
              onTap: () => setState(() => _showStats = !_showStats),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.black87,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(
                      color: healthColor.withValues(alpha: 0.5), width: 1),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: healthColor,
                        shape: BoxShape.circle,
                      ),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      '${latency}ms',
                      style: TextStyle(
                        color: healthColor,
                        fontSize: 12,
                        fontWeight: FontWeight.bold,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),

          // Stream stats overlay
          StreamStatsOverlay(
            visible: _showStats,
            onToggle: () => setState(() => _showStats = !_showStats),
            fps: health.fps,
            latencyMs: latency,
            bitrateKbps: health.bitrateKbps,
            frameDrops: health.frameDrops,
          ),

          // Zoom indicator
          if (_transformController.value.getMaxScaleOnAxis() > 1.01)
            Positioned(
              top: 48,
              left: 16,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.black54,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.zoom_in, size: 14, color: Colors.white70),
                    const SizedBox(width: 4),
                    Text(
                      '${(_transformController.value.getMaxScaleOnAxis() * 100).round()}%',
                      style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 11,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ),
            ),

          // Bottom control bar
          if (_showControls)
            Positioned(
              bottom: 24,
              left: 24,
              right: 24,
              child: RemoteDesktopControlBar(
                isFullscreen: _isFullscreen,
                showStats: _showStats,
                keyboardMode: _keyboardMode,
                recordingDuration: _recordingDuration,
                showShortcuts: _showShortcuts,
                onDisconnect: _disconnect,
                onToggleFullscreen: () => setState(() => _isFullscreen = !_isFullscreen),
                onToggleStats: () => setState(() => _showStats = !_showStats),
                onResetZoom: _resetZoom,
                onOpenTerminal: () => context.push(
                  '/terminal',
                  extra: {'address': widget.address, 'port': widget.port},
                ),
                onOpenFileBrowser: () => context.push(
                  '/files',
                  extra: {'address': widget.address, 'port': widget.port},
                ),
                onSendPowerCommand: _sendPowerCommand,
                onToggleRecording: _toggleRecording,
                onToggleKeyboardMode: _toggleKeyboardMode,
                onCycleRotation: _cycleRotation,
                onToggleShortcuts: () => setState(() => _showShortcuts = !_showShortcuts),
                onToggleClipboardHistory: () {
                  final visible = ref.read(clipboardHistoryVisibleProvider);
                  ref.read(clipboardHistoryVisibleProvider.notifier).state =
                      !visible;
                },
              ),
            ),

          // Reconnecting overlay
          if (reconnectState.isReconnecting)
            Positioned.fill(
              child: Container(
                color: Colors.black54,
                child: Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const SizedBox(
                        width: 48,
                        height: 48,
                        child: CircularProgressIndicator(strokeWidth: 3),
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Reconnecting… (${reconnectState.attempt}/5)',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Backoff: ${reconnectState.backoffSeconds}s',
                        style: const TextStyle(
                          color: Colors.white54,
                          fontSize: 13,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),

          // Shortcuts overlay
          if (_showShortcuts)
            Positioned.fill(
              child: ShortcutsOverlay(
                onDismiss: () => setState(() => _showShortcuts = false),
                onExecute: _executeShortcut,
              ),
            ),

          // Clipboard history overlay
          if (ref.watch(clipboardHistoryVisibleProvider))
            const Positioned.fill(
              child: ClipboardHistoryOverlay(),
            ),

          // Screen lock overlay
          if (_isLocked && _lockEnabled)
            Positioned.fill(
              child: LockScreen(
                onUnlock: () => setState(() => _isLocked = false),
                onDisconnect: _disconnect,
              ),
            ),

          // Keyboard mode indicator
          if (_keyboardMode)
            Positioned(
              top: 48,
              left: 16,
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: Theme.of(context)
                      .colorScheme
                      .primary
                      .withValues(alpha: 0.85),
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.keyboard,
                      size: 14,
                      color: Theme.of(context).colorScheme.onPrimary,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      'Keyboard',
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.onPrimary,
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ],
                ),
              ),
            ),
        ],
      ),
    );
  }
}
