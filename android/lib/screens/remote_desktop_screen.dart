import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/connection_provider.dart' as conn;
import '../providers/streaming_provider.dart';
import '../providers/health_provider.dart';
import '../widgets/stream_stats_overlay.dart';
import '../rust_api_bridge.dart' as bridge;
import '../services/background_service.dart';
import '../services/video_player_service.dart';
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
  Timer? _latencyTimer;
  Timer? _statsTimer;

  final TransformationController _transformController =
      TransformationController();
  final DateTime _connectTime = DateTime.now();

  @override
  void initState() {
    super.initState();
    _initVideoDecoder();
    _startStreaming();
    _startStreamingCheck();
    _startFramePolling();
    _startLatencyPolling();
    _startStatsPolling();
  }

  @override
  void dispose() {
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    _frameTimer?.cancel();
    _frameTimer = null;
    _latencyTimer?.cancel();
    _latencyTimer = null;
    _statsTimer?.cancel();
    _statsTimer = null;
    _keyboardFocusNode.dispose();
    _transformController.dispose();
    VideoPlayerService.dispose()
        .catchError((e) => debugPrint('Video dispose error: $e'));
    super.dispose();
  }

  Future<void> _initVideoDecoder() async {
    try {
      await VideoPlayerService.initialize(width: 1920, height: 1080);
    } catch (e) {
      debugPrint('Video decoder init error: $e');
    }
  }

  Future<void> _startStreaming() async {
    try {
      await bridge.rustApi.startStreaming(widget.address, widget.port);
      if (mounted) {
        ref.read(isStreamingProvider.notifier).state = true;
        ref.read(reconnectStateProvider.notifier).state =
            const ReconnectState.idle();
        await startForegroundServiceWithPeer(widget.address, widget.port);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to start streaming: $e')),
        );
      }
    }
  }

  /// Attempt to reconnect with exponential backoff.
  Future<void> _attemptReconnect(int attempt) async {
    ref.read(reconnectStateProvider.notifier).state =
        ReconnectState.reconnecting(attempt: attempt);
    final backoff = ReconnectState.reconnecting(attempt: attempt)
        .backoffSeconds;

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Reconnecting (attempt $attempt/5) in ${backoff}s…'),
          duration: const Duration(seconds: 2),
        ),
      );
    }

    await Future.delayed(Duration(seconds: backoff));
    if (!mounted) return;

    try {
      await bridge.rustApi.startStreaming(widget.address, widget.port);
      if (mounted) {
        ref.read(isStreamingProvider.notifier).state = true;
        ref.read(reconnectStateProvider.notifier).state =
            const ReconnectState.idle();
        // Restart polling timers
        _startFramePolling();
        _startLatencyPolling();
        _startStatsPolling();
      }
    } catch (e) {
      if (!mounted) return;
      final nextAttempt = attempt + 1;
      if (nextAttempt <= 5) {
        await _attemptReconnect(nextAttempt);
      } else {
        ref.read(reconnectStateProvider.notifier).state =
            const ReconnectState.failed();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Failed to reconnect after 5 attempts'),
              duration: Duration(seconds: 4),
            ),
          );
        }
      }
    }
  }

  void _startStreamingCheck() {
    _streamingCheckTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) async {
        if (!mounted) return;
        final isActive = bridge.rustApi.isStreamingActive();
        if (mounted) {
          // Skip reconnect checks if user is intentionally disconnecting
          if (_isDisconnecting) return;
          final wasActive = ref.read(isStreamingProvider);
          ref.read(isStreamingProvider.notifier).state = isActive;
          // Trigger auto-reconnect if streaming dropped unexpectedly
          if (wasActive && !isActive) {
            final reconnectState = ref.read(reconnectStateProvider);
            if (!reconnectState.isReconnecting) {
              // Cancel polling timers before attempting reconnect
              _frameTimer?.cancel();
              _frameTimer = null;
              _latencyTimer?.cancel();
              _latencyTimer = null;
              _statsTimer?.cancel();
              _statsTimer = null;
              _attemptReconnect(1);
            }
          }
        }
      },
    );
  }

  /// Poll the Rust backend for H.264 frames and feed them to MediaCodec.
  void _startFramePolling() {
    _frameTimer = Timer.periodic(const Duration(milliseconds: 8), (_) async {
      if (!mounted) return;
      try {
        final frames = await bridge.rustApi.receiveFrames(5);
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

  /// Poll RTT every 1 second and update the latency and health providers.
  void _startLatencyPolling() {
    _latencyTimer = Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      final rttUs = bridge.rustApi.getStreamingRtt();
      final rttMs = rttUs ~/ 1000;
      ref.read(latencyProvider.notifier).state = rttMs;
      ref.read(healthProvider.notifier).update(latencyMs: rttMs);
    });
  }

  /// Poll streaming stats every 2 seconds for the stats overlay.
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

  /// Transform a screen-space position to content-space accounting for zoom/pan.
  Offset _inverseTransform(Offset screenPos) {
    final matrix = _transformController.value;
    final scale = matrix.getMaxScaleOnAxis();
    final translation = matrix.getTranslation();
    // Apply inverse transform
    final cx = (screenPos.dx - translation.x) / scale;
    final cy = (screenPos.dy - translation.y) / scale;
    return Offset(
      cx.clamp(0, double.infinity),
      cy.clamp(0, double.infinity),
    );
  }

  Future<void> _handleTap(TapUpDetails details) async {
    // Transform coordinates for zoom
    final transformed = _inverseTransform(details.localPosition);
    final x = transformed.dx;
    final y = transformed.dy;
    try {
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        x,
        y,
        1, // left button
        true,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        x,
        y,
        1,
        false,
      );
    } catch (e) {
      debugPrint('Mouse event error: $e');
    }
  }

  Future<void> _handleDragUpdate(DragUpdateDetails details) async {
    // Scale delta by inverse zoom so dragging feels consistent at any zoom level
    final scale = _transformController.value.getMaxScaleOnAxis();
    final scaledDx = details.delta.dx / scale;
    final scaledDy = details.delta.dy / scale;
    try {
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        scaledDx,
        scaledDy,
        0, // no button (movement)
        false,
      );
    } catch (e) {
      debugPrint('Drag mouse event error: $e');
    }
  }

  Future<void> _handleDoubleTap() async {
    try {
      // Double click: two rapid click cycles
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        true,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        false,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        true,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        false,
      );
    } catch (e) {
      debugPrint('Double tap mouse event error: $e');
    }
  }

  /// Long press → right-click (button=3)
  Future<void> _handleRightClick(LongPressStartDetails details) async {
    final transformed = _inverseTransform(details.localPosition);
    try {
      final x = transformed.dx;
      final y = transformed.dy;
      // Move to position then right-click press + release
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        x,
        y,
        0, // no button (just move)
        false,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        3, // right button
        true,
      );
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        3,
        false,
      );
    } catch (e) {
      debugPrint('Right click error: $e');
    }
  }

  /// Scroll via two-finger drag
  Future<void> _handleScroll(PointerScrollEvent event) async {
    try {
      await bridge.rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        event.scrollDelta.dx,
        event.scrollDelta.dy,
        2, // scroll event (interpreted as MouseScroll on Rust side)
        false,
      );
    } catch (e) {
      debugPrint('Scroll error: $e');
    }
  }

  /// Toggle keyboard capture mode
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

  /// Reset zoom to 1x
  void _resetZoom() {
    _transformController.value = Matrix4.identity();
  }

  /// Handle raw keyboard events in keyboard mode
  KeyEventResult _onKeyEvent(FocusNode node, KeyEvent event) {
    if (!_keyboardMode) {
      return KeyEventResult.ignored;
    }

    if (event is KeyRepeatEvent) {
      return KeyEventResult.handled;
    }

    if (event is! KeyDownEvent && event is! KeyUpEvent) {
      return KeyEventResult.handled;
    }

    final isPressed = event is KeyDownEvent;
    final key = event.logicalKey;

    // Modifier keys: send press/release individually
    if (_isModifierKey(key)) {
      final keyCode = _logicalKeyToAndroidKeyCode(key);
      if (keyCode != 0) {
        final encodedCode = isPressed ? keyCode : keyCode + 100000;
        _sendKeyEvent(encodedCode);
        return KeyEventResult.handled;
      }
    }

    if (!isPressed) {
      return KeyEventResult.ignored;
    }

    // Printable characters: send as text
    final char = _logicalKeyToChar(key);
    if (char != null) {
      _sendText(char);
      return KeyEventResult.handled;
    }

    // Special/control keys
    final keyCode = _logicalKeyToAndroidKeyCode(key);
    if (keyCode != 0) {
      _sendKeyEvent(keyCode);
      return KeyEventResult.handled;
    }

    return KeyEventResult.ignored;
  }

  bool _isModifierKey(LogicalKeyboardKey key) {
    return key == LogicalKeyboardKey.shiftLeft ||
        key == LogicalKeyboardKey.shiftRight ||
        key == LogicalKeyboardKey.controlLeft ||
        key == LogicalKeyboardKey.controlRight ||
        key == LogicalKeyboardKey.altLeft ||
        key == LogicalKeyboardKey.altRight ||
        key == LogicalKeyboardKey.metaLeft ||
        key == LogicalKeyboardKey.metaRight;
  }

  void _sendText(String text) {
    bridge.rustApi
        .sendKeyboardEvent(
          widget.address,
          widget.port,
          0,
          text,
        )
        .catchError((e) => debugPrint('Text input error: $e'));
  }

  void _sendKeyEvent(int keyCode) {
    bridge.rustApi
        .sendKeyboardEvent(
          widget.address,
          widget.port,
          keyCode,
          '',
        )
        .catchError((e) => debugPrint('Key event error: $e'));
  }

  String? _logicalKeyToChar(LogicalKeyboardKey key) {
    if (key.keyLabel.isNotEmpty && key.keyLabel.length == 1) {
      return key.keyLabel;
    }
    return null;
  }

  int _logicalKeyToAndroidKeyCode(LogicalKeyboardKey key) {
    if (key == LogicalKeyboardKey.enter) return 66;
    if (key == LogicalKeyboardKey.backspace) return 67;
    if (key == LogicalKeyboardKey.arrowUp) return 19;
    if (key == LogicalKeyboardKey.arrowDown) return 20;
    if (key == LogicalKeyboardKey.arrowLeft) return 21;
    if (key == LogicalKeyboardKey.arrowRight) return 22;
    if (key == LogicalKeyboardKey.space) return 62;
    if (key == LogicalKeyboardKey.escape) return 111;
    if (key == LogicalKeyboardKey.tab) return 61;
    if (key == LogicalKeyboardKey.delete) return 112;

    if (key == LogicalKeyboardKey.f1) return 131;
    if (key == LogicalKeyboardKey.f2) return 132;
    if (key == LogicalKeyboardKey.f3) return 133;
    if (key == LogicalKeyboardKey.f4) return 134;
    if (key == LogicalKeyboardKey.f5) return 135;
    if (key == LogicalKeyboardKey.f6) return 136;
    if (key == LogicalKeyboardKey.f7) return 137;
    if (key == LogicalKeyboardKey.f8) return 138;
    if (key == LogicalKeyboardKey.f9) return 139;
    if (key == LogicalKeyboardKey.f10) return 140;
    if (key == LogicalKeyboardKey.f11) return 141;
    if (key == LogicalKeyboardKey.f12) return 142;

    if (key == LogicalKeyboardKey.shiftLeft ||
        key == LogicalKeyboardKey.shiftRight) {
      return 59;
    }
    if (key == LogicalKeyboardKey.controlLeft ||
        key == LogicalKeyboardKey.controlRight) {
      return 113;
    }
    if (key == LogicalKeyboardKey.altLeft || key == LogicalKeyboardKey.altRight) {
      return 57;
    }
    if (key == LogicalKeyboardKey.metaLeft ||
        key == LogicalKeyboardKey.metaRight) {
      return 117;
    }

    if (key == LogicalKeyboardKey.capsLock) return 115;
    if (key == LogicalKeyboardKey.pageUp) return 92;
    if (key == LogicalKeyboardKey.pageDown) return 93;
    if (key == LogicalKeyboardKey.home) return 122;
    if (key == LogicalKeyboardKey.end) return 123;
    if (key == LogicalKeyboardKey.insert) return 124;

    return 0;
  }

  Future<void> _sendPowerCommand(String action) async {
    // Build confirmation dialog
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

  void _toggleFullscreen() {
    setState(() {
      _isFullscreen = !_isFullscreen;
    });
  }

  Future<void> _disconnect() async {
    _isDisconnecting = true;
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    _frameTimer?.cancel();
    _frameTimer = null;
    _latencyTimer?.cancel();
    _latencyTimer = null;
    _statsTimer?.cancel();
    _statsTimer = null;
    try {
      await bridge.rustApi.stopStreaming();
      await stopForegroundService();
      // Record disconnection in history
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
      Navigator.of(context).pop();
    }
  }

  Widget _buildVideoDisplay(bool isStreaming) {
    final textureId = VideoPlayerService.textureId;

    if (textureId != null && textureId > 0 && isStreaming) {
      return Center(
        child: Texture(textureId: textureId),
      );
    }

    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Icon(
            Icons.monitor_outlined,
            size: 80,
            color: Colors.white38,
          ),
          const SizedBox(height: 16),
          Text(
            isStreaming
                ? 'Receiving stream...'
                : 'Connecting to remote desktop...',
            style: const TextStyle(color: Colors.white54),
          ),
          if (!isStreaming) ...{
            const SizedBox(height: 8),
            const Text(
              'Initializing MediaCodec decoder...',
              style: TextStyle(color: Colors.white38, fontSize: 12),
            ),
          },
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final latency = ref.watch(latencyProvider);
    final isStreaming = ref.watch(isStreamingProvider);
    final health = ref.watch(healthProvider);
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
          // Video display with pinch-to-zoom and input handling
          Focus(
            focusNode: _keyboardFocusNode,
            autofocus: false,
            onKeyEvent: _onKeyEvent,
            child: InteractiveViewer(
              transformationController: _transformController,
              minScale: 1.0,
              maxScale: 4.0,
              panEnabled: false,
              scaleEnabled: true,
              child: Listener(
                onPointerSignal: (event) {
                  if (event is PointerScrollEvent) {
                    _handleScroll(event);
                  }
                },
                child: GestureDetector(
                  onTapUp: _handleTap,
                  onDoubleTap: _handleDoubleTap,
                  onPanUpdate: _handleDragUpdate,
                  onLongPressStart: _handleRightClick,
                  child: Container(
                    color: Colors.black,
                    child: _buildVideoDisplay(isStreaming),
                  ),
                ),
              ),
            ),
          ),

          // Connection health indicator (replaces simple latency indicator)
          Positioned(
            top: 16,
            right: 16,
            child: GestureDetector(
              onTap: () {
                setState(() => _showStats = !_showStats);
              },
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: Colors.black87,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: healthColor.withValues(alpha: 0.5), width: 1),
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

          // Stream stats overlay (F8: toggled by tapping the health indicator)
          StreamStatsOverlay(
            visible: _showStats,
            onToggle: () => setState(() => _showStats = !_showStats),
            fps: health.fps,
            latencyMs: latency,
            bitrateKbps: health.bitrateKbps,
            frameDrops: health.frameDrops,
          ),

          // Zoom indicator (shown briefly when zoom changes)
          if (_transformController.value.getMaxScaleOnAxis() > 1.01)
            Positioned(
              top: 48,
              left: 16,
              child: Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
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

          // Overlay controls
          if (_showControls)
            Positioned(
              bottom: 24,
              left: 24,
              right: 24,
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  FilledButton.tonalIcon(
                    onPressed: _disconnect,
                    icon: const Icon(Icons.power_settings_new),
                    label: const Text('Disconnect'),
                    style: FilledButton.styleFrom(
                      backgroundColor: Colors.red.withValues(alpha: 0.8),
                    ),
                  ),
                  IconButton.filledTonal(
                    onPressed: _toggleFullscreen,
                    icon: Icon(
                      _isFullscreen
                          ? Icons.fullscreen_exit
                          : Icons.fullscreen,
                    ),
                    tooltip: 'Toggle fullscreen',
                  ),
                  // Stats toggle
                  IconButton.filledTonal(
                    onPressed: () {
                      setState(() => _showStats = !_showStats);
                    },
                    icon: const Icon(Icons.bar_chart),
                    isSelected: _showStats,
                    tooltip: 'Stream stats',
                  ),
                  // Reset zoom
                  IconButton.filledTonal(
                    onPressed: _resetZoom,
                    icon: const Icon(Icons.zoom_out_map),
                    tooltip: 'Reset zoom',
                  ),
                  // Keyboard mode toggle
                  // Power management
                  PopupMenuButton<String>(
                    onSelected: (action) => _sendPowerCommand(action),
                    itemBuilder: (ctx) => [
                      const PopupMenuItem(
                        value: 'sleep',
                        child: ListTile(
                          leading: Icon(Icons.bedtime_outlined),
                          title: Text('Sleep'),
                          subtitle: Text('Suspend to RAM'),
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'shutdown',
                        child: ListTile(
                          leading: Icon(Icons.power_settings_new, color: Colors.redAccent),
                          title: Text('Shutdown'),
                          subtitle: Text('Power off the PC'),
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'restart',
                        child: ListTile(
                          leading: Icon(Icons.restart_alt),
                          title: Text('Restart'),
                          subtitle: Text('Reboot the PC'),
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                        ),
                      ),
                      const PopupMenuItem(
                        value: 'hibernate',
                        child: ListTile(
                          leading: Icon(Icons.nightlight_outlined),
                          title: Text('Hibernate'),
                          subtitle: Text('Save state & power off'),
                          dense: true,
                          contentPadding: EdgeInsets.zero,
                        ),
                      ),
                    ],
                    child: const Icon(Icons.power_settings_new),
                  ),
                  IconButton.filledTonal(
                    onPressed: _toggleKeyboardMode,
                    icon: Icon(
                      _keyboardMode
                          ? Icons.keyboard
                          : Icons.keyboard_alt_outlined,
                    ),
                    style: IconButton.styleFrom(
                      backgroundColor: _keyboardMode
                          ? Theme.of(context)
                              .colorScheme
                              .primary
                              .withValues(alpha: 0.3)
                          : null,
                    ),
                    tooltip: _keyboardMode
                        ? 'Keyboard mode active'
                        : 'Toggle keyboard',
                  ),
                ],
              ),
            ),

          // Reconnecting overlay
          if (ref.watch(reconnectStateProvider).isReconnecting)
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
                        'Reconnecting… (${ref.watch(reconnectStateProvider).attempt}/5)',
                        style: const TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Backoff: ${ref.watch(reconnectStateProvider).backoffSeconds}s',
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
