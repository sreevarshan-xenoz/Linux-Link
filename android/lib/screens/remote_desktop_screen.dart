import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/connection_provider.dart';
import '../providers/streaming_provider.dart';
import '../rust_api_bridge.dart';
import '../services/video_player_service.dart';

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
  bool _showControls = true;
  Timer? _streamingCheckTimer;

  @override
  void initState() {
    super.initState();
    _initVideoDecoder();
    _startStreaming();
    _startStreamingCheck();
  }

  @override
  void dispose() {
    _streamingCheckTimer?.cancel();
    _streamingCheckTimer = null;
    VideoPlayerService.dispose().catchError((e) => debugPrint('Video dispose error: $e'));
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
      await rustApi.startStreaming(widget.address, widget.port);
      if (mounted) {
        ref.read(isStreamingProvider.notifier).state = true;
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to start streaming: $e')),
        );
      }
    }
  }

  void _startStreamingCheck() {
    _streamingCheckTimer = Timer.periodic(
      const Duration(seconds: 2),
      (_) async {
        if (!mounted) return;
        final isActive = await rustApi.isStreamingActive();
        if (mounted) {
          ref.read(isStreamingProvider.notifier).state = isActive;
        }
      },
    );
  }

  Future<void> _handleTap(TapUpDetails details) async {
    final x = details.localPosition.dx;
    final y = details.localPosition.dy;
    try {
      await rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        x,
        y,
        1, // left button
        true,
      );
      await rustApi.sendMouseEvent(
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
    try {
      await rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        details.delta.dx,
        details.delta.dy,
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
      await rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        true,
      );
      await rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        false,
      );
      await rustApi.sendMouseEvent(
        widget.address,
        widget.port,
        0,
        0,
        1,
        true,
      );
      await rustApi.sendMouseEvent(
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

  void _toggleFullscreen() {
    setState(() {
      _isFullscreen = !_isFullscreen;
    });
  }

  void _toggleControls() {
    setState(() {
      _showControls = !_showControls;
    });
  }

  Future<void> _disconnect() async {
    try {
      await rustApi.stopStreaming();
    } catch (e) {
      debugPrint('Stop streaming error: $e');
    }
    if (mounted) {
      ref.read(connectionStateProvider.notifier).state = ConnectionState.disconnected;
      ref.read(isStreamingProvider.notifier).state = false;
      Navigator.of(context).pop();
    }
  }

  /// Build the video display area using MediaCodec Texture or placeholder.
  Widget _buildVideoDisplay(bool isStreaming) {
    final textureId = VideoPlayerService.textureId;

    if (textureId != null && textureId > 0 && isStreaming) {
      // Render decoded video frames via MediaCodec SurfaceTexture
      return Center(
        child: Texture(textureId: textureId),
      );
    }

    // Placeholder while not streaming
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
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
          if (!isStreaming) ...[
            const SizedBox(height: 8),
            const Text(
              'Initializing MediaCodec decoder...',
              style: TextStyle(color: Colors.white38, fontSize: 12),
            ),
          ],
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final latency = ref.watch(latencyProvider);
    final isStreaming = ref.watch(isStreamingProvider);

    return Scaffold(
      body: Stack(
        children: [
          // Video display
          GestureDetector(
            onTapUp: _handleTap,
            onDoubleTap: _handleDoubleTap,
            onPanUpdate: _handleDragUpdate,
            child: Container(
              color: Colors.black,
              child: _buildVideoDisplay(isStreaming),
            ),
          ),
          // Latency indicator
          Positioned(
            top: 16,
            right: 16,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Colors.black54,
                borderRadius: BorderRadius.circular(12),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.signal_cellular_alt,
                    size: 14,
                    color: latency < 50
                        ? Colors.green
                        : latency < 100
                            ? Colors.orange
                            : Colors.red,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    '${latency}ms',
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
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
                      backgroundColor: Colors.red.withOpacity(0.8),
                    ),
                  ),
                  IconButton.filledTonal(
                    onPressed: _toggleFullscreen,
                    icon: Icon(
                      _isFullscreen
                          ? Icons.fullscreen_exit
                          : Icons.fullscreen,
                    ),
                  ),
                  IconButton.filledTonal(
                    onPressed: _toggleControls,
                    icon: const Icon(Icons.visibility_off),
                  ),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
