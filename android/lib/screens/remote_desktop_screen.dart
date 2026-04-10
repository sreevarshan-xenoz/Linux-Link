import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/connection_provider.dart';
import '../providers/streaming_provider.dart';

class RemoteDesktopScreen extends ConsumerStatefulWidget {
  const RemoteDesktopScreen({super.key});

  @override
  ConsumerState<RemoteDesktopScreen> createState() =>
      _RemoteDesktopScreenState();
}

class _RemoteDesktopScreenState extends ConsumerState<RemoteDesktopScreen> {
  bool _isFullscreen = false;
  bool _showControls = true;

  void _handleTap(TapUpDetails details) {
    // TODO: Wire up to Rust FFI send_mouse_event()
    final dx = details.localPosition.dx;
    final dy = details.localPosition.dy;
    debugPrint('Tap at ($dx, $dy)');
  }

  void _handleDragUpdate(DragUpdateDetails details) {
    // TODO: Wire up to Rust FFI send_mouse_event() for trackpad mode
    debugPrint('Drag delta: (${details.delta.dx}, ${details.delta.dy})');
  }

  void _handleDoubleTap() {
    // TODO: Wire up to Rust FFI for double-click
    debugPrint('Double tap');
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

  void _disconnect(WidgetRef ref) {
    // TODO: Wire up to Rust FFI disconnect
    ref.read(connectionStateProvider.notifier).state = ConnectionState.disconnected;
    ref.read(isStreamingProvider.notifier).state = false;
    Navigator.of(context).pop();
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
              child: Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // Placeholder Texture widget
                    // TODO: Integrate MediaCodec SurfaceTexture for video rendering
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
                    const SizedBox(height: 8),
                    const Text(
                      'MediaCodec integration pending',
                      style: TextStyle(color: Colors.white38, fontSize: 12),
                    ),
                  ],
                ),
              ),
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
                    onPressed: () => _disconnect(ref),
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
