import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import '../services/video_player_service.dart';

/// Callback types for remote desktop gesture events.
///
/// All position values are in content-space (accounting for zoom/pan).
typedef TapCallback = void Function(double x, double y);
typedef DragCallback = void Function(double dx, double dy);
typedef ScrollCallback = void Function(double dx, double dy);

/// Wraps the remote desktop video display with gesture handling for
/// mouse emulation (tap, drag, double-tap, long-press for right-click,
/// scroll, pinch-zoom) and file drag-and-drop transfer.
class RemoteDesktopGestureHandler extends StatelessWidget {
  final TransformationController transformController;
  final bool isStreaming;
  final TapCallback? onTap;
  final TapCallback? onDoubleTap;
  final DragCallback? onPanUpdate;
  final TapCallback? onRightClick;
  final ScrollCallback? onScroll;
  final ValueChanged<String>? onFileDrop;

  const RemoteDesktopGestureHandler({
    super.key,
    required this.transformController,
    required this.isStreaming,
    this.onTap,
    this.onDoubleTap,
    this.onPanUpdate,
    this.onRightClick,
    this.onScroll,
    this.onFileDrop,
  });

  /// Transform a screen-space position to content-space accounting for zoom/pan.
  Offset _inverseTransform(Offset screenPos) {
    final matrix = transformController.value;
    final scale = matrix.getMaxScaleOnAxis();
    final translation = matrix.getTranslation();
    final cx = (screenPos.dx - translation.x) / scale;
    final cy = (screenPos.dy - translation.y) / scale;
    return Offset(
      cx.clamp(0, double.infinity),
      cy.clamp(0, double.infinity),
    );
  }

  Widget _buildVideoDisplay() {
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
    return DragTarget<String>(
      onWillAcceptWithDetails: (_) => true,
      onAcceptWithDetails: (details) {
        onFileDrop?.call(details.data);
      },
      builder: (context, candidateData, rejectedData) {
        return Stack(
          children: [
            // Pinch-to-zoom via InteractiveViewer wrapping gesture detection
            InteractiveViewer(
              transformationController: transformController,
              minScale: 1.0,
              maxScale: 4.0,
              panEnabled: false,
              scaleEnabled: true,
              child: Listener(
                onPointerSignal: (event) {
                  if (event is PointerScrollEvent && onScroll != null) {
                    onScroll!(event.scrollDelta.dx, event.scrollDelta.dy);
                  }
                },
                child: GestureDetector(
                  onTapUp: (details) {
                    if (onTap != null) {
                      final t = _inverseTransform(details.localPosition);
                      onTap!(t.dx, t.dy);
                    }
                  },
                  onDoubleTap: () {
                    if (onDoubleTap != null) {
                      onDoubleTap!(0, 0);
                    }
                  },
                  onPanUpdate: (details) {
                    if (onPanUpdate != null) {
                      final scale =
                          transformController.value.getMaxScaleOnAxis();
                      onPanUpdate!(details.delta.dx / scale,
                          details.delta.dy / scale);
                    }
                  },
                  onLongPressStart: (details) {
                    if (onRightClick != null) {
                      final t = _inverseTransform(details.localPosition);
                      onRightClick!(t.dx, t.dy);
                    }
                  },
                  child: Container(
                    color: Colors.black,
                    child: _buildVideoDisplay(),
                  ),
                ),
              ),
            ),
            // Drag hover overlay
            if (candidateData.isNotEmpty)
              Positioned.fill(
                child: Container(
                  decoration: BoxDecoration(
                    border: Border.all(
                      color: Theme.of(context)
                          .colorScheme
                          .primary
                          .withValues(alpha: 0.8),
                      width: 3,
                    ),
                  ),
                  child: Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.cloud_upload,
                          size: 48,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Drop to send file',
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.primary,
                            fontSize: 16,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
          ],
        );
      },
    );
  }
}
