import 'dart:math' as math;
import 'package:flutter/material.dart';

/// A draggable overlay showing real-time streaming statistics (FPS, latency, bitrate).
class StreamStatsOverlay extends StatefulWidget {
  final bool visible;
  final VoidCallback onToggle;
  final double fps;
  final int latencyMs;
  final int bitrateKbps;
  final int frameDrops;

  const StreamStatsOverlay({
    super.key,
    required this.visible,
    required this.onToggle,
    this.fps = 0,
    this.latencyMs = 0,
    this.bitrateKbps = 0,
    this.frameDrops = 0,
  });

  @override
  State<StreamStatsOverlay> createState() => _StreamStatsOverlayState();
}

class _StreamStatsOverlayState extends State<StreamStatsOverlay> {
  /// Latency history for mini line chart (last 30 samples).
  final List<int> _latencyHistory = [];

  @override
  void didUpdateWidget(StreamStatsOverlay oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.latencyMs != oldWidget.latencyMs && widget.latencyMs > 0) {
      _latencyHistory.add(widget.latencyMs);
      if (_latencyHistory.length > 30) {
        _latencyHistory.removeAt(0);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.visible) return const SizedBox.shrink();

    final theme = Theme.of(context);
    final latencyColor = widget.latencyMs < 50
        ? Colors.green
        : widget.latencyMs < 100
            ? Colors.orange
            : Colors.red;

    return Positioned(
      top: 80,
      right: 8,
      child: GestureDetector(
        onLongPress: widget.onToggle,
        child: Container(
          width: 160,
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Colors.black87,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.white24, width: 0.5),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              // Header row with toggle hint
              Row(
                children: [
                  Icon(Icons.bar_chart,
                      size: 12, color: theme.colorScheme.primary),
                  const SizedBox(width: 4),
                  Text(
                    'Stream Stats',
                    style: TextStyle(
                      color: theme.colorScheme.primary,
                      fontSize: 10,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const Spacer(),
                  GestureDetector(
                    onTap: widget.onToggle,
                    child: const Icon(Icons.close,
                        size: 12, color: Colors.white38),
                  ),
                ],
              ),
              const SizedBox(height: 6),
              // FPS
              _statRow(
                icon: Icons.speed,
                label: 'FPS',
                value: widget.fps.toStringAsFixed(1),
                color: widget.fps > 20 ? Colors.green : Colors.orange,
              ),
              const SizedBox(height: 2),
              // Latency
              _statRow(
                icon: Icons.timer,
                label: 'Latency',
                value: '${widget.latencyMs} ms',
                color: latencyColor,
              ),
              const SizedBox(height: 2),
              // Bitrate
              _statRow(
                icon: Icons.wifi,
                label: 'Bitrate',
                value: '${widget.bitrateKbps} kbps',
                color: Colors.blue,
              ),
              const SizedBox(height: 2),
              // Frame drops
              _statRow(
                icon: Icons.warning_amber,
                label: 'Drops',
                value: '${widget.frameDrops}',
                color: widget.frameDrops > 10 ? Colors.red : Colors.white54,
              ),
              // Mini latency chart
              if (_latencyHistory.length >= 2) ...[
                const SizedBox(height: 6),
                _latencyChart(theme),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _statRow({
    required IconData icon,
    required String label,
    required String value,
    required Color color,
  }) {
    return Row(
      children: [
        Icon(icon, size: 10, color: color),
        const SizedBox(width: 4),
        Text(
          label,
          style: const TextStyle(color: Colors.white54, fontSize: 9),
        ),
        const Spacer(),
        Text(
          value,
          style: TextStyle(
            color: color,
            fontSize: 10,
            fontWeight: FontWeight.w600,
            fontFamily: 'monospace',
          ),
        ),
      ],
    );
  }

  Widget _latencyChart(ThemeData theme) {
    final maxLatency = _latencyHistory.reduce(math.max).toDouble();
    final minLatency = _latencyHistory.reduce(math.min).toDouble();
    final range = (maxLatency - minLatency).clamp(1.0, double.infinity);

    return CustomPaint(
        size: const Size(double.infinity, 20),
        painter: _LatencyChartPainter(
          samples: _latencyHistory,
          min: minLatency,
          range: range,
          color: theme.colorScheme.primary,
        ));
  }
}

class _LatencyChartPainter extends CustomPainter {
  final List<int> samples;
  final double min;
  final double range;
  final Color color;

  const _LatencyChartPainter({
    required this.samples,
    required this.min,
    required this.range,
    required this.color,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (samples.length < 2) return;

    final paint = Paint()
      ..color = color.withValues(alpha: 0.6)
      ..strokeWidth = 1.5
      ..style = PaintingStyle.stroke;

    final fillPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [
          color.withValues(alpha: 0.3),
          color.withValues(alpha: 0.0),
        ],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));

    final path = Path();
    final fillPath = Path();
    final stepX = size.width / (samples.length - 1);

    for (var i = 0; i < samples.length; i++) {
      final x = i * stepX;
      final normalized = (samples[i] - min) / range;
      final y = size.height - (normalized * size.height);

      if (i == 0) {
        path.moveTo(x, y);
        fillPath.moveTo(x, size.height);
        fillPath.lineTo(x, y);
      } else {
        path.lineTo(x, y);
        fillPath.lineTo(x, y);
      }
    }

    fillPath.lineTo(size.width, size.height);
    fillPath.close();

    canvas.drawPath(fillPath, fillPaint);
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(_LatencyChartPainter oldDelegate) =>
      samples != oldDelegate.samples;
}
