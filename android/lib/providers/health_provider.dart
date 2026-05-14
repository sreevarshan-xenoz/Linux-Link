import 'package:flutter_riverpod/flutter_riverpod.dart';

/// Connection health levels for visual indicator color coding.
enum ConnectionHealth { excellent, good, fair, poor, disconnected }

/// Connection health metrics for a streaming session.
class HealthMetrics {
  /// Current RTT in milliseconds.
  final int latencyMs;

  /// Current frame rate (frames per second).
  final double fps;

  /// Estimated bitrate in kilobits per second.
  final int bitrateKbps;

  /// Number of frames dropped in the last monitoring window.
  final int frameDrops;

  /// Derived health level.
  ConnectionHealth get health {
    if (latencyMs < 30 && frameDrops < 2) return ConnectionHealth.excellent;
    if (latencyMs < 80 && frameDrops < 5) return ConnectionHealth.good;
    if (latencyMs < 200 && frameDrops < 15) return ConnectionHealth.fair;
    return ConnectionHealth.poor;
  }

  const HealthMetrics({
    this.latencyMs = 0,
    this.fps = 0,
    this.bitrateKbps = 0,
    this.frameDrops = 0,
  });
}

/// Provider for streaming session health metrics.
///
/// Maintains a sliding window of latency samples for smoothing.
/// Other providers (latencyProvider, isStreamingProvider) feed into this.
final healthProvider =
    StateNotifierProvider<HealthNotifier, HealthMetrics>((ref) {
  return HealthNotifier();
});

class HealthNotifier extends StateNotifier<HealthMetrics> {
  HealthNotifier() : super(const HealthMetrics());

  /// Sliding window of latency samples (up to 10).
  final List<int> _latencyHistory = [];

  /// Update health metrics with new data points.
  void update({
    int? latencyMs,
    double? fps,
    int? bitrateKbps,
    int? frameDrops,
  }) {
    if (latencyMs != null) {
      _latencyHistory.add(latencyMs);
      if (_latencyHistory.length > 10) {
        _latencyHistory.removeAt(0);
      }
    }

    state = HealthMetrics(
      latencyMs: latencyMs ?? state.latencyMs,
      fps: fps ?? state.fps,
      bitrateKbps: bitrateKbps ?? state.bitrateKbps,
      frameDrops: frameDrops ?? state.frameDrops,
    );
  }

  /// Get the smoothed latency (median of sliding window).
  int get smoothedLatencyMs {
    if (_latencyHistory.isEmpty) return 0;
    final sorted = List<int>.from(_latencyHistory)..sort();
    return sorted[sorted.length ~/ 2];
  }

  /// Reset health metrics to defaults.
  void reset() {
    _latencyHistory.clear();
    state = const HealthMetrics();
  }
}
