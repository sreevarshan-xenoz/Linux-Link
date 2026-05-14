import 'package:flutter_riverpod/flutter_riverpod.dart';

final isStreamingProvider = StateProvider<bool>((ref) => false);

final latencyProvider = StateProvider<int>((ref) => 0);

/// Auto-reconnect state.
///
/// - `idle`: No reconnect in progress.
/// - `reconnecting(attempt, maxAttempts)`: Reconnect in progress.
/// - `failed`: All reconnect attempts exhausted.
class ReconnectState {
  final int attempt;
  final int maxAttempts;
  final bool isReconnecting;

  const ReconnectState._({
    this.attempt = 0,
    this.maxAttempts = 5,
    this.isReconnecting = false,
  });

  const ReconnectState.idle() : this._();

  const ReconnectState.reconnecting({int attempt = 1, int maxAttempts = 5})
      : this._(
          attempt: attempt,
          maxAttempts: maxAttempts,
          isReconnecting: true,
        );

  const ReconnectState.failed({int maxAttempts = 5})
      : this._(
          attempt: maxAttempts,
          maxAttempts: maxAttempts,
          isReconnecting: false,
        );

  int get backoffSeconds {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, capped at 30s
    final exp = (1 << (attempt - 1)).clamp(1, 30);
    return exp;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is ReconnectState &&
          runtimeType == other.runtimeType &&
          attempt == other.attempt &&
          maxAttempts == other.maxAttempts &&
          isReconnecting == other.isReconnecting;

  @override
  int get hashCode => Object.hash(attempt, maxAttempts, isReconnecting);
}

final reconnectStateProvider = StateProvider<ReconnectState>(
  (ref) => const ReconnectState.idle(),
);
