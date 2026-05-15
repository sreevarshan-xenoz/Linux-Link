import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../rust_api_bridge.dart' as bridge;

/// F10: Gamepad input capture and forwarding service.
///
/// Captures gamepad/controller state from Android's input subsystem
/// via MethodChannel and forwards events to the remote PC over the
/// QUIC streaming channel at 60 Hz.
class GamepadService {
  static const _channel = MethodChannel('com.linuxlink/gamepad');
  static const _pollInterval = Duration(milliseconds: 16); // ~60 Hz
  static Timer? _timer;
  static bool _active = false;

  /// Whether gamepad capture is currently active.
  static bool get isActive => _active;

  /// Start polling gamepad state and forwarding to the remote PC.
  static void start() {
    if (_active) return;
    _active = true;
    _timer = Timer.periodic(_pollInterval, (_) => _pollAndSend());
    debugPrint('GamepadService started');
  }

  /// Stop gamepad capture.
  static void stop() {
    _active = false;
    _timer?.cancel();
    _timer = null;
    debugPrint('GamepadService stopped');
  }

  /// Poll gamepad state from Android and send via FFI.
  static Future<void> _pollAndSend() async {
    if (!_active) return;

    try {
      final result = await _channel.invokeMethod<Map<dynamic, dynamic>>(
        'getGamepadState',
      );
      if (result == null || !_active) return;

      final axes = (result['axes'] as List<dynamic>?)
              ?.map((e) => (e as num).toInt().clamp(-32768, 32767))
              .toList() ??
          [0, 0, 0, 0, 0, 0];

      final buttons = (result['buttons'] as num?)?.toInt() ?? 0;

      await bridge.rustApi.sendGamepadEvent(
        axes: axes,
        buttons: buttons,
      );
    } catch (e) {
      // Gamepad not connected or not available — silent
    }
  }
}
