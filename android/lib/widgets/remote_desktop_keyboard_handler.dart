import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Wraps a [Focus] widget that captures keyboard events and translates them
/// into remote keycodes or text for the Linux Link server.
///
/// When [enabled] is false, keyboard events are ignored (passed through).
/// When enabled, modifier keys are sent as press/release individually,
/// printable characters are sent as text, and special keys are mapped
/// through [logicalKeyToAndroidKeyCode].
class RemoteDesktopKeyboardHandler extends StatelessWidget {
  final bool enabled;
  final FocusNode focusNode;
  final Widget child;
  final ValueChanged<int> onKeyCode;
  final ValueChanged<String> onText;

  const RemoteDesktopKeyboardHandler({
    super.key,
    required this.enabled,
    required this.focusNode,
    required this.child,
    required this.onKeyCode,
    required this.onText,
  });

  KeyEventResult _onKeyEvent(FocusNode node, KeyEvent event) {
    if (!enabled) return KeyEventResult.ignored;
    if (event is KeyRepeatEvent) return KeyEventResult.handled;
    if (event is! KeyDownEvent && event is! KeyUpEvent) {
      return KeyEventResult.handled;
    }

    final isPressed = event is KeyDownEvent;
    final key = event.logicalKey;

    // Modifier keys: send press/release individually
    if (_isModifierKey(key)) {
      final keyCode = logicalKeyToAndroidKeyCode(key);
      if (keyCode != 0) {
        onKeyCode(isPressed ? keyCode : keyCode + 100000);
      }
      return KeyEventResult.handled;
    }

    if (!isPressed) return KeyEventResult.ignored;

    // Printable characters: send as text
    final char = logicalKeyToChar(key);
    if (char != null) {
      onText(char);
      return KeyEventResult.handled;
    }

    // Special/control keys
    final keyCode = logicalKeyToAndroidKeyCode(key);
    if (keyCode != 0) {
      onKeyCode(keyCode);
      return KeyEventResult.handled;
    }

    return KeyEventResult.ignored;
  }

  /// Check if a key is a modifier (Shift, Ctrl, Alt, Meta).
  static bool _isModifierKey(LogicalKeyboardKey key) {
    return key == LogicalKeyboardKey.shiftLeft ||
        key == LogicalKeyboardKey.shiftRight ||
        key == LogicalKeyboardKey.controlLeft ||
        key == LogicalKeyboardKey.controlRight ||
        key == LogicalKeyboardKey.altLeft ||
        key == LogicalKeyboardKey.altRight ||
        key == LogicalKeyboardKey.metaLeft ||
        key == LogicalKeyboardKey.metaRight;
  }

  /// Extract a single printable character from a key if available.
  static String? logicalKeyToChar(LogicalKeyboardKey key) {
    if (key.keyLabel.isNotEmpty && key.keyLabel.length == 1) {
      return key.keyLabel;
    }
    return null;
  }

  /// Map a Flutter [LogicalKeyboardKey] to an Android keycode.
  ///
  /// Returns 0 for unmapped keys.
  static int logicalKeyToAndroidKeyCode(LogicalKeyboardKey key) {
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
    if (key == LogicalKeyboardKey.altLeft ||
        key == LogicalKeyboardKey.altRight) {
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

  @override
  Widget build(BuildContext context) {
    return Focus(
      focusNode: focusNode,
      autofocus: false,
      onKeyEvent: _onKeyEvent,
      child: child,
    );
  }
}
