import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'clipboard_service.dart';
import '../rust_api_bridge.dart' as bridge;

/// Service that periodically syncs clipboard content between Android and the remote PC.
///
/// - Polls local Android clipboard every 3 seconds.
/// - Listens for remote clipboard changes from the Rust backend.
/// - Uses content hash comparison to avoid sync loops.
///
/// Call [start] when a streaming session begins, [stop] when it ends.
class ClipboardSyncService {
  static const String _keyEnabled = 'clipboard_auto_sync';
  static const Duration _pollInterval = Duration(seconds: 3);

  Timer? _localPollTimer;
  String _lastLocalHash = '';
  String _lastRemoteHash = '';
  String? _currentAddress;
  int? _currentPort;
  bool _isRunning = false;

  /// Whether the auto-sync feature is enabled in settings.
  static Future<bool> isEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_keyEnabled) ?? false;
  }

  /// Enable or disable the feature in settings.
  static Future<void> setEnabled(bool enabled) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_keyEnabled, enabled);
  }

  /// Start the sync service. Call when streaming begins.
  void start(String address, int port) {
    if (_isRunning) return;
    _isRunning = true;
    _currentAddress = address;
    _currentPort = port;
    _lastLocalHash = '';
    _lastRemoteHash = '';
    _startLocalPolling();
    debugPrint('ClipboardSyncService: started');
  }

  /// Stop the sync service. Call when streaming ends.
  void stop() {
    _isRunning = false;
    _localPollTimer?.cancel();
    _localPollTimer = null;
    _currentAddress = null;
    _currentPort = null;
    _lastLocalHash = '';
    _lastRemoteHash = '';
    debugPrint('ClipboardSyncService: stopped');
  }

  /// Called when a remote clipboard change is detected (e.g., from KDE Connect plugin).
  /// Updates the remote hash so local polling doesn't re-send it.
  void onRemoteClipboardChanged(String content) {
    _lastRemoteHash = _computeHash(content);
    // Push the remote content to the local Android clipboard
    ClipboardService.setClipboard(content);
    debugPrint('ClipboardSyncService: remote → local sync');
  }

  void _startLocalPolling() {
    _localPollTimer = Timer.periodic(_pollInterval, (_) async {
      if (!_isRunning) return;
      await _pollLocalClipboard();
    });
  }

  Future<void> _pollLocalClipboard() async {
    final address = _currentAddress;
    final port = _currentPort;
    if (address == null || port == null) return;

    try {
      final text = await ClipboardService.getClipboard();
      if (text == null || text.isEmpty) return;

      final hash = _computeHash(text);
      // Don't re-send if local content matches our last sync
      if (hash == _lastLocalHash || hash == _lastRemoteHash) return;

      _lastLocalHash = hash;
      await bridge.rustApi.sendClipboard(address, port, text);
      debugPrint('ClipboardSyncService: local → remote sync');
    } catch (e) {
      debugPrint('ClipboardSyncService: poll error: $e');
    }
  }

  String _computeHash(String content) {
    return const JsonEncoder().convert(content.length) +
        content.hashCode.toString();
  }
}

/// Global singleton instance.
final clipboardSyncService = ClipboardSyncService();
