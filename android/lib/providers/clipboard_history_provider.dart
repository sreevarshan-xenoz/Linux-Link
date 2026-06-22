import 'package:flutter_riverpod/flutter_riverpod.dart';

/// A single clipboard history entry.
class ClipboardEntry {
  final String text;
  final DateTime timestamp;
  final String preview;

  ClipboardEntry({required this.text, required this.timestamp})
      : preview = _computePreview(text);

  static String _computePreview(String text) {
    if (text.isEmpty) return '(empty)';
    final firstLine = text.split('\n').first.trim();
    if (firstLine.length > 80) {
      return '${firstLine.substring(0, 80)}…';
    }
    return firstLine;
  }

  /// Human-readable relative timestamp.
  String get relativeTime {
    final diff = DateTime.now().difference(timestamp);
    if (diff.inSeconds < 60) return '${diff.inSeconds}s ago';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }
}

/// Ring-buffer clipboard history that stores up to [maxEntries] entries.
///
/// Automatically deduplicates consecutive identical entries.
class ClipboardHistoryNotifier extends StateNotifier<List<ClipboardEntry>> {
  static const int maxEntries = 20;

  ClipboardHistoryNotifier() : super([]);

  /// Add a new clipboard entry. Skips duplicates of the most recent entry.
  void addEntry(String text) {
    if (text.isEmpty) return;
    if (state.isNotEmpty && state.last.text == text) return;

    final entry = ClipboardEntry(text: text, timestamp: DateTime.now());
    if (state.length >= maxEntries) {
      // Ring buffer: remove oldest, append new
      state = [...state.skip(1), entry];
    } else {
      state = [...state, entry];
    }
  }

  /// Remove all history entries.
  void clear() {
    state = [];
  }
}

/// Provides the clipboard history ring buffer.
final clipboardHistoryProvider =
    StateNotifierProvider<ClipboardHistoryNotifier, List<ClipboardEntry>>(
  (ref) => ClipboardHistoryNotifier(),
);

/// Whether the clipboard history overlay is currently visible.
final clipboardHistoryVisibleProvider = StateProvider<bool>((ref) => false);
