import 'dart:convert';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/peer_info.dart';

/// Key for persisting bookmarks as a JSON string in SharedPreferences.
const _kBookmarksKey = 'bookmarked_peers';

/// Provider for bookmarked peers with persistence.
final bookmarksProvider =
    StateNotifierProvider<BookmarksNotifier, List<PeerInfo>>((ref) {
  return BookmarksNotifier();
});

class BookmarksNotifier extends StateNotifier<List<PeerInfo>> {
  BookmarksNotifier() : super([]) {
    _load();
  }

  /// Load bookmarks from SharedPreferences.
  Future<void> _load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_kBookmarksKey);
      if (raw != null && raw.isNotEmpty) {
        final list = jsonDecode(raw) as List<dynamic>;
        state = list
            .map((e) => PeerInfo.fromJson(e as Map<String, dynamic>))
            .toList();
      }
    } catch (e) {
      // Silently fail — bookmarks just start empty
    }
  }

  /// Persist current bookmarks to SharedPreferences.
  Future<void> _save() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = jsonEncode(state.map((p) => p.toJson()).toList());
      await prefs.setString(_kBookmarksKey, raw);
    } catch (e) {
      // Silently fail — bookmarks still work in-memory
    }
  }

  /// Check if a peer is bookmarked by name.
  bool isBookmarked(String peerName) {
    return state.any((p) => p.name == peerName);
  }

  /// Toggle bookmark status for a peer.
  Future<void> toggle(PeerInfo peer) async {
    if (isBookmarked(peer.name)) {
      state = state.where((p) => p.name != peer.name).toList();
    } else {
      state = [...state, peer];
    }
    await _save();
  }

  /// Add a peer to bookmarks.
  Future<void> add(PeerInfo peer) async {
    if (!isBookmarked(peer.name)) {
      state = [...state, peer];
      await _save();
    }
  }

  /// Remove a peer from bookmarks by name.
  Future<void> remove(String peerName) async {
    state = state.where((p) => p.name != peerName).toList();
    await _save();
  }

  /// Clear all bookmarks.
  Future<void> clear() async {
    state = [];
    await _save();
  }
}
