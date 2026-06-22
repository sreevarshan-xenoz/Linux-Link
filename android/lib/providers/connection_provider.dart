import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/peer_info.dart';

enum ConnectionState { disconnected, connecting, connected, error }

final connectionStateProvider =
    StateProvider<ConnectionState>((ref) => ConnectionState.disconnected);

final peersProvider =
    StateNotifierProvider<PeersNotifier, List<PeerInfo>>((ref) {
  return PeersNotifier();
});

final selectedPeerProvider = StateProvider<PeerInfo?>((ref) => null);

final selectedPeerAddressProvider = StateProvider<String?>((ref) => null);

final selectedPeerPortProvider = StateProvider<int?>((ref) => null);

final manualPeersProvider =
    StateNotifierProvider<ManualPeersNotifier, List<PeerInfo>>((ref) {
  return ManualPeersNotifier();
});

class PeersNotifier extends StateNotifier<List<PeerInfo>> {
  PeersNotifier() : super([]);

  void setPeers(List<PeerInfo> peers) {
    state = peers;
  }

  void addPeer(PeerInfo peer) {
    state = [...state, peer];
  }

  void removePeer(String name) {
    state = state.where((p) => p.name != name).toList();
  }

  void updatePeer(String name, PeerInfo updated) {
    state = [
      for (final p in state)
        if (p.name == name) updated else p,
    ];
  }

  void clear() {
    state = [];
  }
}

/// SharedPreferences key for persisting manual peers.
const _manualPeersPrefKey = 'manual_peers';

/// Load manually-added peers from SharedPreferences.
Future<List<PeerInfo>> loadManualPeers() async {
  try {
    final prefs = await SharedPreferences.getInstance();
    final json = prefs.getString(_manualPeersPrefKey);
    if (json == null || json.isEmpty) return [];
    final list = jsonDecode(json) as List<dynamic>;
    return list
        .map((e) => PeerInfo.fromJson(e as Map<String, dynamic>))
        .toList();
  } catch (e) {
    debugPrint('Failed to load manual peers: $e');
    return [];
  }
}

/// Persist manual peers to SharedPreferences.
Future<void> saveManualPeers(List<PeerInfo> peers) async {
  try {
    final prefs = await SharedPreferences.getInstance();
    final json = jsonEncode(peers.map((p) => p.toJson()).toList());
    await prefs.setString(_manualPeersPrefKey, json);
  } catch (e) {
    debugPrint('Failed to save manual peers: $e');
  }
}

class ManualPeersNotifier extends StateNotifier<List<PeerInfo>> {
  ManualPeersNotifier() : super([]);

  void addPeer(String name, String ip, {int port = 1716}) {
    final peer = PeerInfo(
      name: name,
      dnsName: '$name.tailc34144.ts.net',
      ips: [ip],
      online: true,
    );
    state = [...state, peer];
    _persist();
  }

  void removePeer(String name) {
    state = state.where((p) => p.name != name).toList();
    _persist();
  }

  void clear() {
    state = [];
    _persist();
  }

  /// Asynchronously persist current state to SharedPreferences.
  /// Fire-and-forget — errors are logged internally.
  void _persist() {
    final snapshot = state;
    saveManualPeers(snapshot);
  }
}
