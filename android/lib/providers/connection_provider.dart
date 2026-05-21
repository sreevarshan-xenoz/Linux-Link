import 'package:flutter_riverpod/flutter_riverpod.dart';
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
  }

  void removePeer(String name) {
    state = state.where((p) => p.name != name).toList();
  }

  void clear() {
    state = [];
  }
}
