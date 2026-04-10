import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/peer_info.dart';
import '../providers/connection_provider.dart';
import '../widgets/peer_list_tile.dart';

class ConnectionScreen extends ConsumerWidget {
  const ConnectionScreen({super.key});

  Future<void> _refreshPeers(WidgetRef ref) async {
    // TODO: Wire up to Rust FFI get_peers()
    // Simulated peers for development
    final simulatedPeers = [
      const PeerInfo(
        name: 'arch-desktop',
        dnsName: 'arch-desktop.tail12345.ts.net',
        ips: ['100.64.0.1'],
        online: true,
      ),
      const PeerInfo(
        name: 'work-laptop',
        dnsName: 'work-laptop.tail12345.ts.net',
        ips: ['100.64.0.2'],
        online: true,
      ),
      const PeerInfo(
        name: 'home-server',
        dnsName: 'home-server.tail12345.ts.net',
        ips: ['100.64.0.3'],
        online: false,
      ),
    ];
    ref.read(peersProvider.notifier).setPeers(simulatedPeers);
  }

  void _connectToPeer(WidgetRef ref, PeerInfo peer) {
    ref.read(selectedPeerProvider.notifier).state = peer;
    ref.read(connectionStateProvider.notifier).state = ConnectionState.connecting;

    // TODO: Wire up to Rust FFI connect_to_peer()
    // Simulate connection
    Future.delayed(const Duration(seconds: 2), () {
      ref.read(connectionStateProvider.notifier).state = ConnectionState.connected;
    });
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final peers = ref.watch(peersProvider);
    final connectionState = ref.watch(connectionStateProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Linux Link'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: () => _refreshPeers(ref),
            tooltip: 'Refresh peers',
          ),
        ],
      ),
      body: Column(
        children: [
          // Connection status banner
          if (connectionState != ConnectionState.disconnected)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              color: switch (connectionState) {
                ConnectionState.connecting => Colors.orange.withOpacity(0.1),
                ConnectionState.connected => Colors.green.withOpacity(0.1),
                ConnectionState.error => Colors.red.withOpacity(0.1),
                ConnectionState.disconnected => Colors.transparent,
              },
              child: Row(
                children: [
                  switch (connectionState) {
                    ConnectionState.connecting =>
                      const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    ConnectionState.connected =>
                      const Icon(Icons.check_circle, color: Colors.green),
                    ConnectionState.error =>
                      const Icon(Icons.error, color: Colors.red),
                    ConnectionState.disconnected => const SizedBox.shrink(),
                  },
                  const SizedBox(width: 8),
                  Text(
                    switch (connectionState) {
                      ConnectionState.connecting => 'Connecting...',
                      ConnectionState.connected => 'Connected',
                      ConnectionState.error => 'Connection error',
                      ConnectionState.disconnected => '',
                    },
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          // Peer list
          Expanded(
            child: peers.isEmpty
                ? Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.computer_outlined,
                          size: 64,
                          color: Theme.of(context).colorScheme.outline,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'No peers discovered',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Make sure Tailscale is running and peers are online',
                          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                        ),
                        const SizedBox(height: 16),
                        FilledButton.icon(
                          onPressed: () => _refreshPeers(ref),
                          icon: const Icon(Icons.refresh),
                          label: const Text('Scan for peers'),
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    itemCount: peers.length,
                    itemBuilder: (context, index) {
                      final peer = peers[index];
                      return PeerListTile(
                        peer: peer,
                        onTap: peer.online
                            ? () => _connectToPeer(ref, peer)
                            : null,
                      );
                    },
                  ),
          ),
        ],
      ),
    );
  }
}
