import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/peer_info.dart';
import '../providers/connection_provider.dart';
import '../widgets/peer_list_tile.dart';
import '../rust_api_bridge.dart';

class ConnectionScreen extends ConsumerStatefulWidget {
  const ConnectionScreen({super.key});

  @override
  ConsumerState<ConnectionScreen> createState() => _ConnectionScreenState();
}

class _ConnectionScreenState extends ConsumerState<ConnectionScreen> {
  bool _isLoading = false;

  Future<void> _refreshPeers() async {
    setState(() => _isLoading = true);
    try {
      final peers = await rustApi.getPeers();
      if (mounted) {
        ref.read(peersProvider.notifier).setPeers(peers);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to fetch peers: $e')),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _connectToPeer(PeerInfo peer) async {
    if (peer.ips.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Peer has no IP addresses')),
        );
      }
      return;
    }

    ref.read(selectedPeerProvider.notifier).state = peer;
    ref.read(connectionStateProvider.notifier).state = ConnectionState.connecting;

    try {
      final address = peer.ips.first;
      const port = 1716;
      final state = await rustApi.connectToPeer(address, port);

      if (mounted) {
        switch (state) {
          case rust_api_bridge.ConnectionState.connected:
            ref.read(connectionStateProvider.notifier).state = ConnectionState.connected;
            // Navigate to remote desktop screen
            Navigator.of(context).pushNamed(
              '/remote',
              arguments: {'address': address, 'port': port},
            );
          case rust_api_bridge.ConnectionState.connecting:
            ref.read(connectionStateProvider.notifier).state = ConnectionState.connecting;
          case rust_api_bridge.ConnectionState.error:
            ref.read(connectionStateProvider.notifier).state = ConnectionState.error;
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Failed to connect to peer')),
              );
            }
          case rust_api_bridge.ConnectionState.disconnected:
            ref.read(connectionStateProvider.notifier).state = ConnectionState.disconnected;
        }
      }
    } catch (e) {
      if (mounted) {
        ref.read(connectionStateProvider.notifier).state = ConnectionState.error;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Connection error: $e')),
        );
      }
    }
  }

  @override
  void initState() {
    super.initState();
    _refreshPeers();
  }

  @override
  Widget build(BuildContext context) {
    final peers = ref.watch(peersProvider);
    final connectionState = ref.watch(connectionStateProvider);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Linux Link'),
        actions: [
          if (_isLoading)
            const Padding(
              padding: EdgeInsets.all(12.0),
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _isLoading ? null : () => _refreshPeers(),
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
                          onPressed: _isLoading ? null : _refreshPeers,
                          icon: _isLoading
                              ? const SizedBox(
                                  width: 16,
                                  height: 16,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                    color: Colors.white,
                                  ),
                                )
                              : const Icon(Icons.refresh),
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
                            ? () => _connectToPeer(peer)
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
