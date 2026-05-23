import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../models/peer_info.dart';
import '../providers/connection_provider.dart' as conn;
import '../providers/bookmarks_provider.dart';
import '../widgets/peer_list_tile.dart';
import '../rust_api_bridge.dart' as bridge;
import '../api.dart' as frb;
import '../services/history_service.dart';

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
      final peers = await bridge.rustApi.getPeers();
      if (mounted) {
        ref.read(conn.peersProvider.notifier).setPeers(peers);
        // Show hint if no peers found on Android (Tailscale API unavailable)
        if (peers.isEmpty) {
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(
                content: Text(
                  'No peers found. On Android, use "Connect by IP" to connect directly to your server.',
                ),
                duration: Duration(seconds: 5),
                behavior: SnackBarBehavior.floating,
              ),
            );
          }
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to fetch peers: $e'),
            duration: const Duration(seconds: 4),
          ),
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

    ref.read(conn.selectedPeerProvider.notifier).state = peer;
    ref.read(conn.connectionStateProvider.notifier).state =
        conn.ConnectionState.connecting;

    try {
      final address = peer.ips.first;
      const port = 1716;
      final state = await bridge.rustApi.connectToPeer(address, port);

      if (mounted) {
        switch (state) {
          case bridge.ConnectionState.connected:
            ref.read(conn.connectionStateProvider.notifier).state =
                conn.ConnectionState.connected;
            HistoryService.addRecord(ConnectionRecord(
              peerName: peer.name,
              peerAddress: address,
              port: port,
              connectedAt: DateTime.now(),
            )).catchError((e) => debugPrint('History save error: $e'));
            context.go('/remote', extra: {'address': address, 'port': port});
          case bridge.ConnectionState.connecting:
            ref.read(conn.connectionStateProvider.notifier).state =
                conn.ConnectionState.connecting;
          case bridge.ConnectionState.error:
            ref.read(conn.connectionStateProvider.notifier).state =
                conn.ConnectionState.error;
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(content: Text('Failed to connect to peer')),
              );
            }
          case bridge.ConnectionState.disconnected:
            ref.read(conn.connectionStateProvider.notifier).state =
                conn.ConnectionState.disconnected;
        }
      }
    } catch (e) {
      if (mounted) {
        ref.read(conn.connectionStateProvider.notifier).state =
            conn.ConnectionState.error;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Connection error: $e')),
        );
      }
    }
  }

  Future<void> _toggleBookmark(PeerInfo peer) async {
    final bookmarks = ref.read(bookmarksProvider.notifier);
    await bookmarks.toggle(peer);
  }

  void _wakePeer(PeerInfo peer) {
    showDialog(
      context: context,
      builder: (ctx) {
        var macController = TextEditingController();
        return AlertDialog(
          title: const Text('Wake on LAN'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Enter the MAC address for ${peer.name} to send a Wake-on-LAN magic packet.',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 4),
              Text(
                'Format: AA:BB:CC:DD:EE:FF',
                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                      fontFamily: 'monospace',
                    ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: macController,
                decoration: const InputDecoration(
                  labelText: 'MAC Address',
                  hintText: 'AA:BB:CC:DD:EE:FF',
                  helperText: 'Required to wake the machine on your LAN',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.wifi),
                ),
                textInputAction: TextInputAction.done,
                textCapitalization: TextCapitalization.characters,
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel'),
            ),
            FilledButton.icon(
              onPressed: () async {
                final mac = macController.text.trim();
                if (mac.isEmpty) return;
                Navigator.pop(ctx);

                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('Sending Wake-on-LAN magic packet...'),
                    duration: Duration(seconds: 5),
                  ),
                );

                try {
                  // Use standard LAN broadcast address
                  await bridge.rustApi.sendWol(mac, '255.255.255.255');
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Wake signal sent to ${peer.name}'),
                        backgroundColor: Colors.green,
                        duration: const Duration(seconds: 3),
                      ),
                    );
                  }
                } catch (e) {
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Failed to send wake signal: $e'),
                        backgroundColor: Colors.red,
                      ),
                    );
                  }
                }
              },
              icon: const Icon(Icons.power_settings_new),
              label: const Text('Send Wake Signal'),
            ),
          ],
        );
      },
    );
  }

  void _showConnectDialog() {
    final addressController = TextEditingController();
    final portController = TextEditingController(text: '1716');
    final nameController = TextEditingController(text: 'Arch Linux Server');

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Connect by IP'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Enter the Tailscale IP and port of your Linux Link server.',
              style: Theme.of(context).textTheme.bodyMedium,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: nameController,
              decoration: const InputDecoration(
                labelText: 'Server Name',
                hintText: 'My Linux PC',
                prefixIcon: Icon(Icons.label),
                border: OutlineInputBorder(),
              ),
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: addressController,
              decoration: const InputDecoration(
                labelText: 'Tailscale IP',
                hintText: '100.x.x.x',
                prefixIcon: Icon(Icons.computer),
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.url,
              textInputAction: TextInputAction.next,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: portController,
              decoration: const InputDecoration(
                labelText: 'Port',
                hintText: '1716',
                prefixIcon: Icon(Icons.numbers),
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.number,
              textInputAction: TextInputAction.done,
            ),
            const SizedBox(height: 8),
            Text(
              'Tip: Your Arch Linux server IP is 100.66.52.120',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.primary,
                  ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          FilledButton.icon(
            onPressed: () {
              final name = nameController.text.trim();
              final address = addressController.text.trim();
              final portStr = portController.text.trim();
              if (address.isEmpty) return;
              final port = int.tryParse(portStr) ?? 1716;

              // Add as manual peer for future use
              ref.read(conn.manualPeersProvider.notifier).addPeer(
                    name.isEmpty ? address : name,
                    address,
                    port: port,
                  );

              Navigator.pop(ctx);
              _connectToIp(address, port);
            },
            icon: const Icon(Icons.link),
            label: const Text('Connect'),
          ),
        ],
      ),
    );
  }

  Future<void> _connectToIp(String address, int port) async {
    ref.read(conn.connectionStateProvider.notifier).state =
        conn.ConnectionState.connecting;

    try {
      debugPrint('Connecting to $address:$port...');
      final frbState = await bridge.rustApi.frbConnectToPeer(address, port);
      debugPrint('Connection result: $frbState');

      if (mounted) {
        final state = _mapFrbConnectionState(frbState);
        ref.read(conn.connectionStateProvider.notifier).state = state;

        switch (state) {
          case conn.ConnectionState.connected:
            debugPrint('Connected successfully, navigating to remote desktop');
            HistoryService.addRecord(ConnectionRecord(
              peerName: address,
              peerAddress: address,
              port: port,
              connectedAt: DateTime.now(),
            )).catchError((e) => debugPrint('History save error: $e'));
            context.go('/remote', extra: {'address': address, 'port': port});
          case conn.ConnectionState.connecting:
            break;
          case conn.ConnectionState.error:
            final errorMsg = frbState.when(
              connected: () => '',
              connecting: () => '',
              disconnected: () => '',
              error: (dto) => dto.message,
              );
              debugPrint('Connection error: $errorMsg');
              String userMessage = 'Failed to connect to $address:$port';

              // Find the error DTO for more granular check
              final errorDto = frbState.when(
                error: (e) => e,
                connected: () => null,
                connecting: () => null,
                disconnected: () => null,
              );

              if (errorDto != null && (errorDto.code == 2001 || errorDto.code == 2003)) {
              userMessage = 'Cannot reach server at $address:$port.\n\n'
                  'Make sure:\n'
                  '• The Linux Link server is running on your PC\n'
                  '• Tailscale is active on both devices\n'
                  '• No firewall is blocking port $port\n\n'
                  'Start the server with: linux-link-server start';
              } else if (errorMsg.isNotEmpty) {
              userMessage += '\n\n$errorMsg';
              }            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text(userMessage),
                duration: const Duration(seconds: 6),
                backgroundColor: Theme.of(context).colorScheme.error,
              ),
            );
          case conn.ConnectionState.disconnected:
            break;
        }
      }
    } catch (e, stackTrace) {
      debugPrint('Connection exception: $e');
      debugPrint('Stack trace: $stackTrace');
      if (mounted) {
        ref.read(conn.connectionStateProvider.notifier).state =
            conn.ConnectionState.error;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Connection error: $e'),
            duration: const Duration(seconds: 6),
            backgroundColor: Theme.of(context).colorScheme.error,
          ),
        );
      }
    }
  }

  conn.ConnectionState _mapFrbConnectionState(frb.ConnectionState state) {
    return state.when(
      connected: () => conn.ConnectionState.connected,
      disconnected: () => conn.ConnectionState.disconnected,
      connecting: () => conn.ConnectionState.connecting,
      error: (_) => conn.ConnectionState.error,
    );
  }

  @override
  void initState() {
    super.initState();
    _refreshPeers();
  }

  @override
  Widget build(BuildContext context) {
    final discoveredPeers = ref.watch(conn.peersProvider);
    final manualPeers = ref.watch(conn.manualPeersProvider);
    final connectionState = ref.watch(conn.connectionStateProvider);
    final bookmarks = ref.watch(bookmarksProvider);

    // Combine discovered and manual peers
    final allPeers = [...manualPeers, ...discoveredPeers];

    // Split peers into bookmarked and unbookmarked
    final favoritePeers =
        allPeers.where((p) => bookmarks.any((b) => b.name == p.name)).toList();
    final otherPeers =
        allPeers.where((p) => !bookmarks.any((b) => b.name == p.name)).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Linux Link'),
        actions: [
          // Recent connections / history button
          IconButton(
            icon: const Icon(Icons.history),
            onPressed: () {
              context.push('/history');
            },
            tooltip: 'Connection history',
          ),
          // Settings button
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              context.push('/settings');
            },
            tooltip: 'Settings',
          ),
          if (_isLoading)
            const Padding(
              padding: EdgeInsets.all(12),
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
          if (connectionState != conn.ConnectionState.disconnected)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              color: switch (connectionState) {
                conn.ConnectionState.connecting =>
                  Colors.orange.withValues(alpha: 0.1),
                conn.ConnectionState.connected =>
                  Colors.green.withValues(alpha: 0.1),
                conn.ConnectionState.error => Colors.red.withValues(alpha: 0.1),
                conn.ConnectionState.disconnected => Colors.transparent,
              },
              child: Row(
                children: [
                  switch (connectionState) {
                    conn.ConnectionState.connecting => const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      ),
                    conn.ConnectionState.connected =>
                      const Icon(Icons.check_circle, color: Colors.green),
                    conn.ConnectionState.error =>
                      const Icon(Icons.error, color: Colors.red),
                    conn.ConnectionState.disconnected =>
                      const SizedBox.shrink(),
                  },
                  const SizedBox(width: 8),
                  Text(
                    switch (connectionState) {
                      conn.ConnectionState.connecting => 'Connecting...',
                      conn.ConnectionState.connected => 'Connected',
                      conn.ConnectionState.error => 'Connection error',
                      conn.ConnectionState.disconnected => '',
                    },
                    style: Theme.of(context).textTheme.bodyMedium,
                  ),
                ],
              ),
            ),
          // Peer list
          Expanded(
            child: allPeers.isEmpty
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
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 32),
                          child: Text(
                            'Tailscale peer discovery is unavailable on Android. '
                            'Connect directly using your server\'s Tailscale IP.',
                            textAlign: TextAlign.center,
                            style: Theme.of(context)
                                .textTheme
                                .bodyMedium
                                ?.copyWith(
                                  color: Theme.of(context)
                                      .colorScheme
                                      .onSurfaceVariant,
                                ),
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
                        const SizedBox(height: 12),
                        OutlinedButton.icon(
                          onPressed: _showConnectDialog,
                          icon: const Icon(Icons.link),
                          label: const Text('Connect by IP'),
                        ),
                      ],
                    ),
                  )
                : ListView(
                    children: [
                      // Favorites section
                      if (favoritePeers.isNotEmpty) ...[
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                          child: Row(
                            children: [
                              const Icon(
                                Icons.star,
                                size: 16,
                                color: Colors.amber,
                              ),
                              const SizedBox(width: 6),
                              Text(
                                'Favorites',
                                style: Theme.of(context)
                                    .textTheme
                                    .titleSmall
                                    ?.copyWith(
                                      color:
                                          Theme.of(context).colorScheme.primary,
                                      fontWeight: FontWeight.w600,
                                    ),
                              ),
                            ],
                          ),
                        ),
                        ...favoritePeers.map(
                          (peer) => _buildPeerTile(peer, isBookmarked: true),
                        ),
                        const Divider(indent: 16, endIndent: 16),
                      ],
                      // All peers section
                      if (otherPeers.isNotEmpty && favoritePeers.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
                          child: Row(
                            children: [
                              Icon(
                                Icons.group,
                                size: 16,
                                color: Theme.of(context)
                                    .colorScheme
                                    .onSurfaceVariant,
                              ),
                              const SizedBox(width: 6),
                              Text(
                                'All Peers',
                                style: Theme.of(context)
                                    .textTheme
                                    .titleSmall
                                    ?.copyWith(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .onSurfaceVariant,
                                    ),
                              ),
                            ],
                          ),
                        ),
                      ...otherPeers.map(
                        (peer) => _buildPeerTile(peer, isBookmarked: false),
                      ),
                      // Empty state for other peers when all are favorited
                      if (otherPeers.isEmpty && favoritePeers.isNotEmpty)
                        Padding(
                          padding: const EdgeInsets.all(24),
                          child: Center(
                            child: Text(
                              'All peers are favorited',
                              style: Theme.of(context)
                                  .textTheme
                                  .bodySmall
                                  ?.copyWith(
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant,
                                  ),
                            ),
                          ),
                        ),
                    ],
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildPeerTile(PeerInfo peer, {required bool isBookmarked}) {
    return Stack(
      children: [
        PeerListTile(
          peer: peer,
          onTap: peer.online ? () => _connectToPeer(peer) : null,
        ),
        // Wake button (only for offline peers)
        if (!peer.online)
          Positioned(
            right: 40,
            top: 0,
            bottom: 0,
            child: Center(
              child: IconButton(
                icon: const Icon(Icons.wifi_find, size: 20),
                color: Colors.orange,
                onPressed: () => _wakePeer(peer),
                tooltip: 'Wake on LAN',
                splashRadius: 16,
              ),
            ),
          ),
        // Bookmark star button
        Positioned(
          right: peer.online ? 40 : 80,
          top: 0,
          bottom: 0,
          child: Center(
            child: IconButton(
              icon: Icon(
                isBookmarked ? Icons.star : Icons.star_border,
                size: 20,
                color: isBookmarked ? Colors.amber : Colors.white24,
              ),
              onPressed: () => _toggleBookmark(peer),
              tooltip:
                  isBookmarked ? 'Remove from favorites' : 'Add to favorites',
              splashRadius: 16,
            ),
          ),
        ),
      ],
    );
  }
}
