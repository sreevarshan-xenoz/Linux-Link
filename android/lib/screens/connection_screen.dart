import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/peer_info.dart';
import '../providers/connection_provider.dart' as conn;
import '../providers/bookmarks_provider.dart';
import '../widgets/peer_list_tile.dart';
import '../rust_api_bridge.dart' as bridge;
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
            // Record connection in history
            HistoryService.addRecord(ConnectionRecord(
              peerName: peer.name,
              peerAddress: address,
              port: port,
              connectedAt: DateTime.now(),
            ));
            Navigator.of(context).pushNamed(
              '/remote',
              arguments: {'address': address, 'port': port},
            );
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

  @override
  void initState() {
    super.initState();
    _refreshPeers();
  }

  @override
  Widget build(BuildContext context) {
    final peers = ref.watch(conn.peersProvider);
    final connectionState = ref.watch(conn.connectionStateProvider);
    final bookmarks = ref.watch(bookmarksProvider);

    // Split peers into bookmarked and unbookmarked
    final favoritePeers = peers
        .where((p) => bookmarks.any((b) => b.name == p.name))
        .toList();
    final otherPeers =
        peers.where((p) => !bookmarks.any((b) => b.name == p.name)).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('Linux Link'),
        actions: [
          // Recent connections / history button
          IconButton(
            icon: const Icon(Icons.history),
            onPressed: () {
              Navigator.of(context).pushNamed('/history');
            },
            tooltip: 'Connection history',
          ),
          // Settings button
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.of(context).pushNamed('/settings');
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
                          style:
                              Theme.of(context).textTheme.bodyMedium?.copyWith(
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant,
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
                                      color: Theme.of(context)
                                          .colorScheme
                                          .primary,
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
        // Bookmark star button
        Positioned(
          right: 40,
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
              tooltip: isBookmarked ? 'Remove from favorites' : 'Add to favorites',
              splashRadius: 16,
            ),
          ),
        ),
      ],
    );
  }
}
