import 'package:flutter/material.dart';
import '../models/peer_info.dart';

class PeerListTile extends StatelessWidget {
  final PeerInfo peer;
  final VoidCallback? onTap;

  const PeerListTile({
    super.key,
    required this.peer,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return ListTile(
      leading: Stack(
        children: [
          const CircleAvatar(
            child: Icon(Icons.computer),
          ),
          Positioned(
            right: 0,
            bottom: 0,
            child: Container(
              width: 12,
              height: 12,
              decoration: BoxDecoration(
                color: peer.online ? Colors.green : Colors.red,
                shape: BoxShape.circle,
                border: Border.all(
                  color: Theme.of(context).scaffoldBackgroundColor,
                  width: 2,
                ),
              ),
            ),
          ),
        ],
      ),
      title: Text(peer.name),
      subtitle: Text(
        peer.ips.isNotEmpty ? peer.ips.join(', ') : 'No IP assigned',
        style: TextStyle(
          color: Theme.of(context).colorScheme.onSurfaceVariant,
        ),
      ),
      trailing: Icon(
        Icons.chevron_right,
        color: Theme.of(context).colorScheme.onSurfaceVariant,
      ),
      onTap: onTap,
    );
  }
}
