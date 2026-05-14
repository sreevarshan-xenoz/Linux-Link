import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// A screen that shows the server's certificate fingerprint on first connect
/// and asks the user to Accept or Reject.
///
/// Also shows a "Trusted Devices" list with un-trust option when accessed
/// from settings.
class TrustScreen extends StatefulWidget {
  /// The server address to verify.
  final String address;

  /// The server's certificate fingerprint (SHA-256 hex string).
  final String fingerprint;

  /// Called when the user accepts the fingerprint.
  final VoidCallback? onAccept;

  /// Called when the user rejects the fingerprint.
  final VoidCallback? onReject;

  /// If true, shows the trusted devices management view instead of first-connect.
  final bool showTrustedDevices;

  const TrustScreen({
    super.key,
    required this.address,
    required this.fingerprint,
    this.onAccept,
    this.onReject,
    this.showTrustedDevices = false,
  });

  @override
  State<TrustScreen> createState() => _TrustScreenState();
}

class _TrustScreenState extends State<TrustScreen> {
  bool _expandedFingerprint = false;
  final List<_TrustedDevice> _trustedDevices = [];

  static const _trustedDevicesKey = 'trusted_devices';

  @override
  void initState() {
    super.initState();
    if (widget.showTrustedDevices) {
      _loadTrustedDevices();
    }
  }

  Future<void> _loadTrustedDevices() async {
    final prefs = await SharedPreferences.getInstance();
    final devicesJson = prefs.getStringList(_trustedDevicesKey) ?? [];
    setState(() {
      _trustedDevices.clear();
      for (final json in devicesJson) {
        final parts = json.split('|');
        if (parts.length >= 3) {
          _trustedDevices.add(_TrustedDevice(
            address: parts[0],
            name: parts[1],
            fingerprint: parts[2],
            trustedAt: DateTime.tryParse(parts[3]) ?? DateTime.now(),
          ));
        }
      }
    });
  }

  Future<void> _saveTrustedDevices() async {
    final prefs = await SharedPreferences.getInstance();
    final devicesJson = _trustedDevices
        .map((d) => '${d.address}|${d.name}|${d.fingerprint}|${d.trustedAt.toIso8601String()}')
        .toList();
    await prefs.setStringList(_trustedDevicesKey, devicesJson);
  }

  Future<void> _removeDevice(int index) async {
    setState(() {
      _trustedDevices.removeAt(index);
    });
    await _saveTrustedDevices();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Device removed from trusted list'),
          duration: Duration(seconds: 2),
        ),
      );
    }
  }

  Future<void> _saveTrust(String action) async {
    if (action == 'accept' && widget.onAccept != null) {
      // Save this device as trusted
      final prefs = await SharedPreferences.getInstance();
      final devicesJson = prefs.getStringList(_trustedDevicesKey) ?? [];
      // Check if already exists
      final alreadyTrusted = devicesJson.any((d) => d.startsWith('${widget.address}|'));
      if (!alreadyTrusted) {
        devicesJson.add('${widget.address}|${widget.address}|${widget.fingerprint}|${DateTime.now().toIso8601String()}');
        await prefs.setStringList(_trustedDevicesKey, devicesJson);
      }
      widget.onAccept!();
    } else if (widget.onReject != null) {
      widget.onReject!();
    }
  }

  /// Format raw hex bytes as colon-separated pairs for display.
  String _formatFingerprint(String hex) {
    final cleaned = hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    final buffer = StringBuffer();
    for (var i = 0; i < cleaned.length; i += 2) {
      if (i > 0) buffer.write(' ');
      if (i > 0 && i % 16 == 0) buffer.write('\n');
      buffer.write(cleaned.substring(i, (i + 2).clamp(0, cleaned.length)));
    }
    return buffer.toString().trim();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    if (widget.showTrustedDevices) {
      return _buildTrustedDevicesView(theme);
    }

    return _buildFirstConnectView(theme);
  }

  Widget _buildFirstConnectView(ThemeData theme) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: const Text('Verify Connection'),
        backgroundColor: Colors.black,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              const Spacer(flex: 1),
              // Shield icon with color coding
              Container(
                width: 80,
                height: 80,
                decoration: BoxDecoration(
                  color: Colors.blueAccent.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                ),
                child: const Icon(
                  Icons.shield_outlined,
                  size: 40,
                  color: Colors.blueAccent,
                ),
              ),
              const SizedBox(height: 24),
              Text(
                'First Connection',
                style: theme.textTheme.titleLarge?.copyWith(
                  color: Colors.white,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 8),
              Text(
                'This is the first time you are connecting to this device.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  color: Colors.white.withValues(alpha: 0.7),
                  fontSize: 14,
                ),
              ),
              const SizedBox(height: 24),
              // Server info card
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.05),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.white12),
                ),
                child: Column(
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.computer, size: 16, color: Colors.white54),
                        const SizedBox(width: 8),
                        Text(
                          'Server: ${widget.address}',
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    // Fingerprint section
                    GestureDetector(
                      onTap: () => setState(() => _expandedFingerprint = !_expandedFingerprint),
                      child: Row(
                        children: [
                          const Icon(Icons.fingerprint, size: 16, color: Colors.blueAccent),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              'Fingerprint (SHA-256):',
                              style: TextStyle(
                                color: Colors.blueAccent.withValues(alpha: 0.8),
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                          Icon(
                            _expandedFingerprint ? Icons.expand_less : Icons.expand_more,
                            size: 16,
                            color: Colors.white38,
                          ),
                        ],
                      ),
                    ),
                    if (_expandedFingerprint) ...[
                      const SizedBox(height: 8),
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.black,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(
                          _formatFingerprint(widget.fingerprint),
                          style: const TextStyle(
                            color: Colors.greenAccent,
                            fontSize: 11,
                            fontFamily: 'monospace',
                            height: 1.4,
                          ),
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Verify this fingerprint matches what you see on the server.',
                        style: TextStyle(
                          color: Colors.white.withValues(alpha: 0.5),
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 16),
              // Warning text
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orangeAccent.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.orangeAccent.withValues(alpha: 0.3)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.warning_amber, size: 16, color: Colors.orangeAccent),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Only accept this connection if you trust the remote device. '
                        'A mismatched fingerprint could indicate a man-in-the-middle attack.',
                        style: TextStyle(
                          color: Colors.orangeAccent.withValues(alpha: 0.9),
                          fontSize: 12,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const Spacer(flex: 2),
              // Action buttons
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton.icon(
                      onPressed: () => _saveTrust('reject'),
                      icon: const Icon(Icons.close, color: Colors.redAccent),
                      label: const Text(
                        'Reject',
                        style: TextStyle(color: Colors.redAccent),
                      ),
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: Colors.redAccent),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: FilledButton.icon(
                      onPressed: () => _saveTrust('accept'),
                      icon: const Icon(Icons.check),
                      label: const Text('Accept'),
                      style: FilledButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildTrustedDevicesView(ThemeData theme) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Trusted Devices'),
      ),
      body: _trustedDevices.isEmpty
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.shield_outlined,
                    size: 48,
                    color: theme.colorScheme.outline,
                  ),
                  const SizedBox(height: 16),
                  Text(
                    'No trusted devices',
                    style: theme.textTheme.titleMedium,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Devices you accept during connection will appear here',
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            )
          : ListView.builder(
              itemCount: _trustedDevices.length,
              itemBuilder: (context, index) {
                final device = _trustedDevices[index];
                return ListTile(
                  leading: const Icon(Icons.computer, color: Colors.green),
                  title: Text(
                    device.name,
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                  subtitle: Text(
                    '${device.address}\nTrusted: ${_formatDate(device.trustedAt)}',
                    style: const TextStyle(fontSize: 12),
                  ),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, color: Colors.redAccent),
                    tooltip: 'Remove trust',
                    onPressed: () => _confirmRemove(index),
                  ),
                );
              },
            ),
    );
  }

  Future<void> _confirmRemove(int index) async {
    final device = _trustedDevices[index];
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Trust'),
        content: Text(
          'Stop trusting ${device.name} (${device.address})?\n'
          'You will be prompted to verify the fingerprint on next connection.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: FilledButton.styleFrom(
              backgroundColor: Colors.redAccent,
            ),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await _removeDevice(index);
    }
  }

  String _formatDate(DateTime date) {
    return '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')} '
        '${date.hour.toString().padLeft(2, '0')}:${date.minute.toString().padLeft(2, '0')}';
  }
}

class _TrustedDevice {
  final String address;
  final String name;
  final String fingerprint;
  final DateTime trustedAt;

  const _TrustedDevice({
    required this.address,
    required this.name,
    required this.fingerprint,
    required this.trustedAt,
  });
}
