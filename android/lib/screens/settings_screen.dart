import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../rust_api_bridge.dart';

enum VideoQuality { low, medium, high }

enum InputMode { trackpad, touch, mouse }

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  bool _tailscaleEnabled = true;
  VideoQuality _videoQuality = VideoQuality.high;
  InputMode _inputMode = InputMode.trackpad;
  int _connectionTimeout = 30;
  String _version = '1.0.0';
  bool _isTestingConnection = false;

  static const _keyTailscaleEnabled = 'tailscale_enabled';
  static const _keyVideoQuality = 'video_quality';
  static const _keyInputMode = 'input_mode';
  static const _keyConnectionTimeout = 'connection_timeout';

  @override
  void initState() {
    super.initState();
    _loadSettings();
    _loadVersion();
  }

  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _tailscaleEnabled = prefs.getBool(_keyTailscaleEnabled) ?? true;
      _videoQuality = VideoQuality.values
          .firstWhere((e) => e.name == prefs.getString(_keyVideoQuality), orElse: () => VideoQuality.high);
      _inputMode = InputMode.values
          .firstWhere((e) => e.name == prefs.getString(_keyInputMode), orElse: () => InputMode.trackpad);
      _connectionTimeout = prefs.getInt(_keyConnectionTimeout) ?? 30;
    });
  }

  Future<void> _saveSetting(String key, dynamic value) async {
    final prefs = await SharedPreferences.getInstance();
    if (value is bool) {
      await prefs.setBool(key, value);
    } else if (value is String) {
      await prefs.setString(key, value);
    } else if (value is int) {
      await prefs.setInt(key, value);
    }
  }

  Future<void> _loadVersion() async {
    try {
      final version = await rustApi.version();
      if (mounted) {
        setState(() => _version = version);
      }
    } catch (e) {
      debugPrint('Failed to load version: $e');
    }
  }

  Future<void> _testConnection() async {
    setState(() => _isTestingConnection = true);
    try {
      final isReady = await rustApi.checkTailscaleStatus();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              isReady ? 'Tailscale is ready' : 'Tailscale is not ready',
            ),
            backgroundColor: isReady ? Colors.green : Colors.orange,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Connection test failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isTestingConnection = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        actions: [
          IconButton(
            icon: _isTestingConnection
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : const Icon(Icons.wifi_find),
            onPressed: _isTestingConnection ? null : _testConnection,
            tooltip: 'Test Tailscale connection',
          ),
        ],
      ),
      body: ListView(
        children: [
          // Tailscale section
          ListTile(
            leading: const Icon(Icons.vpn_key),
            title: const Text('Tailscale'),
            subtitle: const Text('Enable Tailscale connectivity'),
            trailing: Switch(
              value: _tailscaleEnabled,
              onChanged: (value) {
                setState(() {
                  _tailscaleEnabled = value;
                });
                _saveSetting(_keyTailscaleEnabled, value);
              },
            ),
          ),
          const Divider(),
          // Video quality
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'Video Quality',
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.primary,
              ),
            ),
          ),
          RadioListTile<VideoQuality>(
            title: const Text('High'),
            subtitle: const Text('1080p, higher bitrate'),
            value: VideoQuality.high,
            groupValue: _videoQuality,
            onChanged: (value) {
              setState(() {
                _videoQuality = value!;
              });
              _saveSetting(_keyVideoQuality, value.name);
            },
          ),
          RadioListTile<VideoQuality>(
            title: const Text('Medium'),
            subtitle: const Text('720p, balanced'),
            value: VideoQuality.medium,
            groupValue: _videoQuality,
            onChanged: (value) {
              setState(() {
                _videoQuality = value!;
              });
              _saveSetting(_keyVideoQuality, value.name);
            },
          ),
          RadioListTile<VideoQuality>(
            title: const Text('Low'),
            subtitle: const Text('480p, lower bandwidth'),
            value: VideoQuality.low,
            groupValue: _videoQuality,
            onChanged: (value) {
              setState(() {
                _videoQuality = value!;
              });
              _saveSetting(_keyVideoQuality, value.name);
            },
          ),
          const Divider(),
          // Input mode
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'Input Mode',
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.primary,
              ),
            ),
          ),
          RadioListTile<InputMode>(
            title: const Text('Trackpad'),
            subtitle: const Text('Relative movement, like a laptop trackpad'),
            value: InputMode.trackpad,
            groupValue: _inputMode,
            onChanged: (value) {
              setState(() {
                _inputMode = value!;
              });
              _saveSetting(_keyInputMode, value.name);
            },
          ),
          RadioListTile<InputMode>(
            title: const Text('Touch'),
            subtitle: const Text('Direct touch on screen'),
            value: InputMode.touch,
            groupValue: _inputMode,
            onChanged: (value) {
              setState(() {
                _inputMode = value!;
              });
              _saveSetting(_keyInputMode, value.name);
            },
          ),
          RadioListTile<InputMode>(
            title: const Text('Mouse'),
            subtitle: const Text('External mouse via Bluetooth/USB'),
            value: InputMode.mouse,
            groupValue: _inputMode,
            onChanged: (value) {
              setState(() {
                _inputMode = value!;
              });
              _saveSetting(_keyInputMode, value.name);
            },
          ),
          const Divider(),
          // Connection timeout
          ListTile(
            leading: const Icon(Icons.timer),
            title: const Text('Connection Timeout'),
            subtitle: Text('$_connectionTimeout seconds'),
            trailing: SizedBox(
              width: 120,
              child: Slider(
                value: _connectionTimeout.toDouble(),
                min: 5,
                max: 60,
                divisions: 11,
                label: '$_connectionTimeout s',
                onChanged: (value) {
                  setState(() {
                    _connectionTimeout = value.round();
                  });
                  _saveSetting(_keyConnectionTimeout, _connectionTimeout);
                },
              ),
            ),
          ),
          const Divider(),
          // About section
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
            child: Text(
              'About',
              style: theme.textTheme.titleSmall?.copyWith(
                color: theme.colorScheme.primary,
              ),
            ),
          ),
          ListTile(
            leading: const Icon(Icons.info_outline),
            title: const Text('Version'),
            subtitle: Text(_version),
          ),
          ListTile(
            leading: const Icon(Icons.code),
            title: const Text('Source Code'),
            subtitle: const Text('github.com/sreevarshan/Linux-Link'),
            trailing: const Icon(Icons.open_in_new, size: 18),
            onTap: () {
              // TODO: Open URL in browser
            },
          ),
        ],
      ),
    );
  }
}
