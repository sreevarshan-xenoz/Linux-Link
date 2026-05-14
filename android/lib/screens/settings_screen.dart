import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../rust_api_bridge.dart' as bridge;

enum VideoQuality { ultraLow, low, balanced, high, ultraHigh, custom }

/// Custom quality configuration for the streaming session.
class CustomQuality {
  final int bitrateKbps;
  final int targetFps;
  final int width;
  final int height;

  const CustomQuality({
    this.bitrateKbps = 5000,
    this.targetFps = 30,
    this.width = 1280,
    this.height = 720,
  });

  Map<String, dynamic> toJson() => {
        'bitrateKbps': bitrateKbps,
        'targetFps': targetFps,
        'width': width,
        'height': height,
      };

  factory CustomQuality.fromJson(Map<String, dynamic> json) => CustomQuality(
        bitrateKbps: json['bitrateKbps'] as int? ?? 5000,
        targetFps: json['targetFps'] as int? ?? 30,
        width: json['width'] as int? ?? 1280,
        height: json['height'] as int? ?? 720,
      );
}

/// Resolution presets for custom mode.
class ResolutionPreset {
  final String label;
  final int width;
  final int height;

  const ResolutionPreset(this.label, this.width, this.height);

  static const List<ResolutionPreset> presets = [
    ResolutionPreset('480p (854×480)', 854, 480),
    ResolutionPreset('720p (1280×720)', 1280, 720),
    ResolutionPreset('1080p (1920×1080)', 1920, 1080),
    ResolutionPreset('1440p (2560×1440)', 2560, 1440),
  ];
}

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
  CustomQuality _customQuality = const CustomQuality();
  bool _clipboardAutoSync = false;

  static const _keyTailscaleEnabled = 'tailscale_enabled';
  static const _keyVideoQuality = 'video_quality';
  static const _keyInputMode = 'input_mode';
  static const _keyConnectionTimeout = 'connection_timeout';
  static const _keyCustomQuality = 'custom_quality';
  static const _keyClipboardAutoSync = 'clipboard_auto_sync';

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
      _videoQuality = VideoQuality.values.firstWhere(
          (e) => e.name == prefs.getString(_keyVideoQuality),
          orElse: () => VideoQuality.high);
      _inputMode = InputMode.values.firstWhere(
          (e) => e.name == prefs.getString(_keyInputMode),
          orElse: () => InputMode.trackpad);
      _connectionTimeout = prefs.getInt(_keyConnectionTimeout) ?? 30;
      _clipboardAutoSync = prefs.getBool(_keyClipboardAutoSync) ?? false;
      final customJson = prefs.getString(_keyCustomQuality);
      if (customJson != null) {
        try {
          _customQuality = CustomQuality.fromJson(
            const JsonDecoder().convert(customJson) as Map<String, dynamic>,
          );
        } catch (_) {
          _customQuality = const CustomQuality();
        }
      }
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

  Future<void> _saveCustomQuality(CustomQuality quality) async {
    _customQuality = quality;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_keyCustomQuality, const JsonEncoder().convert(quality.toJson()));
  }

  Future<void> _loadVersion() async {
    try {
      final version = await bridge.rustApi.version();
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
      final isReady = await bridge.rustApi.checkTailscaleStatus();
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

  Widget _buildCustomQualitySection(ThemeData theme) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Container(
        decoration: BoxDecoration(
          color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: theme.colorScheme.primary.withValues(alpha: 0.2),
          ),
        ),
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.tune, size: 16, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  'Custom Quality Settings',
                  style: theme.textTheme.titleSmall?.copyWith(
                    color: theme.colorScheme.primary,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            // Bitrate slider
            Text(
              'Bitrate: ${_customQuality.bitrateKbps} Kbps',
              style: const TextStyle(fontSize: 13),
            ),
            Slider(
              value: _customQuality.bitrateKbps.toDouble(),
              min: 500,
              max: 50000,
              divisions: 99,
              label: '${_customQuality.bitrateKbps} Kbps',
              onChanged: (value) {
                setState(() {
                  _customQuality = CustomQuality(
                    bitrateKbps: value.round(),
                    targetFps: _customQuality.targetFps,
                    width: _customQuality.width,
                    height: _customQuality.height,
                  );
                });
                _saveCustomQuality(_customQuality);
              },
            ),
            const SizedBox(height: 4),
            // FPS selector
            Text(
              'Target FPS: ${_customQuality.targetFps}',
              style: const TextStyle(fontSize: 13),
            ),
            Slider(
              value: _customQuality.targetFps.toDouble(),
              min: 10,
              max: 60,
              divisions: 10,
              label: '${_customQuality.targetFps} FPS',
              onChanged: (value) {
                setState(() {
                  _customQuality = CustomQuality(
                    bitrateKbps: _customQuality.bitrateKbps,
                    targetFps: value.round(),
                    width: _customQuality.width,
                    height: _customQuality.height,
                  );
                });
                _saveCustomQuality(_customQuality);
              },
            ),
            const SizedBox(height: 4),
            // Resolution dropdown
            Text(
              'Resolution: ${_customQuality.width}×${_customQuality.height}',
              style: const TextStyle(fontSize: 13),
            ),
            DropdownButtonFormField<ResolutionPreset>(
              initialValue: ResolutionPreset.presets.firstWhere(
                (r) => r.width == _customQuality.width && r.height == _customQuality.height,
                orElse: () => ResolutionPreset.presets[1],
              ),
              decoration: const InputDecoration(
                isDense: true,
                contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                border: OutlineInputBorder(),
              ),
              items: ResolutionPreset.presets
                  .map((r) => DropdownMenuItem(
                        value: r,
                        child: Text(r.label, style: const TextStyle(fontSize: 13)),
                      ))
                  .toList(),
              onChanged: (ResolutionPreset? preset) {
                if (preset != null) {
                  setState(() {
                    _customQuality = CustomQuality(
                      bitrateKbps: _customQuality.bitrateKbps,
                      targetFps: _customQuality.targetFps,
                      width: preset.width,
                      height: preset.height,
                    );
                  });
                  _saveCustomQuality(_customQuality);
                }
              },
            ),
            const SizedBox(height: 8),
            // Summary
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: theme.colorScheme.tertiaryContainer.withValues(alpha: 0.3),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, size: 14, color: theme.colorScheme.tertiary),
                  const SizedBox(width: 6),
                  Expanded(
                    child: Text(
                      'Requires ~${_customQuality.bitrateKbps ~/ 1000}.${(_customQuality.bitrateKbps % 1000) ~/ 100} Mbps bandwidth',
                      style: TextStyle(
                        fontSize: 11,
                        color: theme.colorScheme.tertiary,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
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
          RadioGroup<VideoQuality>(
            groupValue: _videoQuality,
            onChanged: (VideoQuality? value) {
              if (value != null) {
                setState(() {
                  _videoQuality = value;
                });
                _saveSetting(_keyVideoQuality, value.name);
              }
            },
            child: const Column(
              children: [
                RadioListTile<VideoQuality>(
                  title: Text('Ultra Low'),
                  subtitle: Text('480p, 15 FPS, 1 Mbps'),
                  value: VideoQuality.ultraLow,
                ),
                RadioListTile<VideoQuality>(
                  title: Text('Low'),
                  subtitle: Text('480p, 24 FPS, 2 Mbps'),
                  value: VideoQuality.low,
                ),
                RadioListTile<VideoQuality>(
                  title: Text('Balanced'),
                  subtitle: Text('720p, 30 FPS, 5 Mbps'),
                  value: VideoQuality.balanced,
                ),
                RadioListTile<VideoQuality>(
                  title: Text('High'),
                  subtitle: Text('1080p, 30 FPS, 10 Mbps'),
                  value: VideoQuality.high,
                ),
                RadioListTile<VideoQuality>(
                  title: Text('Ultra High'),
                  subtitle: Text('1080p, 60 FPS, 20 Mbps'),
                  value: VideoQuality.ultraHigh,
                ),
                RadioListTile<VideoQuality>(
                  title: Text('Custom'),
                  subtitle: Text('Manual bitrate, resolution & FPS'),
                  value: VideoQuality.custom,
                ),
              ],
            ),
          ),
          // Custom quality configuration (only shown when 'Custom' is selected)
          if (_videoQuality == VideoQuality.custom)
            _buildCustomQualitySection(theme),
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
          RadioGroup<InputMode>(
            groupValue: _inputMode,
            onChanged: (InputMode? value) {
              if (value != null) {
                setState(() {
                  _inputMode = value;
                });
                _saveSetting(_keyInputMode, value.name);
              }
            },
            child: const Column(
              children: [
                RadioListTile<InputMode>(
                  title: Text('Trackpad'),
                  subtitle: Text('Relative movement, like a laptop trackpad'),
                  value: InputMode.trackpad,
                ),
                RadioListTile<InputMode>(
                  title: Text('Touch'),
                  subtitle: Text('Direct touch on screen'),
                  value: InputMode.touch,
                ),
                RadioListTile<InputMode>(
                  title: Text('Mouse'),
                  subtitle: Text('External mouse via Bluetooth/USB'),
                  value: InputMode.mouse,
                ),
              ],
            ),
          ),
          const Divider(),
          // F26: Trusted Devices
          ListTile(
            leading: const Icon(Icons.shield_outlined),
            title: const Text('Trusted Devices'),
            subtitle: const Text('Manage trusted certificate fingerprints'),
            trailing: const Icon(Icons.chevron_right),
            onTap: () {
              Navigator.of(context).pushNamed('/trust', arguments: {
                'address': '',
                'fingerprint': '',
                'showTrustedDevices': true,
              });
            },
          ),
          const Divider(),
          // Clipboard auto-sync
          ListTile(
            leading: const Icon(Icons.content_copy),
            title: const Text('Clipboard Auto-Sync'),
            subtitle: const Text('Sync clipboard between devices automatically'),
            trailing: Switch(
              value: _clipboardAutoSync,
              onChanged: (value) {
                setState(() {
                  _clipboardAutoSync = value;
                });
                _saveSetting(_keyClipboardAutoSync, value);
              },
            ),
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
