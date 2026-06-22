import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/streaming_provider.dart';

/// Control bar overlay for the remote desktop screen.
///
/// Provides buttons for disconnect, fullscreen, stats, zoom, terminal,
/// file browser, power, recording, keyboard, rotation, and shortcuts.
class RemoteDesktopControlBar extends ConsumerWidget {
  final bool isFullscreen;
  final bool showStats;
  final bool keyboardMode;
  final int recordingDuration;
  final bool showShortcuts;
  final VoidCallback onDisconnect;
  final VoidCallback onToggleFullscreen;
  final VoidCallback onToggleStats;
  final VoidCallback onResetZoom;
  final VoidCallback onOpenTerminal;
  final VoidCallback onOpenFileBrowser;
  final ValueChanged<String> onSendPowerCommand;
  final VoidCallback onToggleRecording;
  final VoidCallback onToggleKeyboardMode;
  final VoidCallback onCycleRotation;
  final VoidCallback onToggleShortcuts;
  final VoidCallback onToggleClipboardHistory;

  const RemoteDesktopControlBar({
    super.key,
    required this.isFullscreen,
    required this.showStats,
    required this.keyboardMode,
    required this.recordingDuration,
    required this.showShortcuts,
    required this.onDisconnect,
    required this.onToggleFullscreen,
    required this.onToggleStats,
    required this.onResetZoom,
    required this.onOpenTerminal,
    required this.onOpenFileBrowser,
    required this.onSendPowerCommand,
    required this.onToggleRecording,
    required this.onToggleKeyboardMode,
    required this.onCycleRotation,
    required this.onToggleShortcuts,
    required this.onToggleClipboardHistory,
  });

  String _formatDuration(int seconds) {
    final m = (seconds ~/ 60).toString().padLeft(2, '0');
    final s = (seconds % 60).toString().padLeft(2, '0');
    return '$m:$s';
  }

  IconData _rotationIcon(RotationMode mode) {
    return switch (mode) {
      RotationMode.auto => Icons.screen_rotation,
      RotationMode.portrait => Icons.screen_lock_portrait,
      RotationMode.landscape => Icons.screen_lock_landscape,
      RotationMode.rotated180 => Icons.flip_to_back,
    };
  }

  String _rotationTooltip(RotationMode mode) {
    return switch (mode) {
      RotationMode.auto => 'Auto rotation',
      RotationMode.portrait => 'Portrait',
      RotationMode.landscape => 'Landscape',
      RotationMode.rotated180 => 'Rotated 180\u00b0',
    };
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isRecording = ref.watch(isRecordingProvider);
    final rotationMode = ref.watch(rotationModeProvider);

    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          FilledButton.tonalIcon(
            onPressed: onDisconnect,
            icon: const Icon(Icons.power_settings_new),
            label: const Text('Disconnect'),
            style: FilledButton.styleFrom(
              backgroundColor: Colors.red.withValues(alpha: 0.8),
            ),
          ),
          const SizedBox(width: 8),
          IconButton.filledTonal(
            onPressed: onToggleFullscreen,
            icon: Icon(
              isFullscreen ? Icons.fullscreen_exit : Icons.fullscreen,
            ),
            tooltip: 'Toggle fullscreen',
          ),
          IconButton.filledTonal(
            onPressed: onToggleStats,
            icon: const Icon(Icons.bar_chart),
            isSelected: showStats,
            tooltip: 'Stream stats',
          ),
          IconButton.filledTonal(
            onPressed: onResetZoom,
            icon: const Icon(Icons.zoom_out_map),
            tooltip: 'Reset zoom',
          ),
          IconButton.filledTonal(
            onPressed: onOpenTerminal,
            icon: const Icon(Icons.terminal),
            tooltip: 'Remote terminal',
          ),
          IconButton.filledTonal(
            onPressed: onOpenFileBrowser,
            icon: const Icon(Icons.folder),
            tooltip: 'File browser',
          ),
          PopupMenuButton<String>(
            onSelected: onSendPowerCommand,
            itemBuilder: (ctx) => [
              const PopupMenuItem(
                value: 'sleep',
                child: ListTile(
                  leading: Icon(Icons.bedtime_outlined),
                  title: Text('Sleep'),
                  subtitle: Text('Suspend to RAM'),
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem(
                value: 'shutdown',
                child: ListTile(
                  leading: Icon(Icons.power_settings_new, color: Colors.redAccent),
                  title: Text('Shutdown'),
                  subtitle: Text('Power off the PC'),
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem(
                value: 'restart',
                child: ListTile(
                  leading: Icon(Icons.restart_alt),
                  title: Text('Restart'),
                  subtitle: Text('Reboot the PC'),
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              ),
              const PopupMenuItem(
                value: 'hibernate',
                child: ListTile(
                  leading: Icon(Icons.nightlight_outlined),
                  title: Text('Hibernate'),
                  subtitle: Text('Save state & power off'),
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              ),
            ],
            child: const Icon(Icons.power_settings_new),
          ),
          IconButton.filledTonal(
            onPressed: onToggleRecording,
            icon: Icon(
              isRecording ? Icons.stop_circle : Icons.fiber_manual_record,
            ),
            style: IconButton.styleFrom(
              backgroundColor: isRecording
                  ? Colors.red.withValues(alpha: 0.8)
                  : null,
            ),
            tooltip: isRecording
                ? 'Stop recording (${_formatDuration(recordingDuration)})'
                : 'Record session',
          ),
          const SizedBox(width: 8),
          IconButton.filledTonal(
            onPressed: onToggleKeyboardMode,
            icon: Icon(
              keyboardMode ? Icons.keyboard : Icons.keyboard_alt_outlined,
            ),
            style: IconButton.styleFrom(
              backgroundColor: keyboardMode
                  ? Theme.of(context).colorScheme.primary.withValues(alpha: 0.3)
                  : null,
            ),
            tooltip: keyboardMode ? 'Keyboard mode active' : 'Toggle keyboard',
          ),
          IconButton.filledTonal(
            onPressed: onCycleRotation,
            icon: Icon(_rotationIcon(rotationMode)),
            tooltip: _rotationTooltip(rotationMode),
          ),
          IconButton.filledTonal(
            onPressed: onToggleClipboardHistory,
            icon: const Icon(Icons.history),
            tooltip: 'Clipboard history',
          ),
          IconButton.filledTonal(
            onPressed: onToggleShortcuts,
            icon: const Icon(Icons.keyboard_command_key),
            isSelected: showShortcuts,
            tooltip: 'Keyboard shortcuts',
          ),
        ],
      ),
    );
  }
}
