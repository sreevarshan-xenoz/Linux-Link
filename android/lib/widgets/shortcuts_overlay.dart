import 'package:flutter/material.dart';

/// A categorized keyboard shortcuts overlay for the remote desktop screen.
///
/// Triggered by a button in the overlay controls. Displays common shortcuts
/// organized by category. Tapping a shortcut sends the key combination
/// to the remote PC.
class ShortcutsOverlay extends StatelessWidget {
  final VoidCallback onDismiss;
  final void Function(String shortcut) onExecute;

  const ShortcutsOverlay({
    super.key,
    required this.onDismiss,
    required this.onExecute,
  });

  static const _shortcuts = <String, List<_ShortcutEntry>>{
    'Navigation': [
      _ShortcutEntry('Alt + Tab', 'Switch windows'),
      _ShortcutEntry('Alt + Shift + Tab', 'Switch windows (reverse)'),
      _ShortcutEntry('Alt + F4', 'Close window'),
      _ShortcutEntry('Super + D', 'Show desktop'),
      _ShortcutEntry('Super + Tab', 'Switch workspaces'),
    ],
    'Editing': [
      _ShortcutEntry('Ctrl + C', 'Copy'),
      _ShortcutEntry('Ctrl + V', 'Paste'),
      _ShortcutEntry('Ctrl + X', 'Cut'),
      _ShortcutEntry('Ctrl + Z', 'Undo'),
      _ShortcutEntry('Ctrl + Shift + Z', 'Redo'),
      _ShortcutEntry('Ctrl + A', 'Select all'),
      _ShortcutEntry('Ctrl + S', 'Save'),
    ],
    'System': [
      _ShortcutEntry('Super + L', 'Lock screen'),
      _ShortcutEntry('Ctrl + Alt + T', 'Open terminal'),
      _ShortcutEntry('Ctrl + Alt + Delete', 'System menu'),
      _ShortcutEntry('PrtSc', 'Screenshot'),
      _ShortcutEntry('Alt + PrtSc', 'Window screenshot'),
    ],
    'Browser': [
      _ShortcutEntry('Ctrl + T', 'New tab'),
      _ShortcutEntry('Ctrl + W', 'Close tab'),
      _ShortcutEntry('Ctrl + Shift + T', 'Reopen closed tab'),
      _ShortcutEntry('Ctrl + Tab', 'Next tab'),
      _ShortcutEntry('Ctrl + Shift + Tab', 'Previous tab'),
      _ShortcutEntry('F5', 'Refresh'),
    ],
  };

  /// Map shortcut display string to the text we send to the Rust backend.
  static String shortcutToText(String display) {
    return switch (display) {
      'Alt + Tab' => '\t',
      'Alt + Shift + Tab' => '\t',
      'Alt + F4' => '\t',
      'Super + D' => '\t',
      'Super + Tab' => '\t',
      'Ctrl + C' => '\x03',
      'Ctrl + V' => '\x16',
      'Ctrl + X' => '\x18',
      'Ctrl + Z' => '\x1a',
      'Ctrl + Shift + Z' => '\x1a',
      'Ctrl + A' => '\x01',
      'Ctrl + S' => '\x13',
      'Super + L' => '\t',
      'Ctrl + Alt + T' => '\t',
      'Ctrl + Alt + Delete' => '\t',
      'PrtSc' => '\t',
      'Alt + PrtSc' => '\t',
      'Ctrl + T' => '\x14',
      'Ctrl + W' => '\x17',
      'Ctrl + Shift + T' => '\x14',
      'Ctrl + Tab' => '\t',
      'Ctrl + Shift + Tab' => '\t',
      'F5' => '\t',
      _ => display,
    };
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Material(
      color: Colors.black87,
      child: SafeArea(
        child: Column(
          children: [
            // Header
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
              child: Row(
                children: [
                  Icon(
                    Icons.keyboard,
                    size: 20,
                    color: theme.colorScheme.primary,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    'Keyboard Shortcuts',
                    style: theme.textTheme.titleMedium?.copyWith(
                      color: theme.colorScheme.primary,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  const Spacer(),
                  IconButton(
                    onPressed: onDismiss,
                    icon: const Icon(Icons.close, color: Colors.white54),
                    tooltip: 'Close',
                  ),
                ],
              ),
            ),
            const Divider(color: Colors.white24),
            // Grid of shortcut categories
            Expanded(
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: _shortcuts.entries.map((entry) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          entry.key,
                          style: theme.textTheme.titleSmall?.copyWith(
                            color: theme.colorScheme.primary.withValues(alpha: 0.8),
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: entry.value.map((shortcut) {
                            return ActionChip(
                              avatar: Icon(
                                Icons.keyboard_command_key,
                                size: 14,
                                color: theme.colorScheme.primary,
                              ),
                              label: Text(
                                shortcut.label,
                                style: const TextStyle(
                                  fontSize: 11,
                                  fontFamily: 'monospace',
                                ),
                              ),
                              tooltip: shortcut.description,
                              onPressed: () {
                                onExecute(shortcut.label);
                              },
                            );
                          }).toList(),
                        ),
                      ],
                    ),
                  );
                }).toList(),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _ShortcutEntry {
  final String label;
  final String description;

  const _ShortcutEntry(this.label, this.description);
}
