import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../providers/clipboard_history_provider.dart';
import '../services/clipboard_service.dart';

/// Semi-transparent overlay that shows recent clipboard history entries.
///
/// Features:
/// - Scrollable list of clipboard entries (newest first, newest on bottom)
/// - Tap an entry to copy it to the local clipboard
/// - Close button and tap-outside-to-dismiss
/// - Shows preview and relative timestamp for each entry
class ClipboardHistoryOverlay extends ConsumerWidget {
  const ClipboardHistoryOverlay({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final history = ref.watch(clipboardHistoryProvider);

    return Stack(
      children: [
        // Dismiss overlay when tapping the background
        GestureDetector(
          onTap: () {
            ref.read(clipboardHistoryVisibleProvider.notifier).state = false;
          },
          child: Container(color: Colors.black45),
        ),
        // Overlay panel at the bottom
        Align(
          alignment: Alignment.bottomCenter,
          child: GestureDetector(
            onTap: () {}, // absorb tap
            child: Container(
              constraints: BoxConstraints(
                maxHeight: MediaQuery.of(context).size.height * 0.45,
              ),
              margin: const EdgeInsets.fromLTRB(16, 0, 16, 80),
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .surfaceContainerHigh
                    .withValues(alpha: 0.95),
                borderRadius: BorderRadius.circular(16),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.3),
                    blurRadius: 16,
                    offset: const Offset(0, -4),
                  ),
                ],
              ),
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  // Header
                  _Header(
                    onClose: () {
                      ref.read(clipboardHistoryVisibleProvider.notifier).state =
                          false;
                    },
                    onClear: () {
                      ref.read(clipboardHistoryProvider.notifier).clear();
                    },
                    hasEntries: history.isNotEmpty,
                  ),
                  // Divider
                  Divider(
                    height: 1,
                    color: Theme.of(context)
                        .colorScheme
                        .outlineVariant
                        .withValues(alpha: 0.5),
                  ),
                  // Entry list
                  if (history.isEmpty)
                    const _EmptyState()
                  else
                    Flexible(
                      child: ListView.builder(
                        shrinkWrap: true,
                        padding: const EdgeInsets.symmetric(vertical: 4),
                        itemCount: history.length,
                        reverse: true, // newest first (last added shows at top)
                        itemBuilder: (context, index) {
                          // Since reversed, the visual index 0 = last element
                          final entry =
                              history[history.length - 1 - index];
                          return Material(
                            type: MaterialType.transparency,
                            child: _ClipboardEntryTile(
                              entry: entry,
                              index: index,
                              onTap: () async {
                                await ClipboardService.setClipboard(entry.text);
                                if (context.mounted) {
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(
                                      content: Text(
                                        'Copied: ${entry.preview}',
                                        overflow: TextOverflow.ellipsis,
                                      ),
                                      duration: const Duration(seconds: 2),
                                    ),
                                  );
                                }
                                ref.read(
                                        clipboardHistoryVisibleProvider.notifier)
                                    .state = false;
                              },
                            ),
                          );
                        },
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _Header extends StatelessWidget {
  final VoidCallback onClose;
  final VoidCallback onClear;
  final bool hasEntries;

  const _Header({
    required this.onClose,
    required this.onClear,
    required this.hasEntries,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(
        children: [
          const Icon(Icons.history, size: 20),
          const SizedBox(width: 8),
          const Text(
            'Clipboard History',
            style: TextStyle(
              fontWeight: FontWeight.w600,
              fontSize: 15,
            ),
          ),
          const Spacer(),
          if (hasEntries)
            IconButton(
              onPressed: onClear,
              icon: const Icon(Icons.delete_sweep_outlined, size: 20),
              tooltip: 'Clear history',
              visualDensity: VisualDensity.compact,
              style: IconButton.styleFrom(
                foregroundColor: Theme.of(context).colorScheme.error,
              ),
            ),
          IconButton(
            onPressed: onClose,
            icon: const Icon(Icons.close, size: 20),
            tooltip: 'Close',
            visualDensity: VisualDensity.compact,
          ),
        ],
      ),
    );
  }
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final muted = theme.colorScheme.onSurface.withValues(alpha: 0.45);
    final veryMuted = theme.colorScheme.onSurface.withValues(alpha: 0.32);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 32, horizontal: 24),
      child: Column(
        children: [
          Icon(Icons.content_paste_off_outlined,
              size: 40, color: veryMuted),
          const SizedBox(height: 12),
          Text(
            'No clipboard history yet',
            style: TextStyle(color: muted, fontSize: 14),
          ),
          const SizedBox(height: 4),
          Text(
            'Clipboard changes during this session\nwill appear here',
            textAlign: TextAlign.center,
            style: TextStyle(color: veryMuted, fontSize: 12),
          ),
        ],
      ),
    );
  }
}

class _ClipboardEntryTile extends StatelessWidget {
  final ClipboardEntry entry;
  final int index;
  final VoidCallback onTap;

  const _ClipboardEntryTile({
    required this.entry,
    required this.index,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final isMultiLine = entry.text.contains('\n');

    return InkWell(
      onTap: onTap,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Index badge
            Container(
              width: 24,
              height: 24,
              alignment: Alignment.center,
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .primaryContainer
                    .withValues(alpha: 0.4),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Text(
                '${index + 1}',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    entry.preview,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  const SizedBox(height: 2),
                  Row(
                    children: [
                      Text(
                        entry.relativeTime,
                        style: TextStyle(
                          fontSize: 11,
                          color: Theme.of(context)
                              .colorScheme
                              .onSurfaceVariant
                              .withValues(alpha: 0.6),
                        ),
                      ),
                      if (isMultiLine) ...[
                        const SizedBox(width: 8),
                        Icon(
                          Icons.library_books_outlined,
                          size: 12,
                          color: Theme.of(context)
                              .colorScheme
                              .onSurfaceVariant
                              .withValues(alpha: 0.4),
                        ),
                        const SizedBox(width: 2),
                        Text(
                          '${entry.text.split('\n').length} lines',
                          style: TextStyle(
                            fontSize: 11,
                            color: Theme.of(context)
                                .colorScheme
                                .onSurfaceVariant
                                .withValues(alpha: 0.4),
                          ),
                        ),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            const SizedBox(width: 4),
            Icon(
              Icons.copy_rounded,
              size: 16,
              color: Theme.of(context)
                  .colorScheme
                  .onSurfaceVariant
                  .withValues(alpha: 0.3),
            ),
          ],
        ),
      ),
    );
  }
}
