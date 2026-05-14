import 'dart:async';

import 'package:flutter/material.dart';
import '../rust_api_bridge.dart' as bridge;

/// A remote terminal screen that lets users execute shell commands on the
/// connected server and see stdout/stderr output in real-time.
class TerminalScreen extends StatefulWidget {
  final String address;
  final int port;

  const TerminalScreen({
    super.key,
    required this.address,
    required this.port,
  });

  @override
  State<TerminalScreen> createState() => _TerminalScreenState();
}

class _TerminalScreenState extends State<TerminalScreen> {
  final TextEditingController _inputController = TextEditingController();
  final ScrollController _scrollController = ScrollController();
  final List<_TerminalLine> _lines = [];
  final List<String> _history = [];
  int _historyIndex = -1;
  bool _isExecuting = false;

  @override
  void initState() {
    super.initState();
    _addLine(const _TerminalLine(
      text: 'Linux Link Remote Terminal',
      style: _LineStyle.header,
    ));
    _addLine(_TerminalLine(
      text: 'Connected to ${widget.address}:${widget.port}',
      style: _LineStyle.info,
    ));
    _addLine(const _TerminalLine(text: '', style: _LineStyle.normal));
  }

  @override
  void dispose() {
    _inputController.dispose();
    _scrollController.dispose();
    super.dispose();
  }

  void _addLine(_TerminalLine line) {
    setState(() => _lines.add(line));
    // Auto-scroll to bottom
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _executeCommand(String command) async {
    if (command.trim().isEmpty) return;

    setState(() => _isExecuting = true);

    // Show the command prompt and input
    _addLine(_TerminalLine(
      text: '\$ $command',
      style: _LineStyle.command,
    ));

    // Add to history
    _history.insert(0, command);
    if (_history.length > 50) _history.removeLast();
    _historyIndex = -1;
    _inputController.clear();

    try {
      final result = await bridge.rustApi.executeCommand(
        widget.address,
        widget.port,
        command,
      );

      // result format: "stdout\n---END-OUTPUT---\nstderr\n---END-ERROR---\nexit_code"
      final stdoutEnd = result.indexOf('\n---END-OUTPUT---\n');
      final stderrEnd = result.lastIndexOf('\n---END-ERROR---\n');

      String stdout = '';
      String stderr = '';
      int exitCode = 0;

      if (stdoutEnd >= 0) {
        stdout = result.substring(0, stdoutEnd);
      }
      if (stderrEnd >= 0 && stdoutEnd >= 0) {
        stderr = result.substring(
          stdoutEnd + '---END-OUTPUT---\n'.length,
          stderrEnd,
        );
      }
      if (stderrEnd >= 0) {
        final after = result.substring(stderrEnd + '---END-ERROR---\n'.length);
        exitCode = int.tryParse(after.trim()) ?? 0;
      }

      if (stdout.isNotEmpty) {
        _addLine(_TerminalLine(text: stdout, style: _LineStyle.stdout));
      }
      if (stderr.isNotEmpty) {
        _addLine(_TerminalLine(text: stderr, style: _LineStyle.stderr));
      }

      _addLine(_TerminalLine(
        text: exitCode == 0
            ? '→ Process exited with code 0'
            : '→ Process exited with code $exitCode',
        style: exitCode == 0 ? _LineStyle.success : _LineStyle.error,
      ));
    } catch (e) {
      _addLine(_TerminalLine(
        text: 'Error: $e',
        style: _LineStyle.error,
      ));
    } finally {
      setState(() => _isExecuting = false);
    }
  }

  void _handleHistory(bool isUp) {
    if (_history.isEmpty) return;

    if (isUp) {
      _historyIndex = (_historyIndex + 1).clamp(0, _history.length - 1);
    } else {
      _historyIndex = (_historyIndex - 1).clamp(-1, _history.length - 1);
    }

    if (_historyIndex >= 0) {
      _inputController.text = _history[_historyIndex];
      _inputController.selection = TextSelection.fromPosition(
        TextPosition(offset: _inputController.text.length),
      );
    } else {
      _inputController.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final isDark = theme.brightness == Brightness.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Remote Terminal'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_outline),
            onPressed: _lines.length > 1
                ? () {
                    setState(() {
                      _lines.removeRange(1, _lines.length);
                    });
                  }
                : null,
            tooltip: 'Clear output',
          ),
        ],
      ),
      body: Column(
        children: [
          // Terminal output
          Expanded(
            child: Container(
              color: isDark ? const Color(0xFF1E1E1E) : const Color(0xFFF5F5F5),
              child: ListView.builder(
                controller: _scrollController,
                padding: const EdgeInsets.all(12),
                itemCount: _lines.length,
                itemBuilder: (context, index) {
                  final line = _lines[index];
                  return SelectableText(
                    line.text,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 13,
                      height: 1.4,
                      color: _lineColor(line.style, isDark),
                      fontWeight:
                          line.style == _LineStyle.header
                              ? FontWeight.bold
                              : FontWeight.normal,
                    ),
                  );
                },
              ),
            ),
          ),
          // Command input bar
          Container(
            decoration: BoxDecoration(
              color: theme.colorScheme.surfaceContainerHighest,
              border: Border(
                top: BorderSide(
                  color: theme.dividerColor,
                  width: 0.5,
                ),
              ),
            ),
            padding: EdgeInsets.only(
              left: 12,
              right: 8,
              bottom: MediaQuery.of(context).padding.bottom + 8,
              top: 8,
            ),
            child: Row(
              children: [
                // Prompt symbol
                Text(
                  '\$',
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                    color: theme.colorScheme.primary,
                  ),
                ),
                const SizedBox(width: 8),
                // Input field
                Expanded(
                  child: TextField(
                    controller: _inputController,
                    enabled: !_isExecuting,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 14,
                    ),
                    decoration: const InputDecoration(
                      isDense: true,
                      border: InputBorder.none,
                      contentPadding: EdgeInsets.symmetric(vertical: 8),
                      hintText: 'Enter command...',
                    ),
                    onSubmitted: (_isExecuting) ? null : _executeCommand,
                    onChanged: (_) => _historyIndex = -1,
                    textInputAction: TextInputAction.send,
                  ),
                ),
                const SizedBox(width: 4),
                // History navigation
                IconButton(
                  icon: const Icon(Icons.keyboard_arrow_up, size: 20),
                  onPressed: () => _handleHistory(true),
                  tooltip: 'Previous command',
                  visualDensity: VisualDensity.compact,
                ),
                IconButton(
                  icon: const Icon(Icons.keyboard_arrow_down, size: 20),
                  onPressed: () => _handleHistory(false),
                  tooltip: 'Next command',
                  visualDensity: VisualDensity.compact,
                ),
                // Execute button
                IconButton(
                  icon: _isExecuting
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.play_arrow),
                  onPressed: _isExecuting
                      ? null
                      : () {
                          final text = _inputController.text.trim();
                          if (text.isNotEmpty) _executeCommand(text);
                        },
                  style: IconButton.styleFrom(
                    backgroundColor: theme.colorScheme.primaryContainer,
                  ),
                  tooltip: 'Execute',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Color _lineColor(_LineStyle style, bool isDark) {
    switch (style) {
      case _LineStyle.header:
        return isDark ? Colors.cyanAccent : Colors.teal;
      case _LineStyle.command:
        return isDark ? Colors.greenAccent : Colors.green;
      case _LineStyle.stdout:
        return isDark ? Colors.white70 : Colors.black87;
      case _LineStyle.stderr:
        return Colors.orange.shade300;
      case _LineStyle.error:
        return Colors.redAccent;
      case _LineStyle.success:
        return Colors.lightGreen;
      case _LineStyle.info:
        return isDark ? Colors.blueAccent : Colors.blue;
      case _LineStyle.normal:
        return isDark ? Colors.white54 : Colors.black54;
    }
  }
}

class _TerminalLine {
  final String text;
  final _LineStyle style;

  const _TerminalLine({required this.text, required this.style});
}

enum _LineStyle {
  header,
  command,
  stdout,
  stderr,
  error,
  success,
  info,
  normal,
}
