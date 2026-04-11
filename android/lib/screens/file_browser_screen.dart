import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../models/remote_file.dart';
import '../rust_api_bridge.dart' as bridge;

class FileItem {
  final String name;
  final bool isDirectory;
  final String? size;
  final String? modified;

  const FileItem({
    required this.name,
    required this.isDirectory,
    this.size,
    this.modified,
  });
}

class FileBrowserScreen extends ConsumerStatefulWidget {
  final String address;
  final int port;

  const FileBrowserScreen({
    super.key,
    required this.address,
    required this.port,
  });

  @override
  ConsumerState<FileBrowserScreen> createState() => _FileBrowserScreenState();
}

class _FileBrowserScreenState extends ConsumerState<FileBrowserScreen>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final Set<int> _selectedLocalFiles = {};
  final Set<int> _selectedRemoteFiles = {};
  bool _isTransferring = false;
  double _transferProgress = 0.0;
  List<String> _pendingFiles = [];

  // Remote file browsing
  String _currentRemotePath = '/';
  List<RemoteFile> _remoteFiles = [];
  bool _remoteLoading = false;

  // Local files selected for transfer
  final List<PlatformFile> _localFiles = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _loadRemoteFiles();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _pickFiles() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        allowMultiple: true,
        withData: false,
      );

      if (result != null && result.files.isNotEmpty) {
        setState(() {
          _localFiles.addAll(result.files);
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to pick files: $e')),
        );
      }
    }
  }

  Future<void> _sendFiles() async {
    if (_localFiles.isEmpty) return;

    setState(() {
      _isTransferring = true;
      _transferProgress = 0.0;
      _pendingFiles = _localFiles.map((f) => f.path ?? f.name).toList();
    });

    int completed = 0;
    for (final file in _localFiles) {
      final filePath = file.path;
      if (filePath == null) continue;

      try {
        final absPath = File(filePath).absolute.path;
        await bridge.rustApi.sendFile(widget.address, widget.port, absPath);
      } catch (e) {
        debugPrint('Failed to send ${file.name}: $e');
      }

      completed++;
      if (mounted) {
        setState(() {
          _transferProgress = completed / _localFiles.length;
        });
      }
    }

    if (mounted) {
      setState(() {
        _isTransferring = false;
        _localFiles.clear();
        _selectedLocalFiles.clear();
        _pendingFiles.clear();
      });

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Files sent successfully')),
      );
    }
  }

  Widget _buildLocalFileList() {
    if (_localFiles.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.upload_file,
              size: 64,
              color: Theme.of(context).colorScheme.outline,
            ),
            const SizedBox(height: 16),
            Text(
              'No files selected',
              style: Theme.of(context).textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              'Tap the + button to select files to send',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      itemCount: _localFiles.length,
      itemBuilder: (context, index) {
        final file = _localFiles[index];
        final isSelected = _selectedLocalFiles.contains(index);

        return ListTile(
          leading: Icon(
            Icons.insert_drive_file,
            color: Theme.of(context).colorScheme.primary,
          ),
          title: Text(file.name),
          subtitle: file.size != null
              ? Text('${_formatFileSize(file.size!)}')
              : null,
          trailing: isSelected
              ? const Icon(Icons.check_circle, color: Colors.blue)
              : null,
          selected: isSelected,
          onLongPress: () {
            setState(() {
              if (isSelected) {
                _selectedLocalFiles.remove(index);
              } else {
                _selectedLocalFiles.add(index);
              }
            });
          },
          onDoubleTap: () {
            setState(() {
              _localFiles.removeAt(index);
              _selectedLocalFiles.remove(index);
            });
          },
        );
      },
    );
  }

  String _formatFileSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }

  Widget _buildRemoteFileList() {
    if (_remoteLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    return Column(
      children: [
        // Path bar with back button
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Row(
            children: [
              if (_currentRemotePath != '/')
                IconButton(
                  icon: const Icon(Icons.arrow_back),
                  onPressed: _navigateUp,
                  tooltip: 'Go up',
                ),
              Expanded(
                child: Text(
                  _currentRemotePath,
                  style: Theme.of(context).textTheme.bodySmall,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              IconButton(
                icon: const Icon(Icons.refresh),
                onPressed: _loadRemoteFiles,
                tooltip: 'Refresh',
              ),
            ],
          ),
        ),
        const Divider(height: 1),
        // File list
        Expanded(
          child: _remoteFiles.isEmpty
              ? Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.folder_open,
                        size: 64,
                        color: Theme.of(context).colorScheme.outline,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Empty directory',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ],
                  ),
                )
              : ListView.builder(
                  itemCount: _remoteFiles.length,
                  itemBuilder: (context, index) {
                    final file = _remoteFiles[index];
                    return ListTile(
                      leading: Icon(
                        file.isDirectory ? Icons.folder : Icons.insert_drive_file,
                        color: file.isDirectory
                            ? Colors.amber
                            : Theme.of(context).colorScheme.primary,
                      ),
                      title: Text(file.name),
                      subtitle: file.isDirectory
                          ? null
                          : Text('${file.formattedSize}  \u2022  ${file.formattedModified}'),
                      onTap: () {
                        if (file.isDirectory) {
                          _navigateInto(file.name);
                        }
                      },
                      onLongPress: file.isDirectory
                          ? null
                          : () => _showFileOptions(file),
                    );
                  },
                ),
        ),
      ],
    );
  }

  Future<void> _loadRemoteFiles() async {
    setState(() => _remoteLoading = true);
    try {
      final files = await bridge.rustApi.listRemoteFiles(
        widget.address,
        widget.port,
        _currentRemotePath,
      );
      if (mounted) {
        setState(() {
          _remoteFiles = files;
          _remoteLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() => _remoteLoading = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load files: $e')),
        );
      }
    }
  }

  void _navigateInto(String name) {
    setState(() {
      _currentRemotePath =
          '${_currentRemotePath}${_currentRemotePath.endsWith('/') ? '' : '/'}$name';
    });
    _loadRemoteFiles();
  }

  void _navigateUp() {
    setState(() {
      final parts =
          _currentRemotePath.split('/').where((s) => s.isNotEmpty).toList();
      parts.removeLast();
      _currentRemotePath = parts.isEmpty ? '/' : '/${parts.join('/')}';
    });
    _loadRemoteFiles();
  }

  void _showFileOptions(RemoteFile file) {
    showModalBottomSheet(
      context: context,
      builder: (context) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            ListTile(
              leading: const Icon(Icons.download),
              title: const Text('Download'),
              onTap: () {
                Navigator.pop(context);
                _downloadFile(file);
              },
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _downloadFile(RemoteFile file) async {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Download for ${file.name} \u2014 coming soon')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('File Browser'),
        bottom: TabBar(
          controller: _tabController,
          tabs: const [
            Tab(icon: Icon(Icons.phone_android), text: 'Local Files'),
            Tab(icon: Icon(Icons.computer), text: 'Remote Files'),
          ],
        ),
        actions: [
          if (_localFiles.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.upload),
              onPressed: _isTransferring ? null : _sendFiles,
              tooltip: 'Send selected files',
            ),
        ],
      ),
      body: Stack(
        children: [
          TabBarView(
            controller: _tabController,
            children: [
              _buildLocalFileList(),
              _buildRemoteFileList(),
            ],
          ),
          if (_isTransferring)
            Container(
              color: Colors.black54,
              child: Center(
                child: Card(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Text('Transferring files...'),
                        const SizedBox(height: 16),
                        LinearProgressIndicator(value: _transferProgress),
                        const SizedBox(height: 8),
                        Text('${(_transferProgress * 100).toInt()}%'),
                      ],
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _isTransferring ? null : _pickFiles,
        child: const Icon(Icons.add),
      ),
    );
  }
}
