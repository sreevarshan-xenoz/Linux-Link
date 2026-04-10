import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

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
  const FileBrowserScreen({super.key});

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

  // Sample data for development
  final List<FileItem> _localFiles = const [
    FileItem(name: 'Documents', isDirectory: true, modified: '2024-01-15'),
    FileItem(name: 'Downloads', isDirectory: true, modified: '2024-01-20'),
    FileItem(name: 'Photos', isDirectory: true, modified: '2024-01-10'),
    FileItem(name: 'report.pdf', isDirectory: false, size: '2.4 MB', modified: '2024-01-18'),
    FileItem(name: 'notes.txt', isDirectory: false, size: '12 KB', modified: '2024-01-19'),
    FileItem(name: 'image.png', isDirectory: false, size: '1.1 MB', modified: '2024-01-17'),
  ];

  final List<FileItem> _remoteFiles = const [
    FileItem(name: 'etc', isDirectory: true, modified: '2024-01-01'),
    FileItem(name: 'home', isDirectory: true, modified: '2024-01-15'),
    FileItem(name: 'var', isDirectory: true, modified: '2024-01-01'),
    FileItem(name: 'backup.tar.gz', isDirectory: false, size: '156 MB', modified: '2024-01-14'),
    FileItem(name: 'config.yaml', isDirectory: false, size: '4 KB', modified: '2024-01-16'),
  ];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _sendFiles() async {
    if (_selectedLocalFiles.isEmpty) return;

    setState(() {
      _isTransferring = true;
      _transferProgress = 0.0;
    });

    // TODO: Wire up to Rust FFI send_file()
    for (int i = 0; i <= 10; i++) {
      await Future.delayed(const Duration(milliseconds: 200));
      setState(() {
        _transferProgress = i / 10;
      });
    }

    setState(() {
      _isTransferring = false;
      _selectedLocalFiles.clear();
    });

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Files sent successfully')),
      );
    }
  }

  Widget _buildFileList(List<FileItem> files, Set<int> selectedFiles) {
    return ListView.builder(
      itemCount: files.length,
      itemBuilder: (context, index) {
        final file = files[index];
        final isSelected = selectedFiles.contains(index);

        return ListTile(
          leading: Icon(
            file.isDirectory ? Icons.folder : Icons.insert_drive_file,
            color: file.isDirectory
                ? Colors.amber
                : Theme.of(context).colorScheme.primary,
          ),
          title: Text(file.name),
          subtitle: Text([file.size, file.modified].whereType<String>().isNotEmpty
              ? [file.size, file.modified].whereType<String>().join('  -  ')
              : ''),
          trailing: isSelected
              ? const Icon(Icons.check_circle, color: Colors.blue)
              : null,
          selected: isSelected,
          onTap: () {
            if (file.isDirectory) {
              // TODO: Navigate into directory
            }
          },
          onLongPress: () {
            setState(() {
              if (isSelected) {
                selectedFiles.remove(index);
              } else {
                selectedFiles.add(index);
              }
            });
          },
        );
      },
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
          if (_selectedLocalFiles.isNotEmpty)
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
              _buildFileList(_localFiles, _selectedLocalFiles),
              _buildFileList(_remoteFiles, _selectedRemoteFiles),
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
    );
  }
}
