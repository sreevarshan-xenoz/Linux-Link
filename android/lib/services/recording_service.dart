import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// F5: Session Recording service.
///
/// Captures received H.264 NAL units and writes them to an MP4 file on the
/// Android device via the native MediaMuxer plugin.
class RecordingService {
  static const _methodChannel = MethodChannel('com.linuxlink/video_player');

  /// Whether a recording is currently in progress.
  static bool _isRecording = false;

  /// Path to the current recording output file.
  static String? _currentFilePath;

  /// Start a new recording session.
  ///
  /// Returns the file path where the recording will be saved.
  static Future<String?> startRecording() async {
    if (_isRecording) return _currentFilePath;

    try {
      final path = await _methodChannel.invokeMethod<String>('startRecording');
      if (path != null && path.isNotEmpty) {
        _isRecording = true;
        _currentFilePath = path;
      }
      return path;
    } catch (e) {
      debugPrint('Failed to start recording: $e');
      return null;
    }
  }

  /// Stop the current recording session.
  ///
  /// Returns the path to the recorded MP4 file, or null.
  static Future<String?> stopRecording() async {
    if (!_isRecording) return _currentFilePath;

    try {
      final path = await _methodChannel.invokeMethod<String>('stopRecording');
      _isRecording = false;
      _currentFilePath = path;
      return path;
    } catch (e) {
      debugPrint('Failed to stop recording: $e');
      _isRecording = false;
      return _currentFilePath;
    }
  }

  /// Feed a single H.264 NAL unit to the recording.
  static Future<void> feedFrame(List<int> data,
      {bool isKeyframe = false}) async {
    if (!_isRecording) return;

    try {
      await _methodChannel.invokeMethod('feedFrameToRecord', {
        'data': data,
        'isKeyframe': isKeyframe,
      });
    } catch (e) {
      debugPrint('Failed to feed frame to recording: $e');
    }
  }

  /// Whether a recording is in progress.
  static bool get isRecording => _isRecording;

  /// The path of the current recording file (may be null if not recording).
  static String? get currentFilePath => _currentFilePath;

  /// Share or open the last recorded file via the system share sheet.
  static Future<bool> shareLastRecording() async {
    if (_currentFilePath == null) return false;
    final file = File(_currentFilePath!);
    if (!file.existsSync()) return false;
    debugPrint(
        'Recording available at: ${file.path} (${file.lengthSync()} bytes)');
    return true;
  }

  /// Get all recorded files from the LinuxLink directory.
  static Future<List<File>> getRecordedFiles() async {
    final moviesDir = Directory('/storage/emulated/0/Movies/LinuxLink');
    if (!await moviesDir.exists()) return [];
    return moviesDir
        .listSync()
        .whereType<File>()
        .where((f) => f.path.endsWith('.mp4') || f.path.endsWith('.h264'))
        .toList()
      ..sort((a, b) => b.lastModifiedSync().compareTo(a.lastModifiedSync()));
  }

  /// Format a file size in human-readable format.
  static String formatSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}
