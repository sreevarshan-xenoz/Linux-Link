import 'package:flutter/services.dart';

/// Service for H.264 video decoding via Android MediaCodec.
///
/// Uses a MethodChannel for configuration and an EventChannel for
/// receiving decoded frame texture IDs.
class VideoPlayerService {
  static const _methodChannel = MethodChannel('com.linuxlink/video_player');
  static const _eventChannel = EventChannel('com.linuxlink/video_events');

  static int? _currentTextureId;

  /// Initialize the MediaCodec decoder. Call once at app startup.
  /// Returns the texture ID to use with the Texture widget.
  static Future<int> initialize({
    int width = 1920,
    int height = 1080,
  }) async {
    final textureId = await _methodChannel.invokeMethod<int>('initialize', {
      'width': width,
      'height': height,
    });
    _currentTextureId = textureId;
    return textureId ?? -1;
  }

  /// Feed an H.264 NAL unit (with start codes) to the decoder.
  /// Call this for each encoded packet received from the Rust backend.
  static Future<void> feedFrame(List<int> h264Data) async {
    await _methodChannel.invokeMethod('feedFrame', {
      'data': Uint8List.fromList(h264Data),
    });
  }

  /// Feed multiple NAL units in batch mode.
  static Future<void> feedFrames(List<List<int>> frames) async {
    for (final frame in frames) {
      await feedFrame(frame);
    }
  }

  /// Get the current texture ID for use with Texture widget.
  static int? get textureId => _currentTextureId;

  /// Release the decoder resources.
  static Future<void> dispose() async {
    await _methodChannel.invokeMethod('dispose');
    _currentTextureId = null;
  }
}
