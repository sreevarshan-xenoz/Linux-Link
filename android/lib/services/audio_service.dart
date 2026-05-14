import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// F1: Audio Streaming service for the Android client.
///
/// Receives Opus-encoded audio packets from the Rust backend and feeds them
/// to the native AudioTrack decoder for low-latency playback.
class AudioService {
  static const _methodChannel = MethodChannel('com.linuxlink/video_player');

  /// Whether audio playback is currently active.
  static bool _isPlaying = false;

  /// Whether a permanent failure has occurred (audio unsupported).
  static bool _hasFailed = false;

  /// Initialize audio streaming.
  ///
  /// Creates an AudioTrack + Opus MediaCodec decoder on the native side.
  /// [sampleRate] defaults to 48000 Hz, [channels] defaults to 2 (stereo).
  static Future<bool> startAudio({
    int sampleRate = 48000,
    int channels = 2,
  }) async {
    if (_isPlaying || _hasFailed) return _isPlaying;

    try {
      await _methodChannel.invokeMethod('startAudio', {
        'sampleRate': sampleRate,
        'channels': channels,
      });
      _isPlaying = true;
      debugPrint('AudioService: started ($sampleRate Hz, $channels ch)');
      return true;
    } catch (e) {
      debugPrint('AudioService: failed to start: $e');
      _hasFailed = true; // Don't retry if device doesn't support Opus decoding
      return false;
    }
  }

  /// Feed a single Opus-encoded packet to the decoder for playback.
  static Future<void> feedPacket(List<int> opusData) async {
    if (!_isPlaying) return;

    try {
      await _methodChannel.invokeMethod('feedAudioPacket', {
        'data': opusData,
      });
    } catch (e) {
      debugPrint('AudioService: feed packet error: $e');
    }
  }

  /// Stop audio playback and release native resources.
  static Future<void> stopAudio() async {
    if (!_isPlaying) return;

    try {
      await _methodChannel.invokeMethod('stopAudio');
    } catch (e) {
      debugPrint('AudioService: stop error: $e');
    }
    _isPlaying = false;
    _hasFailed = false;
  }

  /// Whether audio is currently playing.
  static bool get isPlaying => _isPlaying;

  /// Dispose audio resources (called on screen dispose).
  static Future<void> dispose() async {
    await stopAudio();
  }
}
