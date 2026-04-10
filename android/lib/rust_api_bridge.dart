/// Rust FFI API bridge for Linux Link Android client.
///
/// Before running `flutter_rust_bridge_codegen generate`, this provides
/// a placeholder implementation. After codegen, replace with the
/// generated `RustApi` calls.
library rust_api_bridge;

import 'models/peer_info.dart';

class RustApi {
  static final RustApi _instance = RustApi._internal();
  factory RustApi() => _instance;
  RustApi._internal();

  /// Initialize the Rust backend (call once at app startup).
  Future<void> init() async {
    // Before FRB codegen: no-op
    // After codegen: call `apiStore.initApp()`
  }

  /// Get the version string from the Rust crate.
  Future<String> version() async {
    // After codegen: return RustApi.version()
    return '0.1.0';
  }

  /// Check if Tailscale is ready.
  Future<bool> checkTailscaleStatus() async {
    // After codegen: return RustApi.checkTailscaleStatus()
    return true;
  }

  /// Get list of peers on the tailnet.
  Future<List<PeerInfo>> getPeers() async {
    // After codegen: return RustApi.getPeers().then(...)
    // For now return empty list (no simulated data - real peers from Rust)
    return [];
  }

  /// Connect to a peer by IP and port.
  Future<ConnectionState> connectToPeer(String address, int port) async {
    // After codegen: return RustApi.connectToPeer(address, port)
    await Future.delayed(const Duration(seconds: 2));
    return ConnectionState.connected;
  }

  /// Send clipboard content to peer.
  Future<void> sendClipboard(String address, int port, String content) async {
    // After codegen: return RustApi.sendClipboard(address, port, content)
  }

  /// Get clipboard content from peer.
  Future<String> getClipboard(String address, int port) async {
    // After codegen: return RustApi.getClipboard(address, port)
    return '';
  }

  /// Send file to peer using KDE Share protocol.
  /// [filePath] is the absolute path to the local file.
  Future<void> sendFile(String address, int port, String filePath) async {
    // After codegen: return RustApi.sendFile(address, port, filePath)
    // Simulate progress via callback if needed
  }

  /// Start receiving remote screen streaming.
  Future<void> startStreaming(String address, int port) async {
    // After codegen: return RustApi.startStreaming(address, port)
  }

  /// Stop remote screen streaming.
  Future<void> stopStreaming() async {
    // After codegen: return RustApi.stopStreaming()
  }

  /// Check if streaming is currently active.
  Future<bool> isStreamingActive() async {
    // After codegen: return RustApi.isStreamingActive()
    return false;
  }

  /// Send mouse event (movement, click, drag).
  Future<void> sendMouseEvent(
    String address,
    int port,
    double x,
    double y,
    int button,
    bool isPressed,
  ) async {
    // After codegen: return RustApi.sendMouseEvent(address, port, x, y, button, isPressed)
  }

  /// Send keyboard event (text typing or key code).
  Future<void> sendKeyboardEvent(
    String address,
    int port,
    int keyCode,
    String text,
  ) async {
    // After codegen: return RustApi.sendKeyboardEvent(address, port, keyCode, text)
  }
}

/// Connection state matching the Rust enum.
enum ConnectionState { connected, disconnected, connecting, error }

/// Global singleton instance.
final rustApi = RustApi();
