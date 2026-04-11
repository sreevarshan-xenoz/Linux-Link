/// Rust FFI API bridge for Linux Link Android client.
///
/// Delegates to flutter_rust_bridge generated code.
library rust_api_bridge;

import 'frb_generated.dart';
import 'lib.dart' as frb;
import 'models/peer_info.dart';
import 'providers/connection_provider.dart';

/// Re-export the provider's ConnectionState so screens can use
/// `rust_api_bridge.ConnectionState` without ambiguity.
export 'providers/connection_provider.dart' show ConnectionState;

/// Wrapper for frame data returned by the Rust backend.
class FrameDtoWrapper {
  final List<int> data;
  final bool isKeyframe;

  const FrameDtoWrapper({required this.data, required this.isKeyframe});
}

/// Global singleton providing a stable API surface for screens.
final rustApi = _RustApiBridge._instance;

class _RustApiBridge {
  static final _RustApiBridge _instance = _RustApiBridge._internal();
  _RustApiBridge._internal();

  /// Initialize the Rust backend (call once at app startup).
  Future<void> init() async {
    await RustApi.init();
  }

  /// Get the version string from the Rust crate.
  Future<String> version() async {
    return await frb.version();
  }

  /// Check if Tailscale is ready.
  Future<bool> checkTailscaleStatus() async {
    return await frb.checkTailscaleStatus();
  }

  /// Get list of peers on the tailnet.
  Future<List<PeerInfo>> getPeers() async {
    final dtos = await frb.getPeers();
    return dtos.map((dto) => PeerInfo(
          name: dto.name,
          dnsName: dto.dnsName,
          ips: dto.ips,
          online: dto.online,
        )).toList();
  }

  /// Connect to a peer by IP and port.
  Future<ConnectionState> connectToPeer(String address, int port) async {
    final state = await frb.connectToPeer(address: address, port: port);
    return _mapConnectionState(state);
  }

  /// Send clipboard content to peer.
  Future<void> sendClipboard(String address, int port, String content) async {
    await frb.sendClipboard(address: address, port: port, content: content);
  }

  /// Get clipboard content from peer.
  Future<String> getClipboard(String address, int port) async {
    return await frb.getClipboard(address: address, port: port);
  }

  /// Send file to peer using KDE Share protocol.
  Future<void> sendFile(String address, int port, String filePath) async {
    await frb.sendFile(address: address, port: port, filePath: filePath);
  }

  /// Start receiving remote screen streaming.
  Future<void> startStreaming(String address, int port) async {
    await frb.connectStreaming(address: address, port: port);
  }

  /// Stop remote screen streaming.
  Future<void> stopStreaming() async {
    await frb.stopStreaming();
  }

  /// Check if streaming is currently active.
  Future<bool> isStreamingActive() async {
    return await frb.isStreamingActive();
  }

  /// Receive queued H.264 frames from the streaming client.
  Future<List<FrameDtoWrapper>> receiveFrames(int timeoutMs) async {
    final dtos = await frb.receiveFrames(timeoutMs: BigInt.from(timeoutMs));
    return dtos.map((dto) => FrameDtoWrapper(
          data: dto.data,
          isKeyframe: dto.isKeyframe,
        )).toList();
  }

  /// Get the current RTT to the streaming server in microseconds.
  int getStreamingRtt() {
    return frb.getStreamingRtt().toInt();
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
    await frb.sendMouseEvent(
      address: address,
      port: port,
      x: x,
      y: y,
      button: button,
      isPressed: isPressed,
    );
  }

  /// Send keyboard event (text typing or key code).
  Future<void> sendKeyboardEvent(
    String address,
    int port,
    int keyCode,
    String text,
  ) async {
    await frb.sendKeyboardEvent(
      address: address,
      port: port,
      keyCode: keyCode,
      text: text,
    );
  }

  ConnectionState _mapConnectionState(frb.ConnectionState state) {
    return state.when(
      connected: () => ConnectionState.connected,
      disconnected: () => ConnectionState.disconnected,
      connecting: () => ConnectionState.connecting,
      error: (_) => ConnectionState.error,
    );
  }
}
