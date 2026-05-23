/// Rust FFI API bridge for Linux Link Android client.
///
/// Delegates to flutter_rust_bridge generated code.
library rust_api_bridge;

import 'package:flutter/foundation.dart';

import 'api.dart' as frb;
import 'frb_generated.dart';
import 'models/monitor_info.dart';
import 'models/peer_info.dart';
import 'models/remote_file.dart';
import 'providers/connection_provider.dart';

/// Re-export the provider's ConnectionState so screens can use
/// `rust_api_bridge.ConnectionState` without ambiguity.
export 'providers/connection_provider.dart' show ConnectionState;

/// Wrapper for streaming statistics with BigInt → int conversion.
class StreamingStats {
  final double fps;
  final int bitrateKbps;
  final int e2eLatencyMs;
  final int frameDrops;

  const StreamingStats({
    required this.fps,
    required this.bitrateKbps,
    required this.e2eLatencyMs,
    required this.frameDrops,
  });

  factory StreamingStats.fromDto(frb.StreamingStatsDto dto) => StreamingStats(
        fps: dto.fps,
        bitrateKbps: dto.bitrateKbps.toInt(),
        e2eLatencyMs: dto.e2ELatencyMs.toInt(),
        frameDrops: dto.frameDrops.toInt(),
      );
}

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
    return dtos
        .map((dto) => PeerInfo(
              name: dto.name,
              dnsName: dto.dnsName,
              ips: dto.ips,
              online: dto.online,
            ))
        .toList();
  }

  /// Connect to a peer by IP and port.
  Future<ConnectionState> connectToPeer(String address, int port) async {
    final state = await frb.connectToPeer(address: address, port: port);
    return _mapConnectionState(state);
  }

  /// Connect to a peer and return the full FRB ConnectionState (with error message).
  Future<frb.ConnectionState> frbConnectToPeer(String address, int port) async {
    return await frb.connectToPeer(address: address, port: port);
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

  /// List files in a remote directory.
  Future<List<RemoteFile>> listRemoteFiles(
    String address,
    int port,
    String remotePath,
  ) async {
    final dtos = await frb.listRemoteFiles(
      address: address,
      port: port,
      remotePath: remotePath,
    );
    return dtos
        .map((dto) => RemoteFile(
              name: dto.name,
              isDirectory: dto.isDirectory,
              size: dto.size.toInt(),
              modified: dto.modified.toInt(),
            ))
        .toList();
  }

  /// Start receiving remote screen streaming.
  ///
  /// [monitorIndex] selects which display to stream (0 = primary, null = default).
  Future<void> startStreaming(String address, int port,
      {int? monitorIndex}) async {
    await frb.connectStreaming(
        address: address, port: port, monitorIndex: monitorIndex);
  }

  /// Stop remote screen streaming.
  Future<void> stopStreaming() async {
    await frb.stopStreaming();
  }

  /// Check if streaming is currently active.
  bool isStreamingActive() {
    return frb.isStreamingActive();
  }

  /// Get high-level session status (Active, Stale, Reconnecting, etc.)
  frb.SessionStatus getSessionStatus() {
    return frb.getSessionStatus();
  }

  /// Reconnect to a streaming server using exponential backoff.
  Future<void> reconnectStreaming(String address, int port,
      {int? monitorIndex, required int attempt}) async {
    await frb.reconnectStreaming(
      address: address,
      port: port,
      monitorIndex: monitorIndex,
      attempt: attempt,
    );
  }

  /// Reset the reconnection backoff timer.
  void resetReconnectBackoff() {
    frb.resetReconnectBackoff();
  }

  /// Receive queued H.264 frames from the streaming client.
  Future<List<FrameDtoWrapper>> receiveFrames(int timeoutMs) async {
    final dtos = await frb.receiveFrames(timeoutMs: BigInt.from(timeoutMs));
    return dtos
        .map((dto) => FrameDtoWrapper(
              data: dto.data,
              isKeyframe: dto.isKeyframe,
            ))
        .toList();
  }

  /// Get the current RTT to the streaming server in microseconds.
  int getStreamingRtt() {
    return frb.getStreamingRtt().toInt();
  }

  /// Get detailed streaming session statistics.
  StreamingStats? getStreamingStats() {
    try {
      return StreamingStats.fromDto(frb.getStreamingStats());
    } catch (_) {
      return null;
    }
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

  /// Send Wake-on-LAN magic packet to wake a sleeping peer.
  /// Uses Rust FFI for centralized networking.
  Future<void> sendWol(String macAddress, String broadcastAddr) async {
    await frb.sendWol(macAddress: macAddress, broadcastAddr: broadcastAddr);
  }

  /// Send power management command (sleep/shutdown/restart/hibernate) to the remote PC.
  /// Uses Rust FFI with proper ConnectionManager handshake.
  Future<void> sendPowerCommand(
    String address,
    int port,
    String action,
  ) async {
    await frb.sendPowerCommand(address: address, port: port, action: action);
  }

  /// Execute a command on the remote server via KDE Connect exec protocol (Rust FFI).
  /// Returns stdout, stderr, and exit code as a formatted string.
  Future<String> executeCommand(
    String address,
    int port,
    String command,
  ) async {
    return await frb.executeRemoteCommand(
        address: address, port: port, command: command);
  }

  /// Receive queued Opus-encoded audio packets from the streaming client (F1).
  Future<List<List<int>>> receiveAudio(int timeoutMs) async {
    return await frb.receiveAudio(timeoutMs: BigInt.from(timeoutMs));
  }

  /// Get detailed list of monitors available on the remote server.
  Future<List<MonitorInfo>> getMonitors(String address, int port) async {
    try {
      final dtos = await frb.getMonitors(address: address, port: port);
      return dtos
          .map((dto) => MonitorInfo(
                index: dto.index,
                name: dto.name,
                width: dto.width,
                height: dto.height,
                isPrimary: dto.isPrimary,
              ))
          .toList();
    } catch (e) {
      debugPrint('Failed to get monitors: $e');
      return [];
    }
  }

  /// Get the number of monitors available on the remote server (F2: multi-monitor).
  /// Uses Rust FFI with proper ConnectionManager handshake.
  Future<int> getMonitorCount(String address, int port) async {
    try {
      final monitors = await getMonitors(address, port);
      return monitors.length;
    } catch (e) {
      debugPrint('Failed to get monitor count: $e');
      return 1;
    }
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

  /// Set the persistent data directory for certs and state.
  Future<void> setDataDir(String path) async {
    await frb.setDataDir(path: path);
  }

  /// Poll for incoming KDE Connect packets (notifications, clipboard, etc.).
  Future<List<String>> pollIncomingPackets() async {
    return await frb.pollIncomingPackets();
  }

  /// List all trusted peer certificate labels.
  List<String> listTrustedPeers() {
    return frb.listTrustedPeers();
  }

  /// Remove a trusted peer by label. Returns true if removed.
  bool forgetTrustedPeer(String label) {
    return frb.forgetTrustedPeer(label: label);
  }

  /// Send gamepad state over the QUIC streaming channel.
  Future<void> sendGamepadEvent({
    required List<int> axes,
    required int buttons,
  }) async {
    await frb.sendGamepadEvent(axes: axes, buttons: buttons);
  }

  ConnectionState _mapConnectionState(frb.ConnectionState state) {
    return state.when(
      connected: () => ConnectionState.connected,
      disconnected: () => ConnectionState.disconnected,
      connecting: () => ConnectionState.connecting,
      error: (dto) => ConnectionState.error,
    );
  }
}
