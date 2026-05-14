/// Rust FFI API bridge for Linux Link Android client.
///
/// Delegates to flutter_rust_bridge generated code.
library rust_api_bridge;

import 'dart:convert';
import 'dart:io';

import 'api.dart' as frb;
import 'frb_generated.dart';
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
  Future<void> startStreaming(String address, int port) async {
    await frb.connectStreaming(address: address, port: port);
  }

  /// Stop remote screen streaming.
  Future<void> stopStreaming() async {
    await frb.stopStreaming();
  }

  /// Check if streaming is currently active.
  bool isStreamingActive() {
    return frb.isStreamingActive();
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
  /// Uses raw UDP socket directly (no Rust FFI needed for this).
  Future<void> sendWol(String macAddress, String broadcastAddr) async {
    final mac = _parseMacAddress(macAddress);
    // Build magic packet: 6 bytes of 0xFF + MAC repeated 16 times
    final packet = <int>[...List.filled(6, 0xFF)];
    for (int i = 0; i < 16; i++) {
      packet.addAll(mac);
    }
    final socket = await RawDatagramSocket.bind(
      InternetAddress.anyIPv4,
      0,
    );
    socket.broadcastEnabled = true;
    socket.send(
      packet,
      InternetAddress(broadcastAddr),
      9, // WOL port
    );
    socket.close();
  }

  /// Parse a MAC address string (e.g., "AA:BB:CC:DD:EE:FF") into a 6-byte list.
  List<int> _parseMacAddress(String mac) {
    final hex = mac.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
    if (hex.length != 12) {
      throw ArgumentError.value(
        mac,
        'macAddress',
        'Invalid MAC address: expected 12 hex digits, got ${hex.length}',
      );
    }
    final bytes = <int>[];
    for (int i = 0; i < 12; i += 2) {
      bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
    }
    return bytes;
  }

  /// Send power management command (sleep/shutdown/restart/hibernate) to the remote PC.
  /// Performs the LINUX_LINK_HELLO handshake, consumes the server's response,
  /// then sends the power command — all over a raw TCP connection (no Rust FFI needed).
  Future<void> sendPowerCommand(
    String address,
    int port,
    String action,
  ) async {
    final socket = await Socket.connect(address, port,
        timeout: const Duration(seconds: 5));
    try {
      // Step 1: Send LINUX_LINK_HELLO handshake
      socket.write('LINUX_LINK_HELLO 1\n');
      await socket.flush();

      // Step 2: Drain the server response(s) with a short timeout.
      // The server sends an identity JSON packet (possibly preceded by
      // HANDSHAKE_OK). Read available data for up to 500ms then move on.
      try {
        await socket
            .cast<List<int>>()
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .first
            .timeout(const Duration(milliseconds: 500));
      } catch (_) {
        // Ignore — proceed with sending the power command
      }

      // Step 3: Send the power command as a proper NetworkPacket wire format
      final packet = jsonEncode({
        'type': 'kdeconnect.linuxlink.power',
        'body': {'action': action},
      });
      socket.write('$packet\n');
      await socket.flush();
    } finally {
      await socket.close();
    }
  }

  /// Execute a command on the remote server via KDE Connect exec protocol.
  /// Returns stdout, stderr, and exit code as a formatted string.
  Future<String> executeCommand(
    String address,
    int port,
    String command,
  ) async {
    final socket = await Socket.connect(address, port,
        timeout: const Duration(seconds: 5));
    try {
      // Step 1: Send LINUX_LINK_HELLO handshake
      socket.write('LINUX_LINK_HELLO 1\n');
      await socket.flush();

      // Step 2: Read/discard identity response with timeout
      try {
        await socket
            .cast<List<int>>()
            .transform(utf8.decoder)
            .transform(const LineSplitter())
            .first
            .timeout(const Duration(milliseconds: 500));
      } catch (_) {
        // Proceed regardless
      }

      // Step 3: Send exec command packet
      final packet = jsonEncode({
        'type': 'kdeconnect.linuxlink.exec',
        'body': {'command': command},
      });
      socket.write('$packet\n');
      await socket.flush();

      // Step 4: Read response packet
      final line = await socket
          .cast<List<int>>()
          .transform(utf8.decoder)
          .transform(const LineSplitter())
          .first
          .timeout(const Duration(seconds: 10));

      // Step 5: Parse response
      try {
        final json = jsonDecode(line) as Map<String, dynamic>;
        final body = json['body'] as Map<String, dynamic>?;
        final stdout = body?['stdout'] as String? ?? '';
        final stderr = body?['stderr'] as String? ?? '';
        final exitCode = (body?['exit_code'] as num?)?.toInt() ?? -1;

        return '$stdout\n---END-OUTPUT---\n$stderr\n---END-ERROR---\n$exitCode';
      } catch (e) {
        return '\n---END-OUTPUT---\nFailed to parse server response: $e\n---END-ERROR---\n-1';
      }
    } finally {
      await socket.close();
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

  ConnectionState _mapConnectionState(frb.ConnectionState state) {
    return state.when(
      connected: () => ConnectionState.connected,
      disconnected: () => ConnectionState.disconnected,
      connecting: () => ConnectionState.connecting,
      error: (_) => ConnectionState.error,
    );
  }
}
