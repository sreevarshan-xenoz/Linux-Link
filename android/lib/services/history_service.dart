import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

/// A record of a past connection to a peer.
class ConnectionRecord {
  final String peerName;
  final String peerAddress;
  final int port;
  final DateTime connectedAt;
  final Duration? duration;
  final int bytesTransferred;

  const ConnectionRecord({
    required this.peerName,
    required this.peerAddress,
    required this.port,
    required this.connectedAt,
    this.duration,
    this.bytesTransferred = 0,
  });

  Map<String, dynamic> toJson() => {
        'peerName': peerName,
        'peerAddress': peerAddress,
        'port': port,
        'connectedAtMs': connectedAt.millisecondsSinceEpoch,
        'durationSec': duration?.inSeconds,
        'bytesTransferred': bytesTransferred,
      };

  factory ConnectionRecord.fromJson(Map<String, dynamic> json) =>
      ConnectionRecord(
        peerName: json['peerName'] as String,
        peerAddress: json['peerAddress'] as String,
        port: json['port'] as int,
        connectedAt:
            DateTime.fromMillisecondsSinceEpoch(json['connectedAtMs'] as int),
        duration: json['durationSec'] != null
            ? Duration(seconds: json['durationSec'] as int)
            : null,
        bytesTransferred: json['bytesTransferred'] as int? ?? 0,
      );

  String get formattedDuration {
    if (duration == null) return 'In progress...';
    if (duration!.inHours > 0) {
      return '${duration!.inHours}h ${duration!.inMinutes.remainder(60)}m';
    }
    if (duration!.inMinutes > 0) {
      return '${duration!.inMinutes}m ${duration!.inSeconds.remainder(60)}s';
    }
    return '${duration!.inSeconds}s';
  }

  String get formattedDate {
    final now = DateTime.now();
    final diff = now.difference(connectedAt);
    if (diff.inMinutes < 1) return 'Just now';
    if (diff.inHours < 1) return '${diff.inMinutes}m ago';
    if (diff.inDays < 1) return '${diff.inHours}h ago';
    return '${connectedAt.month}/${connectedAt.day}/${connectedAt.year}';
  }
}

/// Service for persisting and retrieving connection history.
class HistoryService {
  static const _key = 'connection_history';
  static const _maxRecords = 50;

  static Future<List<ConnectionRecord>> getHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final json = prefs.getString(_key);
    if (json == null || json.isEmpty) return [];
    final list = jsonDecode(json) as List<dynamic>;
    return list
        .map((e) => ConnectionRecord.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  static Future<void> addRecord(ConnectionRecord record) async {
    final prefs = await SharedPreferences.getInstance();
    final history = await getHistory();
    history.insert(0, record);
    // Trim to max records
    if (history.length > _maxRecords) {
      history.removeRange(_maxRecords, history.length);
    }
    await prefs.setString(_key, jsonEncode(history.map((r) => r.toJson()).toList()));
  }

  static Future<void> clearHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }

  static Future<void> updateLastConnection({
    required Duration duration,
    int bytesTransferred = 0,
  }) async {
    final history = await getHistory();
    if (history.isEmpty) return;
    final last = history.first;
    history[0] = ConnectionRecord(
      peerName: last.peerName,
      peerAddress: last.peerAddress,
      port: last.port,
      connectedAt: last.connectedAt,
      duration: duration,
      bytesTransferred: bytesTransferred,
    );
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_key, jsonEncode(history.map((r) => r.toJson()).toList()));
  }
}
