import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// F19: Notification Mirroring service.
///
/// Receives forwarded desktop notifications from the remote PC and displays
/// them as Android notifications using flutter_local_notifications.
class NotificationMirrorService {
  static final FlutterLocalNotificationsPlugin _plugin =
      FlutterLocalNotificationsPlugin();
  static bool _initialized = false;
  static const String _channelId = 'linux_link_notifications';
  static const String _channelName = 'PC Notifications';
  static const String _channelDesc = 'Notifications mirrored from your PC';

  /// Initialize the local notifications plugin.
  /// Call once at app startup from main.dart.
  static Future<void> initialize() async {
    if (_initialized) return;

    const androidSettings =
        AndroidInitializationSettings('@mipmap/ic_launcher');
    const iosSettings = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS: iosSettings,
    );

    await _plugin.initialize(
      initSettings,
      onDidReceiveNotificationResponse: _onNotificationTapped,
    );

    // Create the notification channel
    const androidChannel = AndroidNotificationChannel(
      _channelId,
      _channelName,
      description: _channelDesc,
      importance: Importance.high,
      playSound: false,
      enableVibration: true,
    );
    await _plugin
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(androidChannel);

    _initialized = true;
    debugPrint('NotificationMirrorService initialized');
  }

  /// Handle a tapped notification.
  static void _onNotificationTapped(NotificationResponse response) {
    debugPrint('Notification tapped: ${response.payload}');
  }

  /// Process an incoming notification packet from the remote PC.
  ///
  /// `data` is a JSON-encoded notification packet received via the Rust bridge.
  static Future<void> handleNotificationPacket(String data) async {
    if (!_initialized) await initialize();

    try {
      final json = jsonDecode(data) as Map<String, dynamic>;
      final body = json['body'] as Map<String, dynamic>?;
      if (body == null) return;

      final app = body['app'] as String? ?? 'Remote PC';
      final title = body['title'] as String? ?? 'Notification';
      final text = body['text'] as String? ?? '';
      final urgency = (body['urgency'] as num?)?.toInt() ?? 0;

      // Generate a unique notification ID
      final notificationId = DateTime.now().millisecondsSinceEpoch ~/ 10;

      // Style based on urgency
      final importance = switch (urgency) {
        2 => Importance.max,
        1 => Importance.high,
        _ => Importance.defaultImportance,
      };
      final priority = switch (urgency) {
        2 => Priority.max,
        1 => Priority.high,
        _ => Priority.defaultPriority,
      };

      final androidDetails = AndroidNotificationDetails(
        _channelId,
        _channelName,
        channelDescription: _channelDesc,
        importance: importance,
        priority: priority,
        color: const Color(0xFF4285F4),
        icon: '@mipmap/ic_launcher',
        tag: '$app-$title',
        subText: app,
        category: AndroidNotificationCategory.alarm,
      );
      const iosDetails = DarwinNotificationDetails(
        presentAlert: true,
        presentBadge: true,
        presentSound: true,
      );
      final details = NotificationDetails(
        android: androidDetails,
        iOS: iosDetails,
      );

      // Show an Android heads-up notification
      await _plugin.show(
        notificationId,
        title,
        text,
        details,
        payload: jsonEncode({
          'app': app,
          'title': title,
          'text': text,
        }),
      );

      debugPrint('Mirrored notification: [$app] $title');
    } catch (e) {
      debugPrint('Failed to process notification packet: $e');
    }
  }

  /// Cancel all shown PC notification mirrors.
  static Future<void> cancelAll() async {
    await _plugin.cancelAll();
    debugPrint('All mirrored notifications cancelled');
  }

  /// Cancel a specific notification by ID.
  static Future<void> cancel(int notificationId) async {
    await _plugin.cancel(notificationId);
  }
}
