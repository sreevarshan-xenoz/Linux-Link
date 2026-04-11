import 'package:flutter_background_service/flutter_background_service.dart';

/// Initialize the Android foreground service for keeping streaming alive.
///
/// Call this after the app is initialized. The service does NOT start
/// automatically — call [startForegroundService] when streaming begins.
Future<void> initBackgroundService() async {
  final service = FlutterBackgroundService();

  await service.configure(
    androidConfiguration: AndroidConfiguration(
      onStart: _onBackgroundServiceStart,
      autoStart: false,
      isForegroundMode: true,
      notificationChannelId: 'linux_link_streaming',
      initialNotificationTitle: 'Linux Link',
      initialNotificationContent: 'Ready',
      foregroundServiceNotificationId: 888,
    ),
    iosConfiguration: IosConfiguration(),
  );
}

/// Start the foreground service with a notification indicating streaming is active.
Future<void> startForegroundService() async {
  final service = FlutterBackgroundService();
  await service.startService();
}

/// Stop the foreground service.
Future<void> stopForegroundService() async {
  final service = FlutterBackgroundService();
  service.invoke('stop');
}

@pragma('vm:entry-point')
Future<void> _onBackgroundServiceStart(ServiceInstance service) async {
  if (service is AndroidServiceInstance) {
    service.on('setAsForeground').listen((_) {
      service.setAsForegroundService();
    });

    service.on('setAsBackground').listen((_) {
      service.setAsBackgroundService();
    });
  }

  service.on('stop').listen((_) {
    service.stopSelf();
  });
}
