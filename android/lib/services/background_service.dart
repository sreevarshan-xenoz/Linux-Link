import 'package:flutter_background_service/flutter_background_service.dart';
import 'clipboard_sync_service.dart';

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

/// Start the foreground service and set up background features.
/// Call this with the peer's address and port when streaming begins.
Future<void> startForegroundServiceWithPeer(String address, int port) async {
  await startForegroundService();
  // Start clipboard auto-sync if enabled
  final syncEnabled = await ClipboardSyncService.isEnabled();
  if (syncEnabled) {
    clipboardSyncService.start(address, port);
  }
}

/// Stop the foreground service and all background features.
Future<void> stopForegroundService() async {
  final service = FlutterBackgroundService();
  clipboardSyncService.stop();
  service.invoke('stop');
  // Give Android time to process the stop request
  await Future.delayed(const Duration(milliseconds: 200));
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
