import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'rust_api_bridge.dart' as bridge;
import 'screens/connection_screen.dart';
import 'screens/connection_history_screen.dart';
import 'screens/remote_desktop_screen.dart';
import 'screens/file_browser_screen.dart';
import 'screens/settings_screen.dart';
import 'screens/terminal_screen.dart';
import 'screens/trust_screen.dart';
import 'services/notification_service.dart';

final _router = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      builder: (context, state) => const ConnectionScreen(),
    ),
    GoRoute(
      path: '/remote',
      builder: (context, state) {
        final args = state.extra as Map<String, dynamic>?;
        return RemoteDesktopScreen(
          address: args?['address'] as String? ?? '',
          port: args?['port'] as int? ?? 1716,
        );
      },
    ),
    GoRoute(
      path: '/files',
      builder: (context, state) {
        final args = state.extra as Map<String, dynamic>?;
        return FileBrowserScreen(
          address: args?['address'] as String? ?? '',
          port: args?['port'] as int? ?? 1716,
        );
      },
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
    GoRoute(
      path: '/history',
      builder: (context, state) => const ConnectionHistoryScreen(),
    ),
    GoRoute(
      path: '/terminal',
      builder: (context, state) {
        final args = state.extra as Map<String, dynamic>?;
        return TerminalScreen(
          address: args?['address'] as String? ?? '',
          port: args?['port'] as int? ?? 1716,
        );
      },
    ),
    GoRoute(
      path: '/trust',
      builder: (context, state) {
        final args = state.extra as Map<String, dynamic>?;
        return TrustScreen(
          address: args?['address'] as String? ?? '',
          fingerprint: args?['fingerprint'] as String? ?? '',
          onAccept: args?['onAccept'] as VoidCallback?,
          onReject: args?['onReject'] as VoidCallback?,
          showTrustedDevices: args?['showTrustedDevices'] as bool? ?? false,
        );
      },
    ),
  ],
);

/// Periodically poll for incoming KDE Connect packets and dispatch them.
/// Runs while the control connection is active.
void _startPacketPoller() {
  Timer.periodic(const Duration(milliseconds: 500), (timer) async {
    try {
      final packets = await bridge.rustApi.pollIncomingPackets();
      for (final raw in packets) {
        try {
          final json = jsonDecode(raw) as Map<String, dynamic>;
          final type = json['type'] as String?;
          if (type == 'kdeconnect.notification') {
            NotificationMirrorService.handleNotificationPacket(raw);
          }
          // Future: handle other packet types (clipboard push, battery, etc.)
        } catch (_) {}
      }
    } catch (_) {
      // Polling failed — likely disconnected
    }
  });
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  debugPrint('Starting Linux Link initialization...');

  try {
    // Initialize the Rust backend
    debugPrint('Initializing Rust backend...');
    await bridge.rustApi.init();
    debugPrint('Rust backend initialized successfully');
  } catch (e) {
    debugPrint('Failed to initialize Rust backend: $e');
    // Continue anyway - the app might still work without Rust
  }

  // Initialize notification mirroring for incoming PC notifications
  await NotificationMirrorService.initialize();

  // Start polling for incoming KDE Connect packets (notifications, etc.)
  _startPacketPoller();

  debugPrint('Linux Link initialization complete');

  runApp(
    const ProviderScope(
      child: LinuxLinkApp(),
    ),
  );
}

class LinuxLinkApp extends StatelessWidget {
  const LinuxLinkApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: 'Linux Link',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorSchemeSeed: Colors.blue,
      ),
      routerConfig: _router,
    );
  }
}
