import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'rust_api_bridge.dart' as bridge;
import 'screens/connection_screen.dart';
import 'screens/remote_desktop_screen.dart';
import 'screens/file_browser_screen.dart';
import 'screens/settings_screen.dart';
import 'services/background_service.dart';

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
        final address = state.uri.queryParameters['address'] ?? '';
        final port = int.tryParse(state.uri.queryParameters['port'] ?? '1716') ?? 1716;
        return RemoteDesktopScreen(
          address: address,
          port: port,
        );
      },
    ),
    GoRoute(
      path: '/files',
      builder: (context, state) {
        final address = state.uri.queryParameters['address'] ?? '';
        final port = int.tryParse(state.uri.queryParameters['port'] ?? '1716') ?? 1716;
        return FileBrowserScreen(
          address: address,
          port: port,
        );
      },
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
  ],
);

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the Rust backend
  await bridge.rustApi.init();

  // Initialize the Android foreground service
  await initBackgroundService();

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
