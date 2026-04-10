import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'rust_api_bridge.dart';
import 'screens/connection_screen.dart';
import 'screens/remote_desktop_screen.dart';
import 'screens/file_browser_screen.dart';
import 'screens/settings_screen.dart';

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
        final args = state.arguments as Map<String, dynamic>?;
        return RemoteDesktopScreen(
          address: args?['address'] as String? ?? '',
          port: args?['port'] as int? ?? 1716,
        );
      },
    ),
    GoRoute(
      path: '/files',
      builder: (context, state) {
        final args = state.arguments as Map<String, dynamic>?;
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
  ],
);

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize the Rust backend
  await rustApi.init();

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
