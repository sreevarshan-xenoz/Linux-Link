import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
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
      builder: (context, state) => const RemoteDesktopScreen(),
    ),
    GoRoute(
      path: '/files',
      builder: (context, state) => const FileBrowserScreen(),
    ),
    GoRoute(
      path: '/settings',
      builder: (context, state) => const SettingsScreen(),
    ),
  ],
);

void main() {
  WidgetsFlutterBinding.ensureInitialized();

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
