import 'package:flutter_riverpod/flutter_riverpod.dart';

final isStreamingProvider = StateProvider<bool>((ref) => false);

final latencyProvider = StateProvider<int>((ref) => 0);
