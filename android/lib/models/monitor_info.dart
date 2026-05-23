class MonitorInfo {
  final int index;
  final String name;
  final int width;
  final int height;
  final bool isPrimary;

  const MonitorInfo({
    required this.index,
    required this.name,
    required this.width,
    required this.height,
    required this.isPrimary,
  });

  String get resolution => '${width}x$height';

  @override
  String toString() => '$name ($resolution)';
}
