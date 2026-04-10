class PeerInfo {
  final String name;
  final String dnsName;
  final List<String> ips;
  final bool online;

  const PeerInfo({
    required this.name,
    required this.dnsName,
    required this.ips,
    required this.online,
  });

  Map<String, dynamic> toJson() => {
        'name': name,
        'dnsName': dnsName,
        'ips': ips,
        'online': online,
      };

  factory PeerInfo.fromJson(Map<String, dynamic> json) => PeerInfo(
        name: json['name'] ?? '',
        dnsName: json['dnsName'] ?? '',
        ips: List<String>.from(json['ips'] ?? []),
        online: json['online'] ?? false,
      );
}
