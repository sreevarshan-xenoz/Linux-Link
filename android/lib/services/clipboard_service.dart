import 'package:flutter/services.dart';

class ClipboardService {
  static Future<String?> getClipboard() async {
    final clipboardData = await Clipboard.getData(Clipboard.kTextPlain);
    return clipboardData?.text;
  }

  static Future<void> setClipboard(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
  }
}
