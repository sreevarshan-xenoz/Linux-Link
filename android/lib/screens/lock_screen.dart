import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Pin pad button for the lock screen.
class _PinButton extends StatelessWidget {
  final String label;
  final IconData? icon;
  final VoidCallback? onPressed;

  const _PinButton({
    required this.label,
    this.icon,
    this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 72,
      height: 72,
      child: Material(
        color: Colors.white12,
        borderRadius: BorderRadius.circular(36),
        child: InkWell(
          borderRadius: BorderRadius.circular(36),
          onTap: onPressed != null ? () {
            HapticFeedback.lightImpact();
            onPressed!();
          } : null,
          child: Center(
            child: icon != null
                ? Icon(icon, color: Colors.white70, size: 28)
                : Text(
                    label,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 24,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
          ),
        ),
      ),
    );
  }
}

/// Screen lock passcode entry screen.
///
/// Prompts the user for a passcode to unlock the streaming session.
/// Shows a blurred stream behind the lock screen (simulated with a dark overlay).
/// On first use, prompts to set a passcode.
class LockScreen extends StatefulWidget {
  /// Called when the passcode is correctly entered.
  final VoidCallback onUnlock;

  /// Called when the user wants to disconnect instead.
  final VoidCallback onDisconnect;

  const LockScreen({
    super.key,
    required this.onUnlock,
    required this.onDisconnect,
  });

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final _pinController = TextEditingController();
  final _focusNode = FocusNode();
  String _enteredPin = '';
  int _attempts = 0;
  static const int _maxAttempts = 5;
  bool _isLocked = true;
  String? _storedPin;
  bool _isSettingPin = false;
  bool _isConfirmingPin = false;
  String _firstPin = '';

  static const _pinKey = 'screen_lock_pin';
  static const _lockEnabledKey = 'screen_lock_enabled';

  @override
  void initState() {
    super.initState();
    _loadPin();
  }

  @override
  void dispose() {
    _pinController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _loadPin() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _storedPin = prefs.getString(_pinKey);
      _isSettingPin = _storedPin == null || _storedPin!.isEmpty;
    });
  }

  Future<void> _savePin(String pin) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_pinKey, pin);
    await prefs.setBool(_lockEnabledKey, true);
    setState(() {
      _storedPin = pin;
      _isSettingPin = false;
      _isConfirmingPin = false;
      _firstPin = '';
    });
  }

  void _onPinDigit(String digit) {
    if (_enteredPin.length >= 6) return;
    setState(() {
      _enteredPin += digit;
    });
    if (_enteredPin.length == 6) {
      _verifyPin();
    }
  }

  void _onDelete() {
    if (_enteredPin.isNotEmpty) {
      setState(() {
        _enteredPin = _enteredPin.substring(0, _enteredPin.length - 1);
      });
    }
  }

  void _verifyPin() {
    if (_isSettingPin) {
      if (_isConfirmingPin) {
        if (_enteredPin == _firstPin) {
          _savePin(_enteredPin);
          setState(() {
            _isLocked = false;
          });
          widget.onUnlock();
        } else {
          setState(() {
            _isConfirmingPin = false;
            _firstPin = '';
            _enteredPin = '';
          });
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('PINs do not match. Try again.'),
              backgroundColor: Colors.redAccent,
              duration: Duration(seconds: 2),
            ),
          );
        }
      } else {
        setState(() {
          _firstPin = _enteredPin;
          _isConfirmingPin = true;
          _enteredPin = '';
        });
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Confirm your PIN'),
            duration: Duration(seconds: 2),
          ),
        );
      }
      return;
    }

    if (_enteredPin == _storedPin) {
      setState(() {
        _isLocked = false;
        _attempts = 0;
      });
      HapticFeedback.heavyImpact();
      widget.onUnlock();
    } else {
      setState(() {
        _attempts++;
        _enteredPin = '';
      });
      HapticFeedback.heavyImpact();
      if (_attempts >= _maxAttempts) {
        widget.onDisconnect();
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Incorrect PIN. ${_maxAttempts - _attempts} attempts remaining.',
            ),
            backgroundColor: Colors.redAccent,
            duration: const Duration(seconds: 2),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final isLockedState = _isLocked && _storedPin != null && _storedPin!.isNotEmpty;

    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Column(
          children: [
            const Spacer(flex: 2),
            // Lock icon
            Icon(
              isLockedState ? Icons.lock_outline : Icons.lock_open,
              size: 48,
              color: Colors.white38,
            ),
            const SizedBox(height: 16),
            // Title
            Text(
              _isSettingPin
                  ? (_isConfirmingPin ? 'Confirm PIN' : 'Set Screen Lock PIN')
                  : 'Screen Locked',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 20,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              _isSettingPin
                  ? 'Enter a 6-digit PIN'
                  : 'Enter PIN to unlock',
              style: const TextStyle(color: Colors.white54, fontSize: 14),
            ),
            const SizedBox(height: 32),
            // PIN dots display
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: List.generate(6, (i) {
                final filled = i < _enteredPin.length;
                return Container(
                  width: 16,
                  height: 16,
                  margin: const EdgeInsets.symmetric(horizontal: 8),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: filled ? Colors.blueAccent : Colors.white24,
                    border: Border.all(
                      color: filled ? Colors.blueAccent : Colors.white24,
                      width: 2,
                    ),
                  ),
                );
              }),
            ),
            const SizedBox(height: 32),
            // Attempts remaining warning
            if (_attempts > 0 && isLockedState)
              Text(
                '${_maxAttempts - _attempts} attempts remaining',
                style: const TextStyle(color: Colors.orangeAccent, fontSize: 12),
              ),
            const Spacer(flex: 1),
            // PIN pad
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 48),
              child: Column(
                children: [
                  // Row 1: 1 2 3
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _PinButton(label: '1', onPressed: () => _onPinDigit('1')),
                      _PinButton(label: '2', onPressed: () => _onPinDigit('2')),
                      _PinButton(label: '3', onPressed: () => _onPinDigit('3')),
                    ],
                  ),
                  const SizedBox(height: 16),
                  // Row 2: 4 5 6
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _PinButton(label: '4', onPressed: () => _onPinDigit('4')),
                      _PinButton(label: '5', onPressed: () => _onPinDigit('5')),
                      _PinButton(label: '6', onPressed: () => _onPinDigit('6')),
                    ],
                  ),
                  const SizedBox(height: 16),
                  // Row 3: 7 8 9
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _PinButton(label: '7', onPressed: () => _onPinDigit('7')),
                      _PinButton(label: '8', onPressed: () => _onPinDigit('8')),
                      _PinButton(label: '9', onPressed: () => _onPinDigit('9')),
                    ],
                  ),
                  const SizedBox(height: 16),
                  // Row 4: clear 0 backspace
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      _PinButton(
                        label: '',
                        icon: Icons.clear_all,
                        onPressed: () {
                          setState(() => _enteredPin = '');
                        },
                      ),
                      _PinButton(label: '0', onPressed: () => _onPinDigit('0')),
                      _PinButton(
                        label: '',
                        icon: Icons.backspace_outlined,
                        onPressed: _onDelete,
                      ),
                    ],
                  ),
                ],
              ),
            ),
            const Spacer(flex: 2),
            // Disconnect button
            TextButton.icon(
              onPressed: widget.onDisconnect,
              icon: const Icon(Icons.power_settings_new, color: Colors.redAccent),
              label: const Text(
                'Disconnect',
                style: TextStyle(color: Colors.redAccent),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
