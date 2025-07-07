# LinuxLink Android Client

This is the Jetpack Compose Android app for LinuxLink: Mobile Terminal Overlord. It provides a secure, real-time mobile interface for remote Linux administration.

## Features
- Terminal command execution (via FastAPI backend)
- System monitor dashboard
- File explorer (coming soon)
- Voice command interface (coming soon)
- Secure token storage (EncryptedSharedPrefs/Keystore)
- Biometric app lock (optional)

## Setup

1. **Open in Android Studio:**
   - File > Open > Select `/android-client/`
2. **Configure backend URL:**
   - Edit `BASE_URL` in the API service class to point to your FastAPI backend.
3. **Build & Run:**
   - Connect your Android device or use an emulator.
   - Click Run.

## Architecture
- Jetpack Compose for UI
- MVVM (ViewModel, Repository)
- Retrofit for API calls
- Hilt for dependency injection (optional)
- EncryptedSharedPrefs for secure storage

---

See `/docs/` for full architecture and API documentation. 