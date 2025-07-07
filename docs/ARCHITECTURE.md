# LinuxLink Architecture Overview

## System Design
LinuxLink is a two-part system:
- **Android App:** Kotlin, Jetpack Compose, Retrofit, secure storage
- **Backend API:** FastAPI, Python, JWT, async system monitoring, secure command execution

## Stack
| Component   | Technology                |
|------------|---------------------------|
| Frontend   | Kotlin, Jetpack Compose   |
| Backend    | FastAPI, Python 3.10+     |
| Auth       | JWT, EncryptedSharedPrefs |
| Streaming  | WebSocket (future)        |
| Security   | Audit logs, allowlist, sandbox |
| Deployment | Docker, docker-compose    |

## Security Model
- **JWT-based authentication** for all API calls
- **Command allowlist & sandbox** (no shell=True, path restrictions)
- **Audit logging** for all actions
- **Encrypted token storage** on device
- **Biometric/app lock** for mobile app
- **CORS** and HTTPS enforced in production

## Data Flow
1. User logs in via app → receives JWT
2. App sends commands/stats requests with JWT
3. Backend validates, executes securely, returns results
4. All actions logged for audit

---

See `API.md` for endpoint details and `SETUP.md` for deployment instructions. 