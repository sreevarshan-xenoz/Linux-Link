# Linux-Link: Mobile Terminal Overlord

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20Linux-blue)](https://github.com/serrvarshan-xenoz/linux-link)
[![Backend](https://img.shields.io/badge/backend-FastAPI-yellow)](backend-api/README.md)

---

## 🚀 Demo

https://user-images.githubusercontent.com/your-github-id/videos/demo.mp4

Or watch below:

<video src="videos/demo.mp4" controls width="600"></video>

---

## About
**Linux-Link** is a next-generation mobile remote control panel for your Linux machine. Secure, real-time, and feature-rich — combining terminal, file explorer, system monitor, voice commands, and GUI access in one app.

---

## ✨ Features
- 🔒 Secure JWT login & encrypted token storage
- 🖥️ Terminal: Run commands, get real-time output, command history & autosuggest
- 📊 System Monitor: Live CPU, RAM, disk, uptime stats
- 📂 File Explorer: Browse, upload, download (coming soon)
- 🎙️ Voice Commands: Control Linux with your voice (coming soon)
- 🛡️ Audit logging, allowlist, sandboxed backend
- 📱 Modern Android UI (Jetpack Compose)
- 🚪 Logout & automatic token expiry handling

---

## 📦 Quickstart

### Backend (FastAPI)
```sh
git clone https://github.com/serrvarshan-xenoz/linux-link.git
cd linux-link/backend-api
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000
```
Or with Docker Compose:
```sh
cd ..
docker-compose up --build
```

### Android App
- Open `/android-client/` in Android Studio
- Set your backend URL in the API service class
- Build & run on your device or emulator

---

## 🛠️ Development Environment Setup

### Prerequisites

**For Backend:**
- Python 3.10+
- pip (Python package manager)
- Docker & docker-compose (recommended)
- Linux system (Ubuntu, Arch, etc.)

**For Android App:**
- Android Studio (latest version)
- Android SDK (API level 24+)
- Java/Kotlin development environment

---

### Backend Setup (FastAPI)

#### Method 1: Manual Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/serrvarshan-xenoz/linux-link.git
   cd linux-link/backend-api
   ```

2. **Create Virtual Environment (Recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Linux/Mac
   # or
   # venv\Scripts\activate     # On Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set Environment Variables**
   ```bash
   export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   export SAFE_MODE="true"
   ```

5. **Run the Development Server**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

#### Method 2: Docker Compose (Recommended)

1. **Clone and Navigate**
   ```bash
   git clone https://github.com/serrvarshan-xenoz/linux-link.git
   cd linux-link
   ```

2. **Update Environment Variables**
   Edit `docker-compose.yml` and change the `JWT_SECRET`:
   ```yaml
   environment:
     - JWT_SECRET=${JWT_SECRET}
     - SAFE_MODE=true
   ```

3. **Build and Run**
   ```bash
   docker-compose up --build
   ```

---

### Android App Setup

1. **Open Project in Android Studio**
   - Launch Android Studio
   - Select `File > Open`
   - Navigate to `/android-client/` directory
   - Click "Open"

2. **Configure Backend URL**
   - Open `app/src/main/java/com/linuxlink/data/api/ApiService.kt`
   - Update the `BASE_URL` constant:
   ```kotlin
   private const val BASE_URL = "http://YOUR_BACKEND_IP:8000/"
   // Example: "http://192.168.1.100:8000/"
   ```

3. **Sync Project**
   - Let Android Studio sync the project dependencies
   - Wait for Gradle build to complete

4. **Connect Device or Setup Emulator**
   - **Physical Device:** Enable USB debugging and connect via USB
   - **Emulator:** Create an AVD with API level 24+ in AVD Manager

5. **Build and Run**
   - Click the "Run" button (green play icon)
   - Select your target device
   - App will install and launch automatically

---

### Network Configuration

**For Local Development:**
- Ensure both devices are on the same network (WiFi/LAN)
- Find your backend server's IP: `ip addr show` or `ifconfig`
- Use that IP in the Android app's `BASE_URL`

**For Testing:**
- Backend URL format: `http://[IP_ADDRESS]:8000/`
- Example: `http://192.168.1.100:8000/`
- Test backend accessibility: `curl http://[IP]:8000/health`

---

### Troubleshooting

**Common Issues:**

| Problem | Solution |
|---------|----------|
| CORS errors | Ensure backend allows your app's origin |
| JWT token errors | Verify `JWT_SECRET` matches between backend and app |
| Network connection failed | Check devices are on same network, firewall settings |
| Permission denied (backend) | Run backend with appropriate user permissions |
| Android build errors | Clean project, invalidate caches, restart Android Studio |
| Dependencies not found | Run `pip install -r requirements.txt` again |

**Debug Steps:**
1. Check backend logs: `docker-compose logs` or terminal output
2. Verify API endpoints: Visit `http://[IP]:8000/docs` for Swagger UI
3. Check Android logcat for detailed error messages
4. Ensure firewall allows port 8000

---

### Development Workflow

**Testing Checklist:**
- [ ] Backend starts without errors
- [ ] API documentation accessible at `/docs`
- [ ] Android app connects and logs in successfully
- [ ] JWT authentication working
- [ ] Terminal commands execute safely
- [ ] System monitoring displays real-time data
- [ ] Dangerous commands are blocked (test with `rm -rf /tmp/test`)
- [ ] Audit log captures all activities
- [ ] App handles network disconnections gracefully

**Development Tips:**
- Use `--reload` flag with uvicorn for hot-reloading during development
- Check `audit.log` for debugging authentication and command execution
- Use Android Studio's logcat for debugging mobile app issues
- Test with both safe and restricted commands to verify security

---

## 📚 Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Setup Guide](docs/SETUP.md)
- [Security Model](docs/SECURITY.md)

---

## 🚧 Future Plans & Upgrades
- **File Explorer:** Full-featured file management (list, upload, download, delete, preview)
- **Voice Commands:** Android STT integration, natural language command parsing
- **Remote GUI:** VNC/Waypipe/noVNC integration for full graphical access
- **Task Automation:** Macros, routines, and scheduled command execution
- **Customizable Presets:** User-defined quick command buttons
- **Dark Mode & Theming:** UI customization and power-saving mode
- **Settings Screen:** Backend URL, refresh rates, security options
- **Push Notifications:** System alerts, job completions, and critical events
- **Multi-Server Support:** Manage multiple Linux machines from one app
- **Plugin/Extension System:** Community-driven feature expansion
- **Team/Collaboration Features:** Shared command history, audit logs, multi-user access
- **Open Source Community:** Contribution guidelines, issue templates, and more

---

## 🤝 Contributing
Pull requests and issues are welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

---

## License
MIT — see [LICENSE](LICENSE)

---

> Linux-Link is in active development. Star the repo and follow for updates!
