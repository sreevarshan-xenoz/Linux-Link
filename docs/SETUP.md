# LinuxLink Setup Guide

## Prerequisites
- Python 3.10+
- Docker & docker-compose (optional, recommended)
- Android Studio (for app)
- Linux system (for backend)

---

## Backend Setup (FastAPI)

### 1. Clone the repo
```sh
git clone https://github.com/yourusername/linuxlink.git
cd linuxlink/backend-api
```

### 2. Install dependencies
```sh
pip install -r requirements.txt
```

### 3. Set environment variables
- `JWT_SECRET` (required, change in production)
- `SAFE_MODE` (default: true)

### 4. Run the server
```sh
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 5. Or use Docker Compose
```sh
cd ..
docker-compose up --build
```

---

## Android App Setup

### 1. Open in Android Studio
- File > Open > Select `/android-client/`

### 2. Configure backend URL
- Edit `BASE_URL` in the API service class to point to your backend (e.g. `http://192.168.1.100:8000/`)

### 3. Build & Run
- Connect your device or use an emulator
- Click Run

---

## Troubleshooting
- **CORS errors:** Ensure backend allows your app's origin
- **Token errors:** Check JWT_SECRET matches between backend and app
- **Network issues:** Ensure devices are on the same LAN or hotspot
- **Permission denied:** Run backend as a user with required permissions

---

## Real-World Test Checklist
- [ ] Login from app and receive JWT
- [ ] Execute safe commands (e.g. `ls`, `uptime`)
- [ ] Block dangerous commands (e.g. `rm -rf /`)
- [ ] View system stats in app
- [ ] All actions logged in `audit.log`
- [ ] App lock and token storage work as expected

---

See `API.md` for endpoint details and `SECURITY.md` for security best practices. 