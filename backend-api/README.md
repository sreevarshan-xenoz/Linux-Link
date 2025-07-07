# LinuxLink Backend API

This is the FastAPI backend for LinuxLink: Mobile Terminal Overlord. It provides secure, real-time command execution, system monitoring, and authentication for remote Linux administration.

## Features
- JWT-based authentication
- Secure command execution (allowlist, sandboxed, no shell=True)
- Async system stats (CPU, RAM, disk, network)
- Audit logging for all actions
- Docker-ready for easy deployment

## Endpoints
- `POST /auth/login` — Obtain JWT token
- `POST /auth/verify-token` — Validate token
- `POST /exec` — Execute a safe command (with validation)
- `GET /sys/stats` — Get system stats (async, cached)
- `GET /sys/quick-status` — One-tap health check (services, logs, uptime)

## Setup

1. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```
2. **Run the server:**
   ```sh
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```
3. **Or use Docker Compose:**
   ```sh
   docker-compose up --build
   ```

## Security Notes
- All endpoints require JWT except `/auth/login`
- Commands are validated and sandboxed (see `security.py`)
- All actions are logged to `audit.log`
- Change the `JWT_SECRET` in production!

---

See `/docs/API.md` for full API documentation. 