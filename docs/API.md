# Linux-Link API Documentation

## Authentication
All endpoints (except `/auth/login`) require a valid JWT in the `Authorization: Bearer <token>` header.

---

## Endpoints

### 1. `POST /auth/login`
Authenticate and receive a JWT token.

**Request:**
```json
{
  "username": "serrvarshan-xenoz",
  "password": "linuxlink123"
}
```
**Response:**
```json
{
  "access_token": "<JWT>",
  "token_type": "bearer"
}
```
**Errors:**
- 401: Invalid credentials

---

### 2. `POST /auth/verify-token`
Verify if a JWT token is valid.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "valid": true,
  "user": "serrvarshan-xenoz"
}
```
**Errors:**
- 401: Token expired/invalid

---

### 3. `POST /exec`
Execute a safe, allowlisted command on the server.

**Headers:**
- `Authorization: Bearer <token>`

**Request:**
```json
{
  "cmd": "ls -la",
  "timeout": 30
}
```
**Response:**
```json
{
  "stdout": "...",
  "stderr": "...",
  "returncode": 0,
  "command": "ls -la",
  "safe_mode": true,
  "execution_time": 30
}
```
**Errors:**
- 400: Command not allowed/invalid
- 408: Command timeout
- 500: Execution error

---

### 4. `GET /sys/stats`
Get real-time system stats (CPU, RAM, disk, network, uptime).

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "cpu": { ... },
  "memory": { ... },
  "disk": { ... },
  "network": { ... },
  "timestamp": "...",
  "uptime": "...",
  "cached": true
}
```
**Errors:**
- 500: Failed to retrieve stats

---

### 5. `GET /sys/quick-status`
Get a one-tap health check (CPU, RAM, disk, uptime, running services, recent errors).

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "system_stats": {
    "cpu_percent": 12.5,
    "memory_percent": 45.2,
    "disk_percent": 67.1,
    "uptime": "1d 2h 30m"
  },
  "critical_info": {
    "running_services": 42,
    "recent_errors": ["..."]
  },
  "timestamp": "..."
}
```
**Errors:**
- 500: Failed to retrieve quick status

---

## Security Notes
- All commands are validated and sandboxed (see `security.py`)
- Dangerous or restricted commands are blocked
- All actions are logged to `audit.log`

## Example Usage (cURL)
```sh
# Login
curl -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" -d '{"username":"serrvarshan-xenoz","password":"linuxlink123"}'

# Execute command
curl -X POST http://localhost:8000/exec -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" -d '{"cmd":"ls -la"}'

# Get system stats
curl -X GET http://localhost:8000/sys/stats -H "Authorization: Bearer <JWT>"
``` 