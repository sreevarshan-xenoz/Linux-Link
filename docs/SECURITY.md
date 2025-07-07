# Linux-Link Security Model

## Overview
Linux-Link is designed for secure remote Linux administration. Security is enforced at every layer: authentication, command execution, data storage, and network communication.

---

## Authentication
- **JWT-based authentication** for all API calls
- Tokens expire after 24 hours (configurable)
- All endpoints except `/auth/login` require a valid JWT
- Token validation and expiration enforced server-side

## Command Execution Security
- **Allowlist & sandbox:** Only safe, allowlisted commands are executed
- **No `shell=True`:** Commands are parsed and run as argument lists
- **Dangerous patterns blocked:** (e.g. `rm -rf /`, fork bombs, device writes)
- **Restricted paths:** Access to `/root`, `/etc/shadow`, etc. is denied
- **Timeouts:** All commands have a max execution time (default: 30s)
- **Audit logging:** Every action is logged with timestamp, user, command, and result

## System Monitoring
- Stats are read-only and do not expose sensitive data
- All stats endpoints require authentication

## Mobile App Security
- **Encrypted token storage:** JWTs are stored using EncryptedSharedPrefs or Android Keystore
- **App lock:** Optional biometric or password lock on app launch
- **No sensitive data in logs:** App avoids logging tokens or command output

## Network Security
- **HTTPS recommended:** Always deploy backend behind HTTPS (use Caddy, Nginx, or a cloud load balancer)
- **CORS:** Backend restricts allowed origins in production
- **Certificate pinning:** (Recommended for production apps)

## Threat Mitigation
- **Command injection:** Prevented by argument parsing and allowlist
- **Privilege escalation:** Backend should run as a non-root user
- **Replay attacks:** JWTs expire and can be revoked by changing secret
- **Brute force:** Rate limit login attempts (future enhancement)

## Best Practices
- Change `JWT_SECRET` before deploying
- Run backend as a dedicated, non-root user
- Use HTTPS for all API traffic
- Regularly review `audit.log` for suspicious activity
- Keep dependencies up to date

---

See `ARCHITECTURE.md` for system design and `API.md` for endpoint details. 