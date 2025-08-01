# Security Notice

## ⚠️ Important Security Configuration

### JWT Secret Key
The application requires a secure JWT secret key. **Never use the default values in production!**

1. **Generate a secure secret:**
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Set the environment variable:**
   ```bash
   export JWT_SECRET="your-generated-secret-here"
   ```

3. **For Docker deployment:**
   - Copy `.env.example` to `.env`
   - Update the `JWT_SECRET` value
   - Use `docker-compose --env-file .env up`

### Default Credentials
- Change all default usernames and passwords before deployment
- The test credentials in documentation are for example purposes only
- Never use test credentials in production

### File Permissions
Ensure these files have restricted permissions:
```bash
chmod 600 .env
chmod 600 ~/.linux_link_*
chmod 700 ~/.linux_link_certs/
```

### Security Checklist
- [ ] JWT_SECRET is set to a secure random value
- [ ] Default credentials are changed
- [ ] HTTPS is enabled in production
- [ ] Firewall rules are configured
- [ ] File permissions are restricted
- [ ] Audit logging is enabled
- [ ] Rate limiting is configured

## Reporting Security Issues
If you discover a security vulnerability, please email: security@linuxlink.dev