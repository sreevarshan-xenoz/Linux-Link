"""
Linux-Link Security Module

Provides comprehensive security features including certificate-based authentication,
2FA support, user role management, and secure command execution.
"""

import os
import ssl
import json
import time
import hmac
import hashlib
import secrets
import logging
import subprocess
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import jwt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import pyotp
import qrcode
from io import BytesIO
import base64

logger = logging.getLogger(__name__)


class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"
    GUEST = "guest"


class AuthMethod(Enum):
    PASSWORD = "password"
    CERTIFICATE = "certificate"
    TWO_FACTOR = "2fa"
    API_KEY = "api_key"


@dataclass
class User:
    """Represents a system user with authentication and authorization info"""
    username: str
    role: UserRole
    auth_methods: List[AuthMethod]
    created_at: float
    last_login: Optional[float] = None
    password_hash: Optional[str] = None
    certificate_fingerprint: Optional[str] = None
    totp_secret: Optional[str] = None
    api_keys: List[str] = None
    enabled: bool = True
    failed_attempts: int = 0
    locked_until: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['role'] = self.role.value
        data['auth_methods'] = [method.value for method in self.auth_methods]
        # Don't include sensitive data in serialization
        data.pop('password_hash', None)
        data.pop('totp_secret', None)
        data.pop('api_keys', None)
        return data


@dataclass
class Certificate:
    """Represents a client certificate"""
    fingerprint: str
    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    username: str
    created_at: float
    revoked: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['not_before'] = self.not_before.isoformat()
        data['not_after'] = self.not_after.isoformat()
        return data


class SecurityError(Exception):
    """Base exception for security operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class CertificateManager:
    """Manages client certificates for authentication"""
    
    def __init__(self, cert_dir: str = None):
        self.cert_dir = cert_dir or os.path.expanduser('~/.linux_link_certs')
        self.ca_cert_path = os.path.join(self.cert_dir, 'ca.crt')
        self.ca_key_path = os.path.join(self.cert_dir, 'ca.key')
        self.certificates = {}
        self._ensure_cert_dir()
        self._load_certificates()
        logger.info("Certificate manager initialized")
    
    def _ensure_cert_dir(self):
        """Ensure certificate directory exists"""
        os.makedirs(self.cert_dir, mode=0o700, exist_ok=True)
    
    def _load_certificates(self):
        """Load certificates from storage"""
        try:
            cert_file = os.path.join(self.cert_dir, 'certificates.json')
            if os.path.exists(cert_file):
                with open(cert_file, 'r') as f:
                    data = json.load(f)
                    for cert_data in data.get('certificates', []):
                        cert = Certificate(
                            fingerprint=cert_data['fingerprint'],
                            subject=cert_data['subject'],
                            issuer=cert_data['issuer'],
                            serial_number=cert_data['serial_number'],
                            not_before=datetime.fromisoformat(cert_data['not_before']),
                            not_after=datetime.fromisoformat(cert_data['not_after']),
                            username=cert_data['username'],
                            created_at=cert_data['created_at'],
                            revoked=cert_data.get('revoked', False)
                        )
                        self.certificates[cert.fingerprint] = cert
                logger.info(f"Loaded {len(self.certificates)} certificates")
        except Exception as e:
            logger.debug(f"Could not load certificates: {e}")
            self.certificates = {}
    
    def _save_certificates(self):
        """Save certificates to storage"""
        try:
            cert_file = os.path.join(self.cert_dir, 'certificates.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'certificates': [cert.to_dict() for cert in self.certificates.values()]
            }
            
            with open(cert_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved {len(self.certificates)} certificates")
        except Exception as e:
            logger.error(f"Failed to save certificates: {e}")
    
    def generate_ca_certificate(self) -> bool:
        """Generate CA certificate and key"""
        try:
            if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
                logger.info("CA certificate already exists")
                return True
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Linux-Link"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Linux-Link CA"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=3650)  # 10 years
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    key_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).sign(private_key, hashes.SHA256())
            
            # Save private key
            with open(self.ca_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            os.chmod(self.ca_key_path, 0o600)
            
            # Save certificate
            with open(self.ca_cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            logger.info("CA certificate generated successfully")
            return True
        
        except Exception as e:
            logger.error(f"Failed to generate CA certificate: {e}")
            return False
    
    def generate_client_certificate(self, username: str, common_name: str = None) -> Optional[Tuple[str, str]]:
        """Generate client certificate for user"""
        try:
            if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
                if not self.generate_ca_certificate():
                    raise SecurityError("Failed to generate CA certificate", "CA_GENERATION_FAILED")
            
            # Load CA certificate and key
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            
            with open(self.ca_key_path, 'rb') as f:
                ca_key = load_pem_private_key(f.read(), password=None)
            
            # Generate client private key
            client_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Generate client certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Linux-Link"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name or username),
            ])
            
            client_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                client_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)  # 1 year
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=True,
            ).sign(ca_key, hashes.SHA256())
            
            # Get certificate fingerprint
            fingerprint = client_cert.fingerprint(hashes.SHA256()).hex()
            
            # Store certificate info
            cert_info = Certificate(
                fingerprint=fingerprint,
                subject=client_cert.subject.rfc4514_string(),
                issuer=client_cert.issuer.rfc4514_string(),
                serial_number=str(client_cert.serial_number),
                not_before=client_cert.not_valid_before,
                not_after=client_cert.not_valid_after,
                username=username,
                created_at=time.time()
            )
            
            self.certificates[fingerprint] = cert_info
            self._save_certificates()
            
            # Return certificate and key as PEM strings
            cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            key_pem = client_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            logger.info(f"Generated client certificate for user: {username}")
            return cert_pem, key_pem
        
        except Exception as e:
            logger.error(f"Failed to generate client certificate: {e}")
            return None
    
    def verify_certificate(self, cert_pem: str) -> Optional[Certificate]:
        """Verify client certificate"""
        try:
            # Load client certificate
            client_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            
            # Check if certificate is expired
            now = datetime.utcnow()
            if now < client_cert.not_valid_before or now > client_cert.not_valid_after:
                logger.warning("Certificate is expired or not yet valid")
                return None
            
            # Get certificate fingerprint
            fingerprint = client_cert.fingerprint(hashes.SHA256()).hex()
            
            # Check if certificate is registered and not revoked
            cert_info = self.certificates.get(fingerprint)
            if not cert_info or cert_info.revoked:
                logger.warning(f"Certificate not found or revoked: {fingerprint}")
                return None
            
            # Load CA certificate for verification
            if not os.path.exists(self.ca_cert_path):
                logger.error("CA certificate not found")
                return None
            
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            
            # Verify certificate signature
            try:
                ca_cert.public_key().verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    client_cert.signature_hash_algorithm
                )
            except Exception:
                logger.warning("Certificate signature verification failed")
                return None
            
            logger.info(f"Certificate verified for user: {cert_info.username}")
            return cert_info
        
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return None
    
    def revoke_certificate(self, fingerprint: str) -> bool:
        """Revoke a certificate"""
        try:
            if fingerprint in self.certificates:
                self.certificates[fingerprint].revoked = True
                self._save_certificates()
                logger.info(f"Certificate revoked: {fingerprint}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")
            return False
    
    def list_certificates(self, username: str = None) -> List[Certificate]:
        """List certificates, optionally filtered by username"""
        try:
            certs = list(self.certificates.values())
            if username:
                certs = [cert for cert in certs if cert.username == username]
            return certs
        except Exception as e:
            logger.error(f"Failed to list certificates: {e}")
            return []


class TwoFactorAuth:
    """Handles TOTP-based two-factor authentication"""
    
    def __init__(self):
        self.issuer_name = "Linux-Link"
        logger.info("Two-factor auth initialized")
    
    def generate_secret(self, username: str) -> str:
        """Generate TOTP secret for user"""
        try:
            secret = pyotp.random_base32()
            logger.info(f"Generated TOTP secret for user: {username}")
            return secret
        except Exception as e:
            logger.error(f"Failed to generate TOTP secret: {e}")
            raise SecurityError("Failed to generate 2FA secret", "TOTP_GENERATION_FAILED")
    
    def generate_qr_code(self, username: str, secret: str) -> str:
        """Generate QR code for TOTP setup"""
        try:
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=username,
                issuer_name=self.issuer_name
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            logger.info(f"Generated QR code for user: {username}")
            return img_str
        
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            raise SecurityError("Failed to generate QR code", "QR_GENERATION_FAILED")
    
    def verify_token(self, secret: str, token: str) -> bool:
        """Verify TOTP token"""
        try:
            totp = pyotp.TOTP(secret)
            is_valid = totp.verify(token, valid_window=1)  # Allow 1 window tolerance
            
            if is_valid:
                logger.info("TOTP token verified successfully")
            else:
                logger.warning("TOTP token verification failed")
            
            return is_valid
        
        except Exception as e:
            logger.error(f"TOTP verification failed: {e}")
            return False


class SecureCommandExecutor:
    """Executes commands with security restrictions"""
    
    def __init__(self, safe_mode: bool = True):
        self.safe_mode = safe_mode
        self.allowed_commands = self._load_allowed_commands()
        self.blocked_patterns = self._load_blocked_patterns()
        logger.info(f"Secure command executor initialized (safe_mode: {safe_mode})")
    
    def _load_allowed_commands(self) -> List[str]:
        """Load list of allowed commands"""
        # In production, this would be loaded from configuration
        return [
            'ls', 'cat', 'grep', 'find', 'ps', 'top', 'df', 'du',
            'systemctl', 'journalctl', 'pacman', 'yay', 'paru',
            'git', 'docker', 'kubectl', 'ssh', 'scp', 'rsync'
        ]
    
    def _load_blocked_patterns(self) -> List[str]:
        """Load list of blocked command patterns"""
        return [
            r'rm\s+-rf\s+/',  # Dangerous rm commands
            r'dd\s+if=.*of=/dev/',  # Disk writing
            r'mkfs\.',  # Filesystem creation
            r'fdisk',  # Disk partitioning
            r'passwd\s+root',  # Root password change
            r'userdel',  # User deletion
            r'shutdown',  # System shutdown
            r'reboot',  # System reboot
            r'init\s+[06]',  # System halt/reboot
        ]
    
    def is_command_allowed(self, command: str, user_role: UserRole) -> bool:
        """Check if command is allowed for user role"""
        try:
            import re
            
            # Admin users have more privileges
            if user_role == UserRole.ADMIN:
                # Check blocked patterns
                for pattern in self.blocked_patterns:
                    if re.search(pattern, command, re.IGNORECASE):
                        logger.warning(f"Blocked dangerous command: {command}")
                        return False
                return True
            
            # Non-admin users in safe mode
            if self.safe_mode:
                cmd_parts = command.strip().split()
                if not cmd_parts:
                    return False
                
                base_command = cmd_parts[0]
                if base_command not in self.allowed_commands:
                    logger.warning(f"Command not in allowed list: {base_command}")
                    return False
            
            # Check blocked patterns for all users
            for pattern in self.blocked_patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    logger.warning(f"Blocked dangerous command: {command}")
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"Command validation failed: {e}")
            return False
    
    def execute_command(self, command: str, user_role: UserRole, timeout: int = 30) -> Dict[str, Any]:
        """Execute command with security checks"""
        try:
            if not self.is_command_allowed(command, user_role):
                raise SecurityError("Command not allowed", "COMMAND_BLOCKED")
            
            logger.info(f"Executing command: {command}")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'command': command
            }
        
        except subprocess.TimeoutExpired:
            raise SecurityError("Command timed out", "COMMAND_TIMEOUT")
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise SecurityError(f"Command execution failed: {str(e)}", "EXECUTION_FAILED")


# Global instances
_certificate_manager = None
_two_factor_auth = None
_command_executor = None


def get_certificate_manager() -> CertificateManager:
    """Get global certificate manager instance"""
    global _certificate_manager
    if _certificate_manager is None:
        _certificate_manager = CertificateManager()
    return _certificate_manager


def get_two_factor_auth() -> TwoFactorAuth:
    """Get global two-factor auth instance"""
    global _two_factor_auth
    if _two_factor_auth is None:
        _two_factor_auth = TwoFactorAuth()
    return _two_factor_auth


def get_command_executor() -> SecureCommandExecutor:
    """Get global command executor instance"""
    global _command_executor
    if _command_executor is None:
        _command_executor = SecureCommandExecutor()
    return _command_executor


class UserManager:
    """Manages users and their authentication methods"""
    
    def __init__(self):
        self.users = {}
        self.cert_manager = get_certificate_manager()
        self.tfa = get_two_factor_auth()
        self._load_users()
        logger.info("User manager initialized")
    
    def _load_users(self):
        """Load users from storage"""
        try:
            users_file = os.path.expanduser('~/.linux_link_users.json')
            if os.path.exists(users_file):
                with open(users_file, 'r') as f:
                    data = json.load(f)
                    for user_data in data.get('users', []):
                        user = User(
                            username=user_data['username'],
                            role=UserRole(user_data['role']),
                            auth_methods=[AuthMethod(method) for method in user_data['auth_methods']],
                            created_at=user_data['created_at'],
                            last_login=user_data.get('last_login'),
                            password_hash=user_data.get('password_hash'),
                            certificate_fingerprint=user_data.get('certificate_fingerprint'),
                            totp_secret=user_data.get('totp_secret'),
                            api_keys=user_data.get('api_keys', []),
                            enabled=user_data.get('enabled', True),
                            failed_attempts=user_data.get('failed_attempts', 0),
                            locked_until=user_data.get('locked_until')
                        )
                        self.users[user.username] = user
                logger.info(f"Loaded {len(self.users)} users")
        except Exception as e:
            logger.debug(f"Could not load users: {e}")
            self.users = {}
    
    def _save_users(self):
        """Save users to storage"""
        try:
            users_file = os.path.expanduser('~/.linux_link_users.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'users': []
            }
            
            for user in self.users.values():
                user_data = {
                    'username': user.username,
                    'role': user.role.value,
                    'auth_methods': [method.value for method in user.auth_methods],
                    'created_at': user.created_at,
                    'last_login': user.last_login,
                    'password_hash': user.password_hash,
                    'certificate_fingerprint': user.certificate_fingerprint,
                    'totp_secret': user.totp_secret,
                    'api_keys': user.api_keys,
                    'enabled': user.enabled,
                    'failed_attempts': user.failed_attempts,
                    'locked_until': user.locked_until
                }
                data['users'].append(user_data)
            
            with open(users_file, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(users_file, 0o600)  # Secure permissions
                
            logger.debug(f"Saved {len(self.users)} users")
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    def create_user(self, username: str, role: UserRole, auth_methods: List[AuthMethod]) -> bool:
        """Create a new user"""
        try:
            if username in self.users:
                raise SecurityError("User already exists", "USER_EXISTS")
            
            user = User(
                username=username,
                role=role,
                auth_methods=auth_methods,
                created_at=time.time(),
                api_keys=[]
            )
            
            self.users[username] = user
            self._save_users()
            
            logger.info(f"Created user: {username} with role: {role.value}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            return False
    
    def enable_2fa(self, username: str) -> Optional[Tuple[str, str]]:
        """Enable 2FA for user and return secret and QR code"""
        try:
            user = self.users.get(username)
            if not user:
                raise SecurityError("User not found", "USER_NOT_FOUND")
            
            # Generate TOTP secret
            secret = self.tfa.generate_secret(username)
            qr_code = self.tfa.generate_qr_code(username, secret)
            
            # Store secret (will be confirmed when user verifies first token)
            user.totp_secret = secret
            
            # Add 2FA to auth methods if not already present
            if AuthMethod.TWO_FACTOR not in user.auth_methods:
                user.auth_methods.append(AuthMethod.TWO_FACTOR)
            
            self._save_users()
            
            logger.info(f"2FA enabled for user: {username}")
            return secret, qr_code
        
        except Exception as e:
            logger.error(f"Failed to enable 2FA for {username}: {e}")
            return None
    
    def verify_2fa_setup(self, username: str, token: str) -> bool:
        """Verify 2FA setup with initial token"""
        try:
            user = self.users.get(username)
            if not user or not user.totp_secret:
                return False
            
            if self.tfa.verify_token(user.totp_secret, token):
                logger.info(f"2FA setup verified for user: {username}")
                return True
            else:
                # Remove unverified secret
                user.totp_secret = None
                user.auth_methods = [m for m in user.auth_methods if m != AuthMethod.TWO_FACTOR]
                self._save_users()
                return False
        
        except Exception as e:
            logger.error(f"2FA setup verification failed for {username}: {e}")
            return False
    
    def disable_2fa(self, username: str) -> bool:
        """Disable 2FA for user"""
        try:
            user = self.users.get(username)
            if not user:
                return False
            
            user.totp_secret = None
            user.auth_methods = [m for m in user.auth_methods if m != AuthMethod.TWO_FACTOR]
            self._save_users()
            
            logger.info(f"2FA disabled for user: {username}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to disable 2FA for {username}: {e}")
            return False
    
    def verify_2fa_token(self, username: str, token: str) -> bool:
        """Verify 2FA token for user"""
        try:
            user = self.users.get(username)
            if not user or not user.totp_secret:
                return False
            
            return self.tfa.verify_token(user.totp_secret, token)
        
        except Exception as e:
            logger.error(f"2FA token verification failed for {username}: {e}")
            return False
    
    def generate_client_certificate(self, username: str) -> Optional[Tuple[str, str]]:
        """Generate client certificate for user"""
        try:
            user = self.users.get(username)
            if not user:
                raise SecurityError("User not found", "USER_NOT_FOUND")
            
            cert_data = self.cert_manager.generate_client_certificate(username)
            if cert_data:
                cert_pem, key_pem = cert_data
                
                # Get certificate fingerprint
                cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
                
                # Store fingerprint with user
                user.certificate_fingerprint = fingerprint
                
                # Add certificate auth method if not present
                if AuthMethod.CERTIFICATE not in user.auth_methods:
                    user.auth_methods.append(AuthMethod.CERTIFICATE)
                
                self._save_users()
                
                logger.info(f"Generated client certificate for user: {username}")
                return cert_pem, key_pem
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to generate certificate for {username}: {e}")
            return None
    
    def authenticate_user(self, username: str, auth_method: AuthMethod, 
                         credentials: Dict[str, Any]) -> Optional[User]:
        """Authenticate user with specified method"""
        try:
            user = self.users.get(username)
            if not user or not user.enabled:
                return None
            
            # Check if user is locked
            if user.locked_until and time.time() < user.locked_until:
                logger.warning(f"User account locked: {username}")
                return None
            
            # Check if auth method is enabled for user
            if auth_method not in user.auth_methods:
                logger.warning(f"Auth method {auth_method.value} not enabled for user: {username}")
                return None
            
            authenticated = False
            
            if auth_method == AuthMethod.PASSWORD:
                password = credentials.get('password', '')
                if user.password_hash:
                    authenticated = self._verify_password(password, user.password_hash)
            
            elif auth_method == AuthMethod.CERTIFICATE:
                cert_pem = credentials.get('certificate', '')
                cert_info = self.cert_manager.verify_certificate(cert_pem)
                authenticated = cert_info and cert_info.username == username
            
            elif auth_method == AuthMethod.TWO_FACTOR:
                token = credentials.get('token', '')
                authenticated = self.verify_2fa_token(username, token)
            
            elif auth_method == AuthMethod.API_KEY:
                api_key = credentials.get('api_key', '')
                authenticated = api_key in (user.api_keys or [])
            
            if authenticated:
                # Reset failed attempts and update last login
                user.failed_attempts = 0
                user.locked_until = None
                user.last_login = time.time()
                self._save_users()
                
                logger.info(f"User authenticated: {username} via {auth_method.value}")
                return user
            else:
                # Increment failed attempts
                user.failed_attempts += 1
                if user.failed_attempts >= 5:  # Lock after 5 failed attempts
                    user.locked_until = time.time() + 1800  # Lock for 30 minutes
                    logger.warning(f"User account locked due to failed attempts: {username}")
                
                self._save_users()
                logger.warning(f"Authentication failed for user: {username}")
                return None
        
        except Exception as e:
            logger.error(f"Authentication error for {username}: {e}")
            return None
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            # Fallback to simple hash comparison (not recommended for production)
            import hashlib
            return hashlib.sha256(password.encode('utf-8')).hexdigest() == password_hash
    
    def set_password(self, username: str, password: str) -> bool:
        """Set password for user"""
        try:
            user = self.users.get(username)
            if not user:
                return False
            
            try:
                import bcrypt
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            except ImportError:
                # Fallback to simple hash (not recommended for production)
                import hashlib
                password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            
            user.password_hash = password_hash
            
            # Add password auth method if not present
            if AuthMethod.PASSWORD not in user.auth_methods:
                user.auth_methods.append(AuthMethod.PASSWORD)
            
            self._save_users()
            
            logger.info(f"Password set for user: {username}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to set password for {username}: {e}")
            return False
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.users.get(username)
    
    def list_users(self) -> List[User]:
        """List all users"""
        return list(self.users.values())
    
    def delete_user(self, username: str) -> bool:
        """Delete user"""
        try:
            if username in self.users:
                del self.users[username]
                self._save_users()
                logger.info(f"Deleted user: {username}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete user {username}: {e}")
            return False


# Global user manager instance
_user_manager = None


def get_user_manager() -> UserManager:
    """Get global user manager instance"""
    global _user_manager
    if _user_manager is None:
        _user_manager = UserManager()
    return _user_manager


class RoleBasedAccessControl:
    """Manages role-based access control and permissions"""
    
    def __init__(self):
        self.permissions = self._load_permissions()
        logger.info("Role-based access control initialized")
    
    def _load_permissions(self) -> Dict[UserRole, Dict[str, List[str]]]:
        """Load role permissions configuration"""
        return {
            UserRole.ADMIN: {
                "file_management": ["read", "write", "delete", "execute", "upload", "download"],
                "desktop_control": ["view", "control", "configure"],
                "media_control": ["view", "control", "configure"],
                "voice_commands": ["use", "create", "modify", "delete"],
                "remote_desktop": ["view", "control", "configure"],
                "automation": ["view", "create", "execute", "modify", "delete"],
                "package_management": ["view", "install", "remove", "upgrade"],
                "system_monitoring": ["view", "configure", "alerts"],
                "user_management": ["view", "create", "modify", "delete"],
                "security": ["view", "configure", "certificates", "2fa"]
            },
            UserRole.USER: {
                "file_management": ["read", "write", "upload", "download"],
                "desktop_control": ["view", "control"],
                "media_control": ["view", "control"],
                "voice_commands": ["use", "create", "modify"],
                "remote_desktop": ["view", "control"],
                "automation": ["view", "create", "execute", "modify"],
                "package_management": ["view", "install"],
                "system_monitoring": ["view"],
                "user_management": [],
                "security": ["view", "2fa"]
            },
            UserRole.READONLY: {
                "file_management": ["read", "download"],
                "desktop_control": ["view"],
                "media_control": ["view"],
                "voice_commands": ["use"],
                "remote_desktop": ["view"],
                "automation": ["view"],
                "package_management": ["view"],
                "system_monitoring": ["view"],
                "user_management": [],
                "security": ["view"]
            },
            UserRole.GUEST: {
                "file_management": ["read"],
                "desktop_control": ["view"],
                "media_control": ["view"],
                "voice_commands": [],
                "remote_desktop": ["view"],
                "automation": ["view"],
                "package_management": ["view"],
                "system_monitoring": [],
                "user_management": [],
                "security": []
            }
        }
    
    def has_permission(self, user_role: UserRole, resource: str, action: str) -> bool:
        """Check if user role has permission for resource action"""
        try:
            role_permissions = self.permissions.get(user_role, {})
            resource_permissions = role_permissions.get(resource, [])
            
            has_perm = action in resource_permissions
            
            if not has_perm:
                logger.warning(f"Permission denied: {user_role.value} -> {resource}:{action}")
            
            return has_perm
        
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return False
    
    def get_user_permissions(self, user_role: UserRole) -> Dict[str, List[str]]:
        """Get all permissions for a user role"""
        return self.permissions.get(user_role, {})
    
    def can_access_endpoint(self, user_role: UserRole, endpoint: str, method: str) -> bool:
        """Check if user can access specific API endpoint"""
        try:
            # Map endpoints to resources and actions
            endpoint_permissions = {
                # File Management
                "/files/browse": ("file_management", "read"),
                "/files/upload": ("file_management", "upload"),
                "/files/download": ("file_management", "download"),
                "/files/operations/delete": ("file_management", "delete"),
                "/files/operations/rename": ("file_management", "write"),
                "/files/operations/copy": ("file_management", "write"),
                "/files/operations/move": ("file_management", "write"),
                
                # Desktop Control
                "/desktop/info": ("desktop_control", "view"),
                "/desktop/workspaces": ("desktop_control", "view"),
                "/desktop/workspace": ("desktop_control", "control"),
                "/desktop/windows": ("desktop_control", "view"),
                "/desktop/window/focus": ("desktop_control", "control"),
                "/desktop/window/close": ("desktop_control", "control"),
                
                # Media Control
                "/media/players": ("media_control", "view"),
                "/media/play": ("media_control", "control"),
                "/media/pause": ("media_control", "control"),
                "/media/volume": ("media_control", "control"),
                
                # Voice Commands
                "/voice/process": ("voice_commands", "use"),
                "/voice/commands": ("voice_commands", "view"),
                "/voice/commands/custom": ("voice_commands", "create"),
                
                # Remote Desktop
                "/remote/vnc/start": ("remote_desktop", "control"),
                "/remote/vnc/stop": ("remote_desktop", "control"),
                "/remote/screen": ("remote_desktop", "view"),
                
                # Automation
                "/automation/macros": ("automation", "view" if method == "GET" else "create"),
                "/automation/macros/execute": ("automation", "execute"),
                
                # Package Management
                "/packages/search": ("package_management", "view"),
                "/packages/install": ("package_management", "install"),
                "/packages/remove": ("package_management", "remove"),
                "/packages/upgrade": ("package_management", "upgrade"),
                
                # System Monitoring
                "/system/stats": ("system_monitoring", "view"),
                "/system/alerts": ("system_monitoring", "view"),
                
                # User Management
                "/users": ("user_management", "view" if method == "GET" else "create"),
                "/users/roles": ("user_management", "modify"),
                
                # Security
                "/security/certificates": ("security", "certificates"),
                "/security/2fa": ("security", "2fa"),
            }
            
            # Check for exact match first
            if endpoint in endpoint_permissions:
                resource, action = endpoint_permissions[endpoint]
                return self.has_permission(user_role, resource, action)
            
            # Check for pattern matches
            for pattern, (resource, action) in endpoint_permissions.items():
                if endpoint.startswith(pattern.rstrip('*')):
                    return self.has_permission(user_role, resource, action)
            
            # Default deny for unknown endpoints
            logger.warning(f"Unknown endpoint access attempt: {endpoint}")
            return user_role == UserRole.ADMIN  # Only admin can access unknown endpoints
        
        except Exception as e:
            logger.error(f"Endpoint access check failed: {e}")
            return False
    
    def filter_data_by_role(self, data: Dict[str, Any], user_role: UserRole, 
                           data_type: str) -> Dict[str, Any]:
        """Filter sensitive data based on user role"""
        try:
            if user_role == UserRole.ADMIN:
                return data  # Admin sees everything
            
            filtered_data = data.copy()
            
            # Remove sensitive fields based on data type and role
            if data_type == "user_info":
                if user_role not in [UserRole.ADMIN]:
                    filtered_data.pop('password_hash', None)
                    filtered_data.pop('totp_secret', None)
                    filtered_data.pop('api_keys', None)
                    filtered_data.pop('failed_attempts', None)
                    filtered_data.pop('locked_until', None)
            
            elif data_type == "system_info":
                if user_role == UserRole.GUEST:
                    # Guests see limited system info
                    allowed_fields = ['hostname', 'uptime', 'load_average']
                    filtered_data = {k: v for k, v in filtered_data.items() 
                                   if k in allowed_fields}
            
            elif data_type == "package_info":
                if user_role == UserRole.READONLY:
                    # Remove installation/removal capabilities
                    filtered_data.pop('install_command', None)
                    filtered_data.pop('remove_command', None)
            
            return filtered_data
        
        except Exception as e:
            logger.error(f"Data filtering failed: {e}")
            return data
    
    def get_allowed_commands(self, user_role: UserRole) -> List[str]:
        """Get list of allowed commands for user role"""
        command_permissions = {
            UserRole.ADMIN: [
                # System administration
                'systemctl', 'journalctl', 'mount', 'umount', 'fdisk',
                'useradd', 'usermod', 'userdel', 'passwd', 'chown', 'chmod',
                # Package management
                'pacman', 'yay', 'paru', 'apt', 'yum', 'dnf',
                # Network
                'iptables', 'ufw', 'netstat', 'ss', 'tcpdump',
                # File operations
                'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'tar', 'gzip',
                # Process management
                'kill', 'killall', 'pkill', 'nohup',
                # System info
                'ps', 'top', 'htop', 'df', 'du', 'free', 'lscpu', 'lsblk'
            ],
            UserRole.USER: [
                # Basic file operations
                'ls', 'cat', 'less', 'head', 'tail', 'grep', 'find',
                'cp', 'mv', 'mkdir', 'tar', 'gzip',
                # System info (read-only)
                'ps', 'top', 'df', 'du', 'free', 'uptime',
                # Development tools
                'git', 'make', 'gcc', 'python', 'node', 'npm',
                # Package management (limited)
                'pacman -S', 'pacman -Q', 'yay -S'
            ],
            UserRole.READONLY: [
                # Read-only operations
                'ls', 'cat', 'less', 'head', 'tail', 'grep', 'find',
                'ps', 'top', 'df', 'du', 'free', 'uptime',
                'pacman -Q', 'pacman -Ss'
            ],
            UserRole.GUEST: [
                # Very limited operations
                'ls', 'cat', 'less', 'head', 'tail',
                'ps', 'uptime'
            ]
        }
        
        return command_permissions.get(user_role, [])
    
    def validate_command_for_role(self, command: str, user_role: UserRole) -> bool:
        """Validate if command is allowed for user role"""
        try:
            allowed_commands = self.get_allowed_commands(user_role)
            
            # Check if command or command prefix is allowed
            cmd_parts = command.strip().split()
            if not cmd_parts:
                return False
            
            base_command = cmd_parts[0]
            
            # Check exact matches
            if base_command in allowed_commands:
                return True
            
            # Check prefix matches (e.g., "pacman -S" matches "pacman -S package")
            for allowed_cmd in allowed_commands:
                if command.startswith(allowed_cmd):
                    return True
            
            logger.warning(f"Command not allowed for role {user_role.value}: {command}")
            return False
        
        except Exception as e:
            logger.error(f"Command validation failed: {e}")
            return False


# Global RBAC instance
_rbac = None


def get_rbac() -> RoleBasedAccessControl:
    """Get global RBAC instance"""
    global _rbac
    if _rbac is None:
        _rbac = RoleBasedAccessControl()
    return _rbac


@dataclass
class Device:
    """Represents a registered device"""
    device_id: str
    device_name: str
    device_type: str  # mobile, desktop, tablet, etc.
    platform: str  # android, ios, windows, linux, macos
    app_version: str
    device_info: Dict[str, Any]
    username: str
    registered_at: float
    last_seen: Optional[float] = None
    enabled: bool = True
    trusted: bool = False
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class DeviceManager:
    """Manages registered devices and their access"""
    
    def __init__(self):
        self.devices = {}
        self._load_devices()
        logger.info("Device manager initialized")
    
    def _load_devices(self):
        """Load devices from storage"""
        try:
            devices_file = os.path.expanduser('~/.linux_link_devices.json')
            if os.path.exists(devices_file):
                with open(devices_file, 'r') as f:
                    data = json.load(f)
                    for device_data in data.get('devices', []):
                        device = Device(
                            device_id=device_data['device_id'],
                            device_name=device_data['device_name'],
                            device_type=device_data['device_type'],
                            platform=device_data['platform'],
                            app_version=device_data['app_version'],
                            device_info=device_data.get('device_info', {}),
                            username=device_data['username'],
                            registered_at=device_data['registered_at'],
                            last_seen=device_data.get('last_seen'),
                            enabled=device_data.get('enabled', True),
                            trusted=device_data.get('trusted', False),
                            ip_address=device_data.get('ip_address'),
                            user_agent=device_data.get('user_agent')
                        )
                        self.devices[device.device_id] = device
                logger.info(f"Loaded {len(self.devices)} devices")
        except Exception as e:
            logger.debug(f"Could not load devices: {e}")
            self.devices = {}
    
    def _save_devices(self):
        """Save devices to storage"""
        try:
            devices_file = os.path.expanduser('~/.linux_link_devices.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'devices': [device.to_dict() for device in self.devices.values()]
            }
            
            with open(devices_file, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(devices_file, 0o600)  # Secure permissions
                
            logger.debug(f"Saved {len(self.devices)} devices")
        except Exception as e:
            logger.error(f"Failed to save devices: {e}")
    
    def register_device(self, device_name: str, device_type: str, platform: str,
                       app_version: str, username: str, device_info: Dict[str, Any] = None,
                       ip_address: str = None, user_agent: str = None) -> str:
        """Register a new device"""
        try:
            # Generate unique device ID
            device_id = secrets.token_urlsafe(32)
            
            device = Device(
                device_id=device_id,
                device_name=device_name,
                device_type=device_type,
                platform=platform,
                app_version=app_version,
                device_info=device_info or {},
                username=username,
                registered_at=time.time(),
                last_seen=time.time(),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.devices[device_id] = device
            self._save_devices()
            
            logger.info(f"Registered device: {device_name} for user: {username}")
            return device_id
        
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            raise SecurityError("Device registration failed", "DEVICE_REGISTRATION_FAILED")
    
    def get_device(self, device_id: str) -> Optional[Device]:
        """Get device by ID"""
        return self.devices.get(device_id)
    
    def get_user_devices(self, username: str) -> List[Device]:
        """Get all devices for a user"""
        return [device for device in self.devices.values() if device.username == username]
    
    def update_device(self, device_id: str, **kwargs) -> bool:
        """Update device properties"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False
            
            # Update allowed fields
            allowed_fields = ['device_name', 'enabled', 'trusted', 'last_seen', 'ip_address', 'user_agent']
            for field, value in kwargs.items():
                if field in allowed_fields and hasattr(device, field):
                    setattr(device, field, value)
            
            self._save_devices()
            logger.info(f"Updated device: {device_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to update device {device_id}: {e}")
            return False
    
    def update_device_activity(self, device_id: str, ip_address: str = None, 
                              user_agent: str = None) -> bool:
        """Update device last seen and activity info"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False
            
            device.last_seen = time.time()
            if ip_address:
                device.ip_address = ip_address
            if user_agent:
                device.user_agent = user_agent
            
            self._save_devices()
            return True
        
        except Exception as e:
            logger.error(f"Failed to update device activity: {e}")
            return False
    
    def revoke_device(self, device_id: str) -> bool:
        """Revoke/disable a device"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False
            
            device.enabled = False
            device.trusted = False
            self._save_devices()
            
            logger.info(f"Revoked device: {device_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to revoke device {device_id}: {e}")
            return False
    
    def delete_device(self, device_id: str) -> bool:
        """Delete a device"""
        try:
            if device_id in self.devices:
                device = self.devices[device_id]
                del self.devices[device_id]
                self._save_devices()
                
                logger.info(f"Deleted device: {device.device_name} ({device_id})")
                return True
            return False
        
        except Exception as e:
            logger.error(f"Failed to delete device {device_id}: {e}")
            return False
    
    def is_device_authorized(self, device_id: str, username: str) -> bool:
        """Check if device is authorized for user"""
        try:
            device = self.devices.get(device_id)
            if not device:
                return False
            
            return (device.enabled and 
                   device.username == username and
                   device.last_seen and
                   time.time() - device.last_seen < 86400 * 30)  # 30 days
        
        except Exception as e:
            logger.error(f"Device authorization check failed: {e}")
            return False
    
    def get_device_stats(self) -> Dict[str, Any]:
        """Get device statistics"""
        try:
            total_devices = len(self.devices)
            enabled_devices = len([d for d in self.devices.values() if d.enabled])
            trusted_devices = len([d for d in self.devices.values() if d.trusted])
            
            # Group by platform
            platforms = {}
            device_types = {}
            
            for device in self.devices.values():
                platforms[device.platform] = platforms.get(device.platform, 0) + 1
                device_types[device.device_type] = device_types.get(device.device_type, 0) + 1
            
            # Recent activity (last 24 hours)
            recent_cutoff = time.time() - 86400
            recent_devices = len([d for d in self.devices.values() 
                                if d.last_seen and d.last_seen > recent_cutoff])
            
            return {
                'total_devices': total_devices,
                'enabled_devices': enabled_devices,
                'trusted_devices': trusted_devices,
                'recent_devices': recent_devices,
                'platforms': platforms,
                'device_types': device_types
            }
        
        except Exception as e:
            logger.error(f"Failed to get device stats: {e}")
            return {}
    
    def cleanup_old_devices(self, days: int = 90) -> int:
        """Clean up devices not seen for specified days"""
        try:
            cutoff_time = time.time() - (days * 86400)
            old_devices = []
            
            for device_id, device in self.devices.items():
                if not device.last_seen or device.last_seen < cutoff_time:
                    old_devices.append(device_id)
            
            for device_id in old_devices:
                del self.devices[device_id]
            
            if old_devices:
                self._save_devices()
                logger.info(f"Cleaned up {len(old_devices)} old devices")
            
            return len(old_devices)
        
        except Exception as e:
            logger.error(f"Device cleanup failed: {e}")
            return 0


# Global device manager instance
_device_manager = None


def get_device_manager() -> DeviceManager:
    """Get global device manager instance"""
    global _device_manager
    if _device_manager is None:
        _device_manager = DeviceManager()
    return _device_manager


@dataclass
class ActivityLog:
    """Represents an activity log entry"""
    log_id: str
    timestamp: float
    username: str
    device_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    action: str
    resource: str
    details: Dict[str, Any]
    success: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


class ActivityLogger:
    """Manages activity logging and audit trails"""
    
    def __init__(self, log_dir: str = None):
        self.log_dir = log_dir or os.path.expanduser('~/.linux_link_logs')
        self.current_log_file = None
        self.log_rotation_size = 10 * 1024 * 1024  # 10MB
        self.max_log_files = 10
        self._ensure_log_dir()
        self._setup_log_file()
        logger.info("Activity logger initialized")
    
    def _ensure_log_dir(self):
        """Ensure log directory exists"""
        os.makedirs(self.log_dir, mode=0o700, exist_ok=True)
    
    def _setup_log_file(self):
        """Setup current log file"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d')
            self.current_log_file = os.path.join(self.log_dir, f'activity_{timestamp}.log')
            
            # Create file if it doesn't exist
            if not os.path.exists(self.current_log_file):
                with open(self.current_log_file, 'w') as f:
                    f.write(f"# Linux-Link Activity Log - {datetime.now().isoformat()}\\n")
                os.chmod(self.current_log_file, 0o600)
        
        except Exception as e:
            logger.error(f"Failed to setup log file: {e}")
    
    def log_activity(self, username: str, action: str, resource: str, 
                    success: bool = True, details: Dict[str, Any] = None,
                    device_id: str = None, ip_address: str = None, 
                    user_agent: str = None, error_message: str = None):
        """Log an activity"""
        try:
            log_entry = ActivityLog(
                log_id=secrets.token_urlsafe(16),
                timestamp=time.time(),
                username=username,
                device_id=device_id,
                ip_address=ip_address,
                user_agent=user_agent,
                action=action,
                resource=resource,
                details=details or {},
                success=success,
                error_message=error_message
            )
            
            self._write_log_entry(log_entry)
            
            # Also log to system logger for critical actions
            if action in ['login', 'logout', 'failed_login', 'user_created', 'user_deleted', 
                         'certificate_generated', 'device_registered']:
                level = logging.INFO if success else logging.WARNING
                logger.log(level, f"AUDIT: {username} {action} {resource} {'SUCCESS' if success else 'FAILED'}")
        
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")
    
    def _write_log_entry(self, log_entry: ActivityLog):
        """Write log entry to file"""
        try:
            # Check if log rotation is needed
            if (os.path.exists(self.current_log_file) and 
                os.path.getsize(self.current_log_file) > self.log_rotation_size):
                self._rotate_logs()
            
            # Write log entry as JSON
            log_line = json.dumps(log_entry.to_dict()) + '\\n'
            
            with open(self.current_log_file, 'a') as f:
                f.write(log_line)
        
        except Exception as e:
            logger.error(f"Failed to write log entry: {e}")
    
    def _rotate_logs(self):
        """Rotate log files"""
        try:
            # Find existing log files
            log_files = []
            for filename in os.listdir(self.log_dir):
                if filename.startswith('activity_') and filename.endswith('.log'):
                    filepath = os.path.join(self.log_dir, filename)
                    log_files.append((filepath, os.path.getmtime(filepath)))
            
            # Sort by modification time (oldest first)
            log_files.sort(key=lambda x: x[1])
            
            # Remove old files if we have too many
            while len(log_files) >= self.max_log_files:
                old_file, _ = log_files.pop(0)
                try:
                    os.remove(old_file)
                    logger.info(f"Removed old log file: {old_file}")
                except Exception as e:
                    logger.warning(f"Failed to remove old log file {old_file}: {e}")
            
            # Setup new log file
            self._setup_log_file()
        
        except Exception as e:
            logger.error(f"Log rotation failed: {e}")
    
    def search_logs(self, username: str = None, action: str = None, 
                   resource: str = None, start_time: float = None, 
                   end_time: float = None, success: bool = None,
                   limit: int = 100) -> List[ActivityLog]:
        """Search activity logs"""
        try:
            logs = []
            
            # Get all log files
            log_files = []
            for filename in os.listdir(self.log_dir):
                if filename.startswith('activity_') and filename.endswith('.log'):
                    filepath = os.path.join(self.log_dir, filename)
                    log_files.append(filepath)
            
            # Sort by modification time (newest first)
            log_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            
            # Search through log files
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            
                            try:
                                log_data = json.loads(line)
                                
                                # Apply filters
                                if username and log_data.get('username') != username:
                                    continue
                                if action and log_data.get('action') != action:
                                    continue
                                if resource and log_data.get('resource') != resource:
                                    continue
                                if start_time and log_data.get('timestamp', 0) < start_time:
                                    continue
                                if end_time and log_data.get('timestamp', 0) > end_time:
                                    continue
                                if success is not None and log_data.get('success') != success:
                                    continue
                                
                                # Create ActivityLog object
                                log_entry = ActivityLog(
                                    log_id=log_data['log_id'],
                                    timestamp=log_data['timestamp'],
                                    username=log_data['username'],
                                    device_id=log_data.get('device_id'),
                                    ip_address=log_data.get('ip_address'),
                                    user_agent=log_data.get('user_agent'),
                                    action=log_data['action'],
                                    resource=log_data['resource'],
                                    details=log_data.get('details', {}),
                                    success=log_data['success'],
                                    error_message=log_data.get('error_message')
                                )
                                
                                logs.append(log_entry)
                                
                                if len(logs) >= limit:
                                    return logs
                            
                            except json.JSONDecodeError:
                                continue
                
                except Exception as e:
                    logger.warning(f"Failed to read log file {log_file}: {e}")
                    continue
            
            return logs
        
        except Exception as e:
            logger.error(f"Log search failed: {e}")
            return []
    
    def get_user_activity_summary(self, username: str, days: int = 30) -> Dict[str, Any]:
        """Get activity summary for a user"""
        try:
            end_time = time.time()
            start_time = end_time - (days * 86400)
            
            logs = self.search_logs(username=username, start_time=start_time, end_time=end_time)
            
            # Analyze logs
            total_activities = len(logs)
            successful_activities = len([log for log in logs if log.success])
            failed_activities = total_activities - successful_activities
            
            # Group by action
            actions = {}
            resources = {}
            devices = {}
            
            for log in logs:
                actions[log.action] = actions.get(log.action, 0) + 1
                resources[log.resource] = resources.get(log.resource, 0) + 1
                if log.device_id:
                    devices[log.device_id] = devices.get(log.device_id, 0) + 1
            
            # Recent activity (last 24 hours)
            recent_cutoff = time.time() - 86400
            recent_activities = len([log for log in logs if log.timestamp > recent_cutoff])
            
            return {
                'username': username,
                'period_days': days,
                'total_activities': total_activities,
                'successful_activities': successful_activities,
                'failed_activities': failed_activities,
                'recent_activities': recent_activities,
                'top_actions': dict(sorted(actions.items(), key=lambda x: x[1], reverse=True)[:10]),
                'top_resources': dict(sorted(resources.items(), key=lambda x: x[1], reverse=True)[:10]),
                'devices_used': len(devices),
                'last_activity': max([log.timestamp for log in logs]) if logs else None
            }
        
        except Exception as e:
            logger.error(f"Failed to get user activity summary: {e}")
            return {}
    
    def get_system_activity_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get system-wide activity statistics"""
        try:
            end_time = time.time()
            start_time = end_time - (days * 86400)
            
            logs = self.search_logs(start_time=start_time, end_time=end_time, limit=10000)
            
            # Analyze logs
            total_activities = len(logs)
            unique_users = len(set(log.username for log in logs))
            successful_activities = len([log for log in logs if log.success])
            failed_activities = total_activities - successful_activities
            
            # Group by various dimensions
            users = {}
            actions = {}
            resources = {}
            hourly_activity = {}
            
            for log in logs:
                users[log.username] = users.get(log.username, 0) + 1
                actions[log.action] = actions.get(log.action, 0) + 1
                resources[log.resource] = resources.get(log.resource, 0) + 1
                
                # Hourly activity
                hour = datetime.fromtimestamp(log.timestamp).hour
                hourly_activity[hour] = hourly_activity.get(hour, 0) + 1
            
            return {
                'period_days': days,
                'total_activities': total_activities,
                'unique_users': unique_users,
                'successful_activities': successful_activities,
                'failed_activities': failed_activities,
                'success_rate': (successful_activities / total_activities * 100) if total_activities > 0 else 0,
                'top_users': dict(sorted(users.items(), key=lambda x: x[1], reverse=True)[:10]),
                'top_actions': dict(sorted(actions.items(), key=lambda x: x[1], reverse=True)[:10]),
                'top_resources': dict(sorted(resources.items(), key=lambda x: x[1], reverse=True)[:10]),
                'hourly_activity': hourly_activity
            }
        
        except Exception as e:
            logger.error(f"Failed to get system activity stats: {e}")
            return {}
    
    def cleanup_old_logs(self, days: int = 90) -> int:
        """Clean up logs older than specified days"""
        try:
            cutoff_time = time.time() - (days * 86400)
            removed_files = 0
            
            for filename in os.listdir(self.log_dir):
                if filename.startswith('activity_') and filename.endswith('.log'):
                    filepath = os.path.join(self.log_dir, filename)
                    
                    if os.path.getmtime(filepath) < cutoff_time:
                        try:
                            os.remove(filepath)
                            removed_files += 1
                            logger.info(f"Removed old log file: {filename}")
                        except Exception as e:
                            logger.warning(f"Failed to remove old log file {filename}: {e}")
            
            return removed_files
        
        except Exception as e:
            logger.error(f"Log cleanup failed: {e}")
            return 0


# Global activity logger instance
_activity_logger = None


def get_activity_logger() -> ActivityLogger:
    """Get global activity logger instance"""
    global _activity_logger
    if _activity_logger is None:
        _activity_logger = ActivityLogger()
    return _activity_logger