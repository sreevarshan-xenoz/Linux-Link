"""
Linux-Link Performance Optimization and Security Hardening

Provides performance monitoring, optimization, and security hardening
features for the Linux-Link backend system.
"""

import os
import time
import psutil
import logging
import threading
import functools
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics data structure"""
    timestamp: float
    cpu_usage: float
    memory_usage: float
    disk_io_read: int
    disk_io_write: int
    network_io_sent: int
    network_io_recv: int
    active_connections: int
    response_times: Dict[str, float]
    error_rates: Dict[str, float]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


class PerformanceOptimizer:
    """Performance optimization and monitoring system"""
    
    def __init__(self):
        self.metrics_history = []
        self.max_history_size = 1000
        self.optimization_rules = {}
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.cache = {}
        self.cache_ttl = {}
        self.rate_limiters = {}
        self._setup_optimization_rules()
        logger.info("Performance optimizer initialized")
    
    def _setup_optimization_rules(self):
        """Setup performance optimization rules"""
        self.optimization_rules = {
            'high_cpu_usage': {
                'threshold': 80.0,
                'action': self._optimize_cpu_usage,
                'cooldown': 300  # 5 minutes
            },
            'high_memory_usage': {
                'threshold': 85.0,
                'action': self._optimize_memory_usage,
                'cooldown': 300
            },
            'slow_response_time': {
                'threshold': 2.0,  # seconds
                'action': self._optimize_response_time,
                'cooldown': 180  # 3 minutes
            },
            'high_error_rate': {
                'threshold': 5.0,  # percent
                'action': self._optimize_error_handling,
                'cooldown': 600  # 10 minutes
            }
        }
    
    def collect_performance_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics"""
        try:
            # System metrics
            cpu_usage = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            network_io = psutil.net_io_counters()
            
            # Application metrics
            active_connections = len(psutil.net_connections())
            
            metrics = PerformanceMetrics(
                timestamp=time.time(),
                cpu_usage=cpu_usage,
                memory_usage=memory.percent,
                disk_io_read=disk_io.read_bytes if disk_io else 0,
                disk_io_write=disk_io.write_bytes if disk_io else 0,
                network_io_sent=network_io.bytes_sent if network_io else 0,
                network_io_recv=network_io.bytes_recv if network_io else 0,
                active_connections=active_connections,
                response_times={},  # Would be populated by middleware
                error_rates={}      # Would be populated by error handler
            )
            
            # Store metrics
            self.metrics_history.append(metrics)
            if len(self.metrics_history) > self.max_history_size:
                self.metrics_history = self.metrics_history[-self.max_history_size:]
            
            # Check for optimization opportunities
            self._check_optimization_rules(metrics)
            
            return metrics
        
        except Exception as e:
            logger.error(f"Failed to collect performance metrics: {e}")
            return None
    
    def _check_optimization_rules(self, metrics: PerformanceMetrics):
        """Check if any optimization rules should be triggered"""
        try:
            current_time = time.time()
            
            for rule_name, rule in self.optimization_rules.items():
                last_triggered = getattr(self, f'_last_{rule_name}_trigger', 0)
                
                # Check cooldown
                if current_time - last_triggered < rule['cooldown']:
                    continue
                
                # Check threshold
                should_trigger = False
                
                if rule_name == 'high_cpu_usage' and metrics.cpu_usage > rule['threshold']:
                    should_trigger = True
                elif rule_name == 'high_memory_usage' and metrics.memory_usage > rule['threshold']:
                    should_trigger = True
                elif rule_name == 'slow_response_time':
                    avg_response_time = sum(metrics.response_times.values()) / len(metrics.response_times) if metrics.response_times else 0
                    if avg_response_time > rule['threshold']:
                        should_trigger = True
                elif rule_name == 'high_error_rate':
                    avg_error_rate = sum(metrics.error_rates.values()) / len(metrics.error_rates) if metrics.error_rates else 0
                    if avg_error_rate > rule['threshold']:
                        should_trigger = True
                
                if should_trigger:
                    logger.info(f"Triggering optimization rule: {rule_name}")
                    setattr(self, f'_last_{rule_name}_trigger', current_time)
                    
                    # Execute optimization action in background
                    self.thread_pool.submit(rule['action'], metrics)
        
        except Exception as e:
            logger.error(f"Failed to check optimization rules: {e}")
    
    def _optimize_cpu_usage(self, metrics: PerformanceMetrics):
        """Optimize CPU usage"""
        try:
            logger.info("Optimizing CPU usage")
            
            # Reduce thread pool size temporarily
            if self.thread_pool._max_workers > 5:
                self.thread_pool._max_workers = max(5, self.thread_pool._max_workers - 2)
            
            # Clear old cache entries
            self._cleanup_cache()
            
            # Reduce background task frequency
            # This would integrate with other components
            
        except Exception as e:
            logger.error(f"CPU optimization failed: {e}")
    
    def _optimize_memory_usage(self, metrics: PerformanceMetrics):
        """Optimize memory usage"""
        try:
            logger.info("Optimizing memory usage")
            
            # Clear caches
            self.cache.clear()
            self.cache_ttl.clear()
            
            # Trim metrics history
            if len(self.metrics_history) > 500:
                self.metrics_history = self.metrics_history[-500:]
            
            # Force garbage collection
            import gc
            gc.collect()
            
        except Exception as e:
            logger.error(f"Memory optimization failed: {e}")
    
    def _optimize_response_time(self, metrics: PerformanceMetrics):
        """Optimize response times"""
        try:
            logger.info("Optimizing response times")
            
            # Increase cache TTL for frequently accessed data
            for key in list(self.cache_ttl.keys()):
                if self.cache_ttl[key] < time.time() + 300:  # Extend by 5 minutes
                    self.cache_ttl[key] = time.time() + 600
            
            # Increase thread pool size if needed
            if self.thread_pool._max_workers < 15:
                self.thread_pool._max_workers = min(15, self.thread_pool._max_workers + 2)
            
        except Exception as e:
            logger.error(f"Response time optimization failed: {e}")
    
    def _optimize_error_handling(self, metrics: PerformanceMetrics):
        """Optimize error handling"""
        try:
            logger.info("Optimizing error handling")
            
            # Implement circuit breaker pattern for failing services
            # This would integrate with external service calls
            
            # Increase retry delays
            # This would integrate with retry mechanisms
            
        except Exception as e:
            logger.error(f"Error handling optimization failed: {e}")
    
    def cache_result(self, key: str, value: Any, ttl: int = 300):
        """Cache a result with TTL"""
        self.cache[key] = value
        self.cache_ttl[key] = time.time() + ttl
    
    def get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result if still valid"""
        if key in self.cache and key in self.cache_ttl:
            if time.time() < self.cache_ttl[key]:
                return self.cache[key]
            else:
                # Expired, remove from cache
                del self.cache[key]
                del self.cache_ttl[key]
        return None
    
    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        current_time = time.time()
        expired_keys = [
            key for key, expiry in self.cache_ttl.items()
            if current_time >= expiry
        ]
        
        for key in expired_keys:
            del self.cache[key]
            del self.cache_ttl[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_performance_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance summary for specified time period"""
        try:
            cutoff_time = time.time() - (hours * 3600)
            recent_metrics = [m for m in self.metrics_history if m.timestamp > cutoff_time]
            
            if not recent_metrics:
                return {"message": "No metrics available for the specified period"}
            
            # Calculate averages
            avg_cpu = sum(m.cpu_usage for m in recent_metrics) / len(recent_metrics)
            avg_memory = sum(m.memory_usage for m in recent_metrics) / len(recent_metrics)
            avg_connections = sum(m.active_connections for m in recent_metrics) / len(recent_metrics)
            
            # Find peaks
            max_cpu = max(m.cpu_usage for m in recent_metrics)
            max_memory = max(m.memory_usage for m in recent_metrics)
            max_connections = max(m.active_connections for m in recent_metrics)
            
            return {
                'period_hours': hours,
                'data_points': len(recent_metrics),
                'averages': {
                    'cpu_usage': round(avg_cpu, 2),
                    'memory_usage': round(avg_memory, 2),
                    'active_connections': round(avg_connections, 2)
                },
                'peaks': {
                    'max_cpu_usage': round(max_cpu, 2),
                    'max_memory_usage': round(max_memory, 2),
                    'max_connections': max_connections
                },
                'cache_stats': {
                    'cached_items': len(self.cache),
                    'cache_hit_rate': self._calculate_cache_hit_rate()
                }
            }
        
        except Exception as e:
            logger.error(f"Failed to get performance summary: {e}")
            return {}
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate (placeholder)"""
        # This would track actual cache hits/misses
        return 85.0  # Placeholder value


class SecurityHardening:
    """Security hardening and protection mechanisms"""
    
    def __init__(self):
        self.failed_attempts = {}
        self.blocked_ips = {}
        self.security_headers = {}
        self.rate_limits = {}
        self._setup_security_headers()
        self._setup_rate_limits()
        logger.info("Security hardening initialized")
    
    def _setup_security_headers(self):
        """Setup security headers"""
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    def _setup_rate_limits(self):
        """Setup rate limiting rules"""
        self.rate_limits = {
            'login': {'requests': 5, 'window': 300},      # 5 attempts per 5 minutes
            'api_general': {'requests': 100, 'window': 60}, # 100 requests per minute
            'file_upload': {'requests': 10, 'window': 60},  # 10 uploads per minute
            'package_install': {'requests': 5, 'window': 300} # 5 installs per 5 minutes
        }
    
    def check_rate_limit(self, client_ip: str, endpoint_type: str) -> bool:
        """Check if request is within rate limits"""
        try:
            if endpoint_type not in self.rate_limits:
                return True
            
            limit_config = self.rate_limits[endpoint_type]
            key = f"{client_ip}:{endpoint_type}"
            current_time = time.time()
            
            # Initialize tracking for this key
            if key not in self.failed_attempts:
                self.failed_attempts[key] = []
            
            # Clean old attempts outside the window
            window_start = current_time - limit_config['window']
            self.failed_attempts[key] = [
                attempt_time for attempt_time in self.failed_attempts[key]
                if attempt_time > window_start
            ]
            
            # Check if limit exceeded
            if len(self.failed_attempts[key]) >= limit_config['requests']:
                logger.warning(f"Rate limit exceeded for {client_ip} on {endpoint_type}")
                return False
            
            # Record this attempt
            self.failed_attempts[key].append(current_time)
            return True
        
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow on error to avoid blocking legitimate requests
    
    def record_failed_login(self, client_ip: str, username: str):
        """Record failed login attempt"""
        try:
            key = f"login_fail:{client_ip}"
            current_time = time.time()
            
            if key not in self.failed_attempts:
                self.failed_attempts[key] = []
            
            self.failed_attempts[key].append(current_time)
            
            # Clean old attempts (last hour)
            hour_ago = current_time - 3600
            self.failed_attempts[key] = [
                attempt_time for attempt_time in self.failed_attempts[key]
                if attempt_time > hour_ago
            ]
            
            # Block IP if too many failed attempts
            if len(self.failed_attempts[key]) >= 10:  # 10 failed attempts in an hour
                self.block_ip(client_ip, duration=3600)  # Block for 1 hour
                logger.warning(f"Blocked IP {client_ip} due to excessive failed login attempts")
        
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")
    
    def block_ip(self, client_ip: str, duration: int = 3600):
        """Block an IP address for specified duration"""
        self.blocked_ips[client_ip] = time.time() + duration
        logger.info(f"Blocked IP {client_ip} for {duration} seconds")
    
    def is_ip_blocked(self, client_ip: str) -> bool:
        """Check if IP address is blocked"""
        if client_ip in self.blocked_ips:
            if time.time() < self.blocked_ips[client_ip]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[client_ip]
        return False
    
    def validate_input(self, input_data: str, input_type: str = "general") -> bool:
        """Validate input for security threats"""
        try:
            if not input_data:
                return True
            
            # Check for common injection patterns
            dangerous_patterns = [
                r'<script[^>]*>.*?</script>',  # XSS
                r'javascript:',                # JavaScript injection
                r'on\w+\s*=',                 # Event handlers
                r'union\s+select',            # SQL injection
                r'drop\s+table',              # SQL injection
                r'\.\./\.\.',                 # Path traversal
                r'rm\s+-rf',                  # Dangerous commands
                r'sudo\s+',                   # Privilege escalation
            ]
            
            import re
            for pattern in dangerous_patterns:
                if re.search(pattern, input_data, re.IGNORECASE):
                    logger.warning(f"Dangerous pattern detected in input: {pattern}")
                    return False
            
            # Input type specific validation
            if input_type == "filename":
                # Check for path traversal and dangerous characters
                if any(char in input_data for char in ['..', '/', '\\\\', '|', ';', '&']):
                    return False
            
            elif input_type == "command":
                # Very strict validation for commands
                allowed_commands = ['ls', 'cat', 'grep', 'find', 'ps', 'top', 'df', 'du']
                command_parts = input_data.split()
                if command_parts and command_parts[0] not in allowed_commands:
                    return False
            
            return True
        
        except Exception as e:
            logger.error(f"Input validation failed: {e}")
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data with salt"""
        salt = secrets.token_bytes(32)
        hashed = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
        return salt.hex() + hashed.hex()
    
    def verify_hashed_data(self, data: str, hashed: str) -> bool:
        """Verify hashed data"""
        try:
            salt_hex = hashed[:64]  # First 32 bytes (64 hex chars)
            hash_hex = hashed[64:]  # Remaining bytes
            
            salt = bytes.fromhex(salt_hex)
            expected_hash = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
            
            return expected_hash.hex() == hash_hex
        except Exception:
            return False
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return self.security_headers.copy()
    
    def audit_security_event(self, event_type: str, details: Dict[str, Any]):
        """Audit security events"""
        try:
            audit_entry = {
                'timestamp': time.time(),
                'event_type': event_type,
                'details': details,
                'severity': self._get_event_severity(event_type)
            }
            
            # Log security event
            if audit_entry['severity'] == 'high':
                logger.error(f"SECURITY EVENT: {event_type} - {details}")
            elif audit_entry['severity'] == 'medium':
                logger.warning(f"SECURITY EVENT: {event_type} - {details}")
            else:
                logger.info(f"SECURITY EVENT: {event_type} - {details}")
            
            # Store in security log (would integrate with logging system)
            
        except Exception as e:
            logger.error(f"Security audit failed: {e}")
    
    def _get_event_severity(self, event_type: str) -> str:
        """Get severity level for security event"""
        high_severity = ['failed_login_excessive', 'ip_blocked', 'injection_attempt']
        medium_severity = ['failed_login', 'rate_limit_exceeded', 'invalid_token']
        
        if event_type in high_severity:
            return 'high'
        elif event_type in medium_severity:
            return 'medium'
        else:
            return 'low'


# Performance monitoring decorator
def monitor_performance(func_name: str = None):
    """Decorator to monitor function performance"""
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                execution_time = time.time() - start_time
                optimizer = get_performance_optimizer()
                
                # Update response time metrics
                if hasattr(optimizer, 'current_metrics') and optimizer.current_metrics:
                    name = func_name or func.__name__
                    optimizer.current_metrics.response_times[name] = execution_time
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                execution_time = time.time() - start_time
                optimizer = get_performance_optimizer()
                
                # Update response time metrics
                if hasattr(optimizer, 'current_metrics') and optimizer.current_metrics:
                    name = func_name or func.__name__
                    optimizer.current_metrics.response_times[name] = execution_time
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator


# Global instances
_performance_optimizer = None
_security_hardening = None


def get_performance_optimizer() -> PerformanceOptimizer:
    """Get global performance optimizer instance"""
    global _performance_optimizer
    if _performance_optimizer is None:
        _performance_optimizer = PerformanceOptimizer()
    return _performance_optimizer


def get_security_hardening() -> SecurityHardening:
    """Get global security hardening instance"""
    global _security_hardening
    if _security_hardening is None:
        _security_hardening = SecurityHardening()
    return _security_hardening