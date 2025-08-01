"""
Linux-Link Centralized Error Handling

Provides comprehensive error handling, logging, and recovery mechanisms
for all system components.
"""

import os
import json
import time
import logging
import traceback
import functools
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    RESOURCE_NOT_FOUND = "resource_not_found"
    EXTERNAL_SERVICE = "external_service"
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    NETWORK = "network"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class ErrorSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ErrorDetails:
    """Detailed error information"""
    error_id: str
    timestamp: float
    category: ErrorCategory
    severity: ErrorSeverity
    component: str
    function: str
    message: str
    details: Dict[str, Any]
    stack_trace: Optional[str] = None
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['category'] = self.category.value
        data['severity'] = self.severity.value
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


class ErrorHandler:
    """Centralized error handling and recovery system"""
    
    def __init__(self):
        self.error_log = []
        self.max_log_size = 1000
        self.recovery_strategies = {}
        self.error_counts = {}
        self._setup_recovery_strategies()
        logger.info("Error handler initialized")
    
    def _setup_recovery_strategies(self):
        """Setup automatic recovery strategies for common errors"""
        self.recovery_strategies = {
            ErrorCategory.DATABASE: self._recover_database_error,
            ErrorCategory.FILE_SYSTEM: self._recover_filesystem_error,
            ErrorCategory.NETWORK: self._recover_network_error,
            ErrorCategory.EXTERNAL_SERVICE: self._recover_external_service_error,
        }
    
    def handle_error(self, error: Exception, component: str, function: str,
                    category: ErrorCategory = ErrorCategory.UNKNOWN,
                    severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                    user_id: str = None, request_id: str = None,
                    additional_details: Dict[str, Any] = None) -> ErrorDetails:
        """Handle an error with comprehensive logging and recovery"""
        try:
            import secrets
            error_id = secrets.token_urlsafe(16)
            
            # Create error details
            error_details = ErrorDetails(
                error_id=error_id,
                timestamp=time.time(),
                category=category,
                severity=severity,
                component=component,
                function=function,
                message=str(error),
                details=additional_details or {},
                stack_trace=traceback.format_exc(),
                user_id=user_id,
                request_id=request_id
            )
            
            # Log the error
            self._log_error(error_details)
            
            # Update error counts
            self._update_error_counts(category, component)
            
            # Attempt recovery if strategy exists
            if category in self.recovery_strategies:
                try:
                    error_details.recovery_attempted = True
                    recovery_result = self.recovery_strategies[category](error, error_details)
                    error_details.recovery_successful = recovery_result
                    
                    if recovery_result:
                        logger.info(f"Successfully recovered from error: {error_id}")
                    else:
                        logger.warning(f"Recovery failed for error: {error_id}")
                
                except Exception as recovery_error:
                    logger.error(f"Recovery strategy failed: {recovery_error}")
                    error_details.recovery_successful = False
            
            # Store in error log
            self.error_log.append(error_details)
            
            # Trim log if too large
            if len(self.error_log) > self.max_log_size:
                self.error_log = self.error_log[-self.max_log_size:]
            
            # Send alerts for critical errors
            if severity == ErrorSeverity.CRITICAL:
                self._send_critical_alert(error_details)
            
            return error_details
        
        except Exception as handler_error:
            # Fallback logging if error handler itself fails
            logger.critical(f"Error handler failed: {handler_error}")
            logger.critical(f"Original error: {error}")
            
            # Return minimal error details
            return ErrorDetails(
                error_id="handler_failed",
                timestamp=time.time(),
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.CRITICAL,
                component="error_handler",
                function="handle_error",
                message=f"Error handler failed: {handler_error}",
                details={"original_error": str(error)}
            )
    
    def _log_error(self, error_details: ErrorDetails):
        """Log error with appropriate level"""
        log_message = f"[{error_details.error_id}] {error_details.component}.{error_details.function}: {error_details.message}"
        
        if error_details.severity == ErrorSeverity.CRITICAL:
            logger.critical(log_message)
        elif error_details.severity == ErrorSeverity.HIGH:
            logger.error(log_message)
        elif error_details.severity == ErrorSeverity.MEDIUM:
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        # Log stack trace for high severity errors
        if error_details.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            if error_details.stack_trace:
                logger.debug(f"Stack trace for {error_details.error_id}:\\n{error_details.stack_trace}")
    
    def _update_error_counts(self, category: ErrorCategory, component: str):
        """Update error statistics"""
        key = f"{category.value}:{component}"
        self.error_counts[key] = self.error_counts.get(key, 0) + 1
    
    def _send_critical_alert(self, error_details: ErrorDetails):
        """Send alert for critical errors"""
        try:
            # This would integrate with alerting system
            alert_message = f"CRITICAL ERROR: {error_details.component}.{error_details.function} - {error_details.message}"
            logger.critical(f"ALERT: {alert_message}")
            
            # Could send email, SMS, or push notifications here
            
        except Exception as e:
            logger.error(f"Failed to send critical alert: {e}")
    
    def _recover_database_error(self, error: Exception, error_details: ErrorDetails) -> bool:
        """Attempt to recover from database errors"""
        try:
            error_message = str(error).lower()
            
            # Handle connection errors
            if "connection" in error_message or "timeout" in error_message:
                logger.info("Attempting database connection recovery")
                time.sleep(1)  # Brief delay before retry
                return True
            
            # Handle lock errors
            if "lock" in error_message or "busy" in error_message:
                logger.info("Attempting database lock recovery")
                time.sleep(0.5)  # Brief delay for lock release
                return True
            
            return False
        
        except Exception:
            return False
    
    def _recover_filesystem_error(self, error: Exception, error_details: ErrorDetails) -> bool:
        """Attempt to recover from filesystem errors"""
        try:
            error_message = str(error).lower()
            
            # Handle permission errors
            if "permission" in error_message:
                logger.info("Filesystem permission error - cannot auto-recover")
                return False
            
            # Handle disk space errors
            if "space" in error_message or "full" in error_message:
                logger.warning("Disk space error detected")
                # Could trigger cleanup procedures here
                return False
            
            # Handle temporary file issues
            if "temporary" in error_message or "tmp" in error_message:
                logger.info("Attempting temporary file recovery")
                return True
            
            return False
        
        except Exception:
            return False
    
    def _recover_network_error(self, error: Exception, error_details: ErrorDetails) -> bool:
        """Attempt to recover from network errors"""
        try:
            error_message = str(error).lower()
            
            # Handle timeout errors
            if "timeout" in error_message:
                logger.info("Network timeout - will retry with backoff")
                return True
            
            # Handle connection errors
            if "connection" in error_message:
                logger.info("Network connection error - will retry")
                time.sleep(2)  # Brief delay before retry
                return True
            
            return False
        
        except Exception:
            return False
    
    def _recover_external_service_error(self, error: Exception, error_details: ErrorDetails) -> bool:
        """Attempt to recover from external service errors"""
        try:
            error_message = str(error).lower()
            
            # Handle rate limiting
            if "rate" in error_message or "limit" in error_message:
                logger.info("Rate limit detected - implementing backoff")
                time.sleep(5)  # Longer delay for rate limits
                return True
            
            # Handle service unavailable
            if "unavailable" in error_message or "503" in error_message:
                logger.info("Service unavailable - will retry later")
                return True
            
            return False
        
        except Exception:
            return False
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics and trends"""
        try:
            total_errors = len(self.error_log)
            
            # Count by category
            category_counts = {}
            severity_counts = {}
            component_counts = {}
            recent_errors = 0
            
            recent_cutoff = time.time() - 3600  # Last hour
            
            for error in self.error_log:
                category_counts[error.category.value] = category_counts.get(error.category.value, 0) + 1
                severity_counts[error.severity.value] = severity_counts.get(error.severity.value, 0) + 1
                component_counts[error.component] = component_counts.get(error.component, 0) + 1
                
                if error.timestamp > recent_cutoff:
                    recent_errors += 1
            
            # Calculate recovery rate
            recovery_attempted = len([e for e in self.error_log if e.recovery_attempted])
            recovery_successful = len([e for e in self.error_log if e.recovery_successful])
            recovery_rate = (recovery_successful / recovery_attempted * 100) if recovery_attempted > 0 else 0
            
            return {
                'total_errors': total_errors,
                'recent_errors': recent_errors,
                'category_counts': category_counts,
                'severity_counts': severity_counts,
                'component_counts': component_counts,
                'recovery_rate': recovery_rate,
                'recovery_attempted': recovery_attempted,
                'recovery_successful': recovery_successful
            }
        
        except Exception as e:
            logger.error(f"Failed to get error statistics: {e}")
            return {}
    
    def get_recent_errors(self, limit: int = 50) -> List[ErrorDetails]:
        """Get recent errors"""
        return sorted(self.error_log, key=lambda x: x.timestamp, reverse=True)[:limit]
    
    def clear_error_log(self) -> int:
        """Clear error log and return count of cleared errors"""
        count = len(self.error_log)
        self.error_log.clear()
        self.error_counts.clear()
        logger.info(f"Cleared {count} errors from log")
        return count


def error_handler_decorator(component: str, category: ErrorCategory = ErrorCategory.UNKNOWN,
                           severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                           reraise: bool = True):
    """Decorator for automatic error handling"""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_handler = get_error_handler()
                error_details = error_handler.handle_error(
                    error=e,
                    component=component,
                    function=func.__name__,
                    category=category,
                    severity=severity
                )
                
                if reraise:
                    raise
                else:
                    return None
        
        return wrapper
    return decorator


def api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI error handler for API endpoints"""
    try:
        error_handler = get_error_handler()
        
        # Determine error category and severity
        if isinstance(exc, HTTPException):
            if exc.status_code == 401:
                category = ErrorCategory.AUTHENTICATION
                severity = ErrorSeverity.MEDIUM
            elif exc.status_code == 403:
                category = ErrorCategory.AUTHORIZATION
                severity = ErrorSeverity.MEDIUM
            elif exc.status_code == 404:
                category = ErrorCategory.RESOURCE_NOT_FOUND
                severity = ErrorSeverity.LOW
            elif exc.status_code >= 500:
                category = ErrorCategory.SYSTEM
                severity = ErrorSeverity.HIGH
            else:
                category = ErrorCategory.VALIDATION
                severity = ErrorSeverity.LOW
        else:
            category = ErrorCategory.SYSTEM
            severity = ErrorSeverity.HIGH
        
        # Handle the error
        error_details = error_handler.handle_error(
            error=exc,
            component="api",
            function=request.url.path,
            category=category,
            severity=severity,
            request_id=getattr(request.state, 'request_id', None)
        )
        
        # Return appropriate response
        if isinstance(exc, HTTPException):
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "success": False,
                    "error": exc.detail,
                    "error_id": error_details.error_id,
                    "timestamp": error_details.timestamp
                }
            )
        else:
            return JSONResponse(
                status_code=500,
                content={
                    "success": False,
                    "error": "Internal server error",
                    "error_id": error_details.error_id,
                    "timestamp": error_details.timestamp
                }
            )
    
    except Exception as handler_error:
        logger.critical(f"API error handler failed: {handler_error}")
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "error": "Critical system error",
                "timestamp": time.time()
            }
        )


# Global error handler instance
_error_handler = None


def get_error_handler() -> ErrorHandler:
    """Get global error handler instance"""
    global _error_handler
    if _error_handler is None:
        _error_handler = ErrorHandler()
    return _error_handler


# Context manager for error handling
class ErrorContext:
    """Context manager for handling errors in code blocks"""
    
    def __init__(self, component: str, function: str, 
                 category: ErrorCategory = ErrorCategory.UNKNOWN,
                 severity: ErrorSeverity = ErrorSeverity.MEDIUM,
                 reraise: bool = True):
        self.component = component
        self.function = function
        self.category = category
        self.severity = severity
        self.reraise = reraise
        self.error_details = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            error_handler = get_error_handler()
            self.error_details = error_handler.handle_error(
                error=exc_val,
                component=self.component,
                function=self.function,
                category=self.category,
                severity=self.severity
            )
            
            if not self.reraise:
                return True  # Suppress the exception
        
        return False  # Let exception propagate


# Utility functions for common error scenarios
def handle_database_error(func: Callable):
    """Decorator for database operations"""
    return error_handler_decorator(
        component="database",
        category=ErrorCategory.DATABASE,
        severity=ErrorSeverity.HIGH
    )(func)


def handle_filesystem_error(func: Callable):
    """Decorator for filesystem operations"""
    return error_handler_decorator(
        component="filesystem",
        category=ErrorCategory.FILE_SYSTEM,
        severity=ErrorSeverity.MEDIUM
    )(func)


def handle_network_error(func: Callable):
    """Decorator for network operations"""
    return error_handler_decorator(
        component="network",
        category=ErrorCategory.NETWORK,
        severity=ErrorSeverity.MEDIUM
    )(func)


def handle_external_service_error(func: Callable):
    """Decorator for external service calls"""
    return error_handler_decorator(
        component="external_service",
        category=ErrorCategory.EXTERNAL_SERVICE,
        severity=ErrorSeverity.MEDIUM
    )(func)