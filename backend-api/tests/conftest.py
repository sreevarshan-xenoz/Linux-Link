"""
Test configuration and fixtures for Linux-Link backend tests
"""

import pytest
import tempfile
import os
import shutil
from unittest.mock import Mock, patch
from fastapi.testclient import TestClient

# Import the main application
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
from security import get_user_manager, get_certificate_manager, get_device_manager
from monitoring import get_system_monitor
from error_handler import get_error_handler


@pytest.fixture
def client():
    """FastAPI test client"""
    return TestClient(app)


@pytest.fixture
def temp_dir():
    """Temporary directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_user():
    """Mock user for authentication tests"""
    return {
        "sub": "test_user",
        "role": "user",
        "exp": 9999999999  # Far future expiration
    }


@pytest.fixture
def mock_admin_user():
    """Mock admin user for authorization tests"""
    return {
        "sub": "admin_user", 
        "role": "admin",
        "exp": 9999999999
    }


@pytest.fixture
def mock_jwt_token():
    """Mock JWT token"""
    return "mock_jwt_token_for_testing"


@pytest.fixture(autouse=True)
def mock_system_dependencies():
    """Mock system dependencies that require root or specific system setup"""
    with patch('psutil.cpu_percent', return_value=50.0), \\
         patch('psutil.virtual_memory') as mock_vm, \\
         patch('psutil.disk_usage') as mock_disk, \\
         patch('psutil.net_io_counters') as mock_net, \\
         patch('subprocess.run') as mock_subprocess:
        
        # Mock memory info
        mock_vm.return_value = Mock(
            total=8589934592,  # 8GB
            available=4294967296,  # 4GB
            used=4294967296,  # 4GB
            percent=50.0,
            free=4294967296  # 4GB
        )
        
        # Mock disk usage
        mock_disk.return_value = Mock(
            total=1000000000000,  # 1TB
            used=500000000000,    # 500GB
            free=500000000000     # 500GB
        )
        
        # Mock network stats
        mock_net.return_value = Mock(
            bytes_sent=1000000,
            bytes_recv=2000000,
            packets_sent=1000,
            packets_recv=2000
        )
        
        # Mock subprocess calls
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="mock output",
            stderr=""
        )
        
        yield


@pytest.fixture
def sample_file_content():
    """Sample file content for file management tests"""
    return "This is test file content for Linux-Link testing."


@pytest.fixture
def sample_macro():
    """Sample macro for automation tests"""
    return {
        "macro_id": "test_macro",
        "name": "Test Macro",
        "description": "A test macro for unit testing",
        "actions": [
            {
                "id": "action_1",
                "type": "command",
                "command": "echo 'Hello World'",
                "timeout": 30
            },
            {
                "id": "action_2", 
                "type": "delay",
                "parameters": {"seconds": 1}
            }
        ]
    }


@pytest.fixture
def sample_alert_threshold():
    """Sample alert threshold for monitoring tests"""
    return {
        "metric_type": "cpu",
        "metric_name": "cpu_usage_percent",
        "operator": ">",
        "warning_value": 80.0,
        "critical_value": 95.0
    }


@pytest.fixture
def sample_device():
    """Sample device for device management tests"""
    return {
        "device_name": "Test Device",
        "device_type": "mobile",
        "platform": "android",
        "app_version": "1.0.0",
        "device_info": {
            "model": "Test Phone",
            "os_version": "11.0"
        }
    }


@pytest.fixture
def cleanup_test_data():
    """Cleanup test data after tests"""
    yield
    
    # Clean up any test files or data
    try:
        # Reset global instances
        import importlib
        import security
        import monitoring
        import error_handler
        
        # Reset module-level variables
        security._user_manager = None
        security._certificate_manager = None
        security._device_manager = None
        monitoring._system_monitor = None
        error_handler._error_handler = None
        
    except Exception:
        pass  # Ignore cleanup errors


# Mock authentication for tests
def mock_verify_token():
    """Mock token verification for tests"""
    return {"sub": "test_user", "role": "user"}


def mock_verify_admin_token():
    """Mock admin token verification for tests"""
    return {"sub": "admin_user", "role": "admin"}


# Test utilities
def create_test_user(username="test_user", role="user"):
    """Create a test user"""
    from security import UserRole, AuthMethod
    
    user_manager = get_user_manager()
    user_manager.create_user(
        username=username,
        role=UserRole(role),
        auth_methods=[AuthMethod.PASSWORD]
    )
    user_manager.set_password(username, "test_password")
    return username


def create_test_file(temp_dir, filename="test.txt", content="test content"):
    """Create a test file"""
    file_path = os.path.join(temp_dir, filename)
    with open(file_path, 'w') as f:
        f.write(content)
    return file_path


def assert_api_success(response, expected_keys=None):
    """Assert API response is successful"""
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    
    if expected_keys:
        for key in expected_keys:
            assert key in data


def assert_api_error(response, expected_status=400):
    """Assert API response is an error"""
    assert response.status_code == expected_status
    data = response.json()
    assert data.get("success") is False
    assert "error" in data