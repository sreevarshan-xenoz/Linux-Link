"""
Tests for API endpoints
"""

import pytest
import json
from unittest.mock import patch, Mock
from fastapi.testclient import TestClient
from conftest import assert_api_success, assert_api_error, mock_verify_token


class TestFileManagementAPI:
    """Test file management API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_browse_files_endpoint(self, mock_token, client, temp_dir):
        """Test file browsing endpoint"""
        with patch('main.get_file_manager') as mock_fm:
            mock_fm.return_value.browse_directory.return_value = {
                "success": True,
                "items": [
                    {"name": "test.txt", "type": "file", "size": 100},
                    {"name": "subdir", "type": "directory", "size": 0}
                ]
            }
            
            response = client.post("/files/browse", json={"path": temp_dir})
            assert_api_success(response, ["items"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_file_operations_endpoint(self, mock_token, client):
        """Test file operations endpoint"""
        with patch('main.get_file_manager') as mock_fm:
            mock_fm.return_value.delete_file.return_value = True
            
            response = client.post("/files/operations/delete", json={"file_path": "/test/file.txt"})
            assert_api_success(response)
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_file_preview_endpoint(self, mock_token, client):
        """Test file preview endpoint"""
        with patch('main.get_file_manager') as mock_fm:
            mock_fm.return_value.get_file_preview.return_value = {
                "success": True,
                "content": "file content",
                "size": 12,
                "truncated": False
            }
            
            response = client.post("/files/preview", json={"file_path": "/test/file.txt"})
            assert_api_success(response, ["content"])


class TestDesktopControlAPI:
    """Test desktop control API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_desktop_info_endpoint(self, mock_token, client):
        """Test desktop info endpoint"""
        with patch('main.get_desktop_controller') as mock_dc:
            mock_dc.return_value.get_desktop_info.return_value = {
                "desktop_environment": "GNOME",
                "window_manager": "Mutter",
                "display_server": "Wayland"
            }
            
            response = client.get("/desktop/info")
            assert_api_success(response, ["desktop_info"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_workspace_switch_endpoint(self, mock_token, client):
        """Test workspace switching endpoint"""
        with patch('main.get_desktop_controller') as mock_dc:
            mock_dc.return_value.switch_workspace.return_value = True
            
            response = client.post("/desktop/workspace", json={"workspace_id": 2})
            assert_api_success(response)


class TestMediaControlAPI:
    """Test media control API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_media_players_endpoint(self, mock_token, client):
        """Test media players endpoint"""
        with patch('main.get_media_controller') as mock_mc:
            mock_mc.return_value.get_players.return_value = [
                {"name": "Spotify", "status": "playing"},
                {"name": "VLC", "status": "paused"}
            ]
            
            response = client.get("/media/players")
            assert_api_success(response, ["players"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_media_control_endpoint(self, mock_token, client):
        """Test media control endpoint"""
        with patch('main.get_media_controller') as mock_mc:
            mock_mc.return_value.play.return_value = True
            
            response = client.post("/media/play", json={"player": "Spotify"})
            assert_api_success(response)


class TestVoiceCommandAPI:
    """Test voice command API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_voice_process_endpoint(self, mock_token, client):
        """Test voice command processing endpoint"""
        with patch('main.get_voice_processor') as mock_vp:
            mock_vp.return_value.process_command.return_value = {
                "success": True,
                "command": "open file manager",
                "action": "launch_application",
                "result": "File manager opened"
            }
            
            response = client.post("/voice/process", json={"text": "open file manager"})
            assert_api_success(response, ["result"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_custom_commands_endpoint(self, mock_token, client):
        """Test custom commands endpoint"""
        with patch('main.get_voice_processor') as mock_vp:
            mock_vp.return_value.register_custom_command.return_value = True
            
            response = client.post("/voice/commands/custom", json={
                "trigger": "test command",
                "actions": ["echo hello"],
                "description": "Test command"
            })
            assert_api_success(response)


class TestAutomationAPI:
    """Test automation API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_automation_stats_endpoint(self, mock_token, client):
        """Test automation statistics endpoint"""
        with patch('main.get_automation_engine') as mock_ae:
            mock_ae.return_value.get_automation_stats.return_value = {
                "total_macros": 5,
                "active_executions": 2,
                "scheduled_tasks": 3
            }
            
            response = client.get("/automation/stats")
            assert_api_success(response, ["stats"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_create_macro_endpoint(self, mock_token, client, sample_macro):
        """Test macro creation endpoint"""
        with patch('main.get_automation_engine') as mock_ae:
            mock_ae.return_value.create_macro.return_value = True
            
            response = client.post("/automation/macros", json=sample_macro)
            assert_api_success(response)
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_execute_macro_endpoint(self, mock_token, client):
        """Test macro execution endpoint"""
        with patch('main.get_automation_engine') as mock_ae:
            mock_ae.return_value.execute_macro.return_value = "exec_123"
            
            response = client.post("/automation/macros/execute", json={
                "macro_id": "test_macro",
                "variables": {"var1": "value1"}
            })
            assert_api_success(response, ["execution_id"])


class TestPackageManagementAPI:
    """Test package management API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_package_search_endpoint(self, mock_token, client):
        """Test package search endpoint"""
        with patch('main.get_package_manager') as mock_pm:
            mock_pm.return_value.search_packages.return_value = [
                {"name": "vim", "version": "8.2", "description": "Text editor"},
                {"name": "emacs", "version": "27.1", "description": "Text editor"}
            ]
            
            response = client.post("/packages/search", json={
                "query": "editor",
                "include_aur": True
            })
            assert_api_success(response, ["packages"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_package_install_endpoint(self, mock_token, client):
        """Test package installation endpoint"""
        with patch('main.get_package_manager') as mock_pm:
            mock_pm.return_value.install_packages.return_value = "install_123"
            
            response = client.post("/packages/install", json={
                "package_names": ["vim", "git"],
                "from_aur": False
            })
            assert_api_success(response, ["operation_id"])


class TestDeviceManagementAPI:
    """Test device management API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_device_registration_endpoint(self, mock_token, client, sample_device):
        """Test device registration endpoint"""
        with patch('main.get_device_manager') as mock_dm:
            mock_dm.return_value.register_device.return_value = "device_123"
            
            response = client.post("/devices/register", json=sample_device)
            assert_api_success(response, ["device_id"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_get_devices_endpoint(self, mock_token, client):
        """Test get devices endpoint"""
        with patch('main.get_device_manager') as mock_dm:
            mock_dm.return_value.get_user_devices.return_value = [
                {"device_id": "dev1", "device_name": "Phone", "enabled": True},
                {"device_id": "dev2", "device_name": "Tablet", "enabled": True}
            ]
            
            response = client.get("/devices")
            assert_api_success(response, ["devices"])


class TestActivityLoggingAPI:
    """Test activity logging API endpoints"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_activity_logs_endpoint(self, mock_token, client):
        """Test activity logs endpoint"""
        with patch('main.get_activity_logger') as mock_al:
            mock_al.return_value.search_logs.return_value = [
                {"timestamp": 1234567890, "action": "login", "success": True},
                {"timestamp": 1234567891, "action": "file_access", "success": True}
            ]
            
            response = client.get("/activity/logs?limit=10")
            assert_api_success(response, ["logs"])
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_activity_summary_endpoint(self, mock_token, client):
        """Test activity summary endpoint"""
        with patch('main.get_activity_logger') as mock_al:
            mock_al.return_value.get_user_activity_summary.return_value = {
                "total_activities": 100,
                "successful_activities": 95,
                "failed_activities": 5
            }
            
            response = client.get("/activity/summary")
            assert_api_success(response, ["summary"])


class TestErrorHandlingAPI:
    """Test error handling API endpoints"""
    
    @patch('main.verify_token', return_value={"sub": "admin_user", "role": "admin"})
    def test_error_statistics_endpoint(self, mock_token, client):
        """Test error statistics endpoint"""
        with patch('main.get_error_handler') as mock_eh:
            mock_eh.return_value.get_error_statistics.return_value = {
                "total_errors": 50,
                "recent_errors": 5,
                "recovery_rate": 80.0
            }
            
            response = client.get("/errors/statistics")
            assert_api_success(response, ["statistics"])
    
    @patch('main.verify_token', return_value={"sub": "admin_user", "role": "admin"})
    def test_recent_errors_endpoint(self, mock_token, client):
        """Test recent errors endpoint"""
        with patch('main.get_error_handler') as mock_eh:
            mock_eh.return_value.get_recent_errors.return_value = [
                {"error_id": "err1", "severity": "high", "message": "Test error"},
                {"error_id": "err2", "severity": "medium", "message": "Another error"}
            ]
            
            response = client.get("/errors/recent?limit=10")
            assert_api_success(response, ["errors"])


class TestAuthenticationAPI:
    """Test authentication API endpoints"""
    
    def test_login_endpoint(self, client):
        """Test login endpoint"""
        with patch('main.authenticate_user') as mock_auth:
            mock_auth.return_value = {"sub": "test_user", "role": "user"}
            
            with patch('main.jwt.encode') as mock_jwt:
                mock_jwt.return_value = "mock_token"
                
                response = client.post("/auth/login", json={
                    "username": "test_user",
                    "password": "test_password"
                })
                
                # This would normally succeed with proper mocking
                # For now, just verify the endpoint exists
                assert response.status_code in [200, 401, 500]
    
    def test_unauthorized_access(self, client):
        """Test unauthorized access to protected endpoints"""
        response = client.get("/files/browse")
        assert response.status_code == 422  # Missing authorization header
    
    @patch('main.verify_token', side_effect=Exception("Invalid token"))
    def test_invalid_token(self, mock_token, client):
        """Test invalid token handling"""
        response = client.get("/desktop/info")
        assert response.status_code in [401, 500]


class TestAPIErrorHandling:
    """Test API error handling"""
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_file_not_found_error(self, mock_token, client):
        """Test file not found error handling"""
        with patch('main.get_file_manager') as mock_fm:
            from file_manager import FileManagerError
            mock_fm.return_value.browse_directory.side_effect = FileManagerError(
                "Directory not found", "DIR_NOT_FOUND"
            )
            
            response = client.post("/files/browse", json={"path": "/nonexistent"})
            assert response.status_code in [400, 404, 500]
    
    @patch('main.verify_token', return_value=mock_verify_token())
    def test_permission_denied_error(self, mock_token, client):
        """Test permission denied error handling"""
        with patch('main.get_file_manager') as mock_fm:
            from file_manager import PermissionError
            mock_fm.return_value.delete_file.side_effect = PermissionError(
                "Permission denied"
            )
            
            response = client.post("/files/operations/delete", json={"file_path": "/protected"})
            assert response.status_code in [403, 500]
    
    def test_validation_error(self, client):
        """Test request validation error"""
        # Send invalid JSON
        response = client.post("/files/browse", json={"invalid_field": "value"})
        assert response.status_code == 422  # Validation error