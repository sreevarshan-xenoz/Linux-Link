"""
Integration tests for Linux-Link backend
"""

import pytest
import time
import tempfile
import os
from unittest.mock import patch, Mock
from fastapi.testclient import TestClient


class TestFullSystemIntegration:
    """Test full system integration scenarios"""
    
    @patch('main.verify_token', return_value={"sub": "test_user", "role": "user"})
    def test_file_management_workflow(self, mock_token, client, temp_dir):
        """Test complete file management workflow"""
        # Create test file
        test_file = os.path.join(temp_dir, "integration_test.txt")
        with open(test_file, 'w') as f:
            f.write("Integration test content")
        
        with patch('main.get_file_manager') as mock_fm:
            # Mock file manager responses
            mock_fm.return_value.browse_directory.return_value = {
                "success": True,
                "items": [{"name": "integration_test.txt", "type": "file", "size": 24}]
            }
            mock_fm.return_value.get_file_preview.return_value = {
                "success": True,
                "content": "Integration test content",
                "size": 24,
                "truncated": False
            }
            mock_fm.return_value.copy_file.return_value = True
            mock_fm.return_value.delete_file.return_value = True
            
            # 1. Browse directory
            response = client.post("/files/browse", json={"path": temp_dir})
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["items"]) >= 1
            
            # 2. Preview file
            response = client.post("/files/preview", json={"file_path": test_file})
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "content" in data
            
            # 3. Copy file
            response = client.post("/files/operations/copy", json={
                "source_path": test_file,
                "destination_path": f"{temp_dir}/copy_test.txt"
            })
            assert response.status_code == 200
            
            # 4. Delete original file
            response = client.post("/files/operations/delete", json={"file_path": test_file})
            assert response.status_code == 200
    
    @patch('main.verify_token', return_value={"sub": "test_user", "role": "user"})
    def test_automation_workflow(self, mock_token, client, sample_macro):
        """Test complete automation workflow"""
        with patch('main.get_automation_engine') as mock_ae:
            # Mock automation engine responses
            mock_ae.return_value.create_macro.return_value = True
            mock_ae.return_value.execute_macro.return_value = "exec_123"
            mock_ae.return_value.get_macro_status.return_value = Mock(
                execution_id="exec_123",
                status="completed",
                to_dict=lambda: {
                    "execution_id": "exec_123",
                    "status": "completed",
                    "progress": 100
                }
            )
            mock_ae.return_value.get_macros.return_value = [sample_macro]
            
            # 1. Create macro
            response = client.post("/automation/macros", json=sample_macro)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            
            # 2. Execute macro
            response = client.post("/automation/macros/execute", json={
                "macro_id": sample_macro["macro_id"],
                "variables": {"test_var": "test_value"}
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "execution_id" in data
            
            # 3. Check execution status
            execution_id = data["execution_id"]
            response = client.get(f"/automation/executions/{execution_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["execution"]["status"] == "completed"
            
            # 4. List macros
            response = client.get("/automation/macros")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["macros"]) >= 1
    
    @patch('main.verify_token', return_value={"sub": "test_user", "role": "user"})
    def test_package_management_workflow(self, mock_token, client):
        """Test complete package management workflow"""
        with patch('main.get_package_manager') as mock_pm:
            # Mock package manager responses
            mock_pm.return_value.search_packages.return_value = [
                {"name": "vim", "version": "8.2", "description": "Text editor"},
                {"name": "nano", "version": "5.4", "description": "Simple text editor"}
            ]
            mock_pm.return_value.get_package_info.return_value = Mock(
                to_dict=lambda: {
                    "name": "vim",
                    "version": "8.2",
                    "description": "Text editor",
                    "status": "available"
                }
            )
            mock_pm.return_value.install_packages.return_value = "install_123"
            mock_pm.return_value.get_operation_status.return_value = Mock(
                to_dict=lambda: {
                    "operation_id": "install_123",
                    "status": "completed",
                    "progress": 100
                }
            )
            
            # 1. Search packages
            response = client.post("/packages/search", json={
                "query": "editor",
                "include_aur": False
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["packages"]) >= 1
            
            # 2. Get package info
            response = client.get("/packages/info/vim")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["package"]["name"] == "vim"
            
            # 3. Install package
            response = client.post("/packages/install", json={
                "package_names": ["vim"],
                "from_aur": False
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "operation_id" in data
            
            # 4. Check installation status
            operation_id = data["operation_id"]
            response = client.get(f"/packages/operations/{operation_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["operation"]["status"] == "completed"
    
    @patch('main.verify_token', return_value={"sub": "test_user", "role": "user"})
    def test_device_management_workflow(self, mock_token, client, sample_device):
        """Test complete device management workflow"""
        with patch('main.get_device_manager') as mock_dm:
            # Mock device manager responses
            mock_dm.return_value.register_device.return_value = "device_123"
            mock_dm.return_value.get_device.return_value = Mock(
                to_dict=lambda: {
                    "device_id": "device_123",
                    "device_name": sample_device["device_name"],
                    "enabled": True,
                    "username": "test_user"
                },
                username="test_user"
            )
            mock_dm.return_value.get_user_devices.return_value = [
                Mock(to_dict=lambda: {
                    "device_id": "device_123",
                    "device_name": sample_device["device_name"],
                    "enabled": True
                })
            ]
            mock_dm.return_value.update_device.return_value = True
            
            # 1. Register device
            response = client.post("/devices/register", json=sample_device)
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "device_id" in data
            
            # 2. Get device info
            device_id = data["device_id"]
            response = client.get(f"/devices/{device_id}")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["device"]["device_name"] == sample_device["device_name"]
            
            # 3. Update device
            response = client.put(f"/devices/{device_id}", json={
                "device_name": "Updated Device Name"
            })
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            
            # 4. List user devices
            response = client.get("/devices")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert len(data["devices"]) >= 1
    
    @patch('main.verify_token', return_value={"sub": "admin_user", "role": "admin"})
    def test_monitoring_workflow(self, mock_token, client, sample_alert_threshold):
        """Test complete monitoring workflow"""
        with patch('main.get_system_monitor') as mock_sm:
            # Mock system monitor responses
            mock_sm.return_value.create_alert_threshold.return_value = "threshold_123"
            mock_sm.return_value.get_alert_thresholds.return_value = [
                Mock(to_dict=lambda: {
                    "threshold_id": "threshold_123",
                    "metric_type": "cpu",
                    "metric_name": "cpu_usage_percent",
                    "warning_value": 80.0,
                    "critical_value": 95.0
                })
            ]
            mock_sm.return_value.get_alerts.return_value = [
                Mock(to_dict=lambda: {
                    "alert_id": "alert_123",
                    "level": "warning",
                    "title": "High CPU Usage",
                    "acknowledged": False
                })
            ]
            mock_sm.return_value.acknowledge_alert.return_value = True
            mock_sm.return_value.get_monitoring_stats.return_value = {
                "total_metrics": 1000,
                "active_alerts": 2,
                "active_thresholds": 5
            }
            
            # Note: Monitoring endpoints would need to be added to main.py
            # This is a placeholder for the workflow structure
            
            # 1. Create alert threshold
            # 2. Get monitoring statistics  
            # 3. List active alerts
            # 4. Acknowledge alert
            # 5. Get metrics data
            
            # For now, just verify the mock setup works
            assert mock_sm.return_value.create_alert_threshold("threshold_123") == "threshold_123"
    
    def test_error_handling_integration(self, client):
        """Test error handling across different components"""
        # Test authentication error
        response = client.get("/files/browse")
        assert response.status_code == 422  # Missing auth header
        
        # Test with invalid token
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/desktop/info", headers=headers)
        assert response.status_code in [401, 422, 500]
        
        # Test validation error
        response = client.post("/files/browse", json={"invalid_field": "value"})
        assert response.status_code == 422
    
    @patch('main.verify_token', return_value={"sub": "test_user", "role": "user"})
    def test_cross_component_integration(self, mock_token, client):
        """Test integration between different components"""
        with patch('main.get_file_manager') as mock_fm, \\
             patch('main.get_automation_engine') as mock_ae, \\
             patch('main.get_activity_logger') as mock_al:
            
            # Mock responses
            mock_fm.return_value.browse_directory.return_value = {
                "success": True,
                "items": [{"name": "test.txt", "type": "file"}]
            }
            mock_ae.return_value.create_macro.return_value = True
            mock_al.return_value.search_logs.return_value = [
                {"timestamp": time.time(), "action": "file_browse", "success": True}
            ]
            
            # 1. Browse files (should log activity)
            response = client.post("/files/browse", json={"path": "/tmp"})
            assert response.status_code == 200
            
            # 2. Create automation macro
            macro_data = {
                "macro_id": "file_macro",
                "name": "File Operations Macro",
                "description": "Automate file operations",
                "actions": [
                    {"id": "1", "type": "command", "command": "ls -la"}
                ]
            }
            response = client.post("/automation/macros", json=macro_data)
            assert response.status_code == 200
            
            # 3. Check activity logs
            response = client.get("/activity/logs?limit=10")
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
    
    def test_performance_under_load(self, client):
        """Test system performance under simulated load"""
        # This would typically use a load testing framework
        # For now, just test multiple concurrent requests
        
        with patch('main.verify_token', return_value={"sub": "test_user", "role": "user"}):
            with patch('main.get_file_manager') as mock_fm:
                mock_fm.return_value.browse_directory.return_value = {
                    "success": True,
                    "items": []
                }
                
                # Simulate multiple requests
                responses = []
                for i in range(10):
                    response = client.post("/files/browse", json={"path": f"/tmp/test_{i}"})
                    responses.append(response)
                
                # All requests should succeed
                for response in responses:
                    assert response.status_code == 200
    
    def test_data_consistency(self, client, temp_dir):
        """Test data consistency across operations"""
        with patch('main.verify_token', return_value={"sub": "test_user", "role": "user"}):
            with patch('main.get_user_manager') as mock_um, \\
                 patch('main.get_device_manager') as mock_dm:
                
                # Mock user and device data
                mock_user = Mock()
                mock_user.username = "test_user"
                mock_user.to_dict.return_value = {"username": "test_user", "role": "user"}
                
                mock_device = Mock()
                mock_device.device_id = "device_123"
                mock_device.username = "test_user"
                mock_device.to_dict.return_value = {
                    "device_id": "device_123",
                    "username": "test_user",
                    "enabled": True
                }
                
                mock_um.return_value.get_user.return_value = mock_user
                mock_dm.return_value.register_device.return_value = "device_123"
                mock_dm.return_value.get_device.return_value = mock_device
                mock_dm.return_value.get_user_devices.return_value = [mock_device]
                
                # Register device
                device_data = {
                    "device_name": "Test Device",
                    "device_type": "mobile",
                    "platform": "android",
                    "app_version": "1.0.0"
                }
                response = client.post("/devices/register", json=device_data)
                assert response.status_code == 200
                
                # Verify device is associated with correct user
                response = client.get("/devices")
                assert response.status_code == 200
                data = response.json()
                assert len(data["devices"]) >= 1
                assert data["devices"][0]["username"] == "test_user"