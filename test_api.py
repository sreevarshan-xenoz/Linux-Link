#!/usr/bin/env python3
"""
Simple test script to verify Linux-Link API functionality
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def test_login():
    """Test login endpoint"""
    print("Testing login...")
    response = requests.post(f"{BASE_URL}/auth/login", json={
        "username": "admin",
        "password": "test_password_123"
    })
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Login successful!")
        print(f"Token type: {data['token_type']}")
        return data['access_token']
    else:
        print(f"❌ Login failed: {response.status_code} - {response.text}")
        return None

def test_verify_token(token):
    """Test token verification"""
    print("\nTesting token verification...")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(f"{BASE_URL}/auth/verify-token", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Token verification successful!")
        print(f"User: {data['user']}")
        return True
    else:
        print(f"❌ Token verification failed: {response.status_code} - {response.text}")
        return False

def test_system_stats(token):
    """Test system stats endpoint"""
    print("\nTesting system stats...")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/sys/stats", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print("✅ System stats retrieved successfully!")
        print(f"CPU cores: {data['cpu']['count']}")
        print(f"Memory usage: {data['memory']['percent']:.1f}%")
        print(f"Uptime: {data['uptime']}")
        return True
    else:
        print(f"❌ System stats failed: {response.status_code} - {response.text}")
        return False

def test_quick_status(token):
    """Test quick status endpoint"""
    print("\nTesting quick status...")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/sys/quick-status", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Quick status retrieved successfully!")
        print(f"CPU: {data['system_stats']['cpu_percent']:.1f}%")
        print(f"Memory: {data['system_stats']['memory_percent']:.1f}%")
        print(f"Disk: {data['system_stats']['disk_percent']:.1f}%")
        return True
    else:
        print(f"❌ Quick status failed: {response.status_code} - {response.text}")
        return False

def test_command_execution(token):
    """Test command execution"""
    print("\nTesting command execution...")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Test safe command
    response = requests.post(f"{BASE_URL}/exec", 
                           headers=headers,
                           json={"cmd": "whoami", "timeout": 10})
    
    if response.status_code == 200:
        data = response.json()
        print("✅ Command execution successful!")
        print(f"Command: {data['command']}")
        print(f"Output: {data['stdout'].strip()}")
        print(f"Return code: {data['returncode']}")
        return True
    else:
        print(f"❌ Command execution failed: {response.status_code} - {response.text}")
        return False

def main():
    print("🚀 Linux-Link API Test Suite")
    print("=" * 40)
    
    try:
        # Test login
        token = test_login()
        if not token:
            return
        
        # Test token verification
        if not test_verify_token(token):
            return
        
        # Test system stats
        if not test_system_stats(token):
            return
        
        # Test quick status
        if not test_quick_status(token):
            return
        
        # Test command execution
        if not test_command_execution(token):
            return
        
        print("\n🎉 All tests passed! Linux-Link API is working correctly.")
        
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed. Make sure the backend server is running on http://localhost:8000")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()