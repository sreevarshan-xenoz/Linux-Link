import shlex
import subprocess
import re
import os
from typing import List, Dict, Any
from pathlib import Path

class SecureCommandExecutor:
    """Production-grade command execution with multiple security layers"""
    
    SAFE_COMMANDS = {
        'ls', 'pwd', 'whoami', 'uptime', 'df', 'free', 'ps', 'top',
        'systemctl', 'journalctl', 'cat', 'tail', 'head', 'grep',
        'find', 'wc', 'sort', 'uniq', 'awk', 'sed'
    }
    
    DANGEROUS_PATTERNS = [
        r'\brm\s+-rf\s*/', r'\bdd\s+if=', r'\bmkfs\b', r'\bformat\b',
        r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;:', # Fork bomb
        r'\bchmod\s+777', r'\bchown\s+root', r'>\s*/dev/sd[a-z]',
        r'\binit\s+[06]', r'\bshutdown\b', r'\breboot\b', r'\bhalt\b'
    ]
    
    RESTRICTED_PATHS = {'/etc/shadow', '/etc/passwd', '/root', '/boot'}
    
    def __init__(self, safe_mode: bool = True, allowed_commands: List[str] = None):
        self.safe_mode = safe_mode
        self.allowed_commands = allowed_commands or list(self.SAFE_COMMANDS)
        
    def validate_command(self, command_str: str) -> Dict[str, Any]:
        """Comprehensive command validation with detailed feedback"""
        try:
            args = shlex.split(command_str)
        except ValueError as e:
            return {"valid": False, "error": f"Invalid command syntax: {e}"}
        
        if not args:
            return {"valid": False, "error": "Empty command"}
        
        base_command = args[0]
        
        # Safe mode whitelist check
        if self.safe_mode and base_command not in self.allowed_commands:
            return {
                "valid": False, 
                "error": f"Command '{base_command}' not allowed in safe mode",
                "suggestion": f"Available commands: {', '.join(sorted(self.allowed_commands))}"
            }
        
        # Dangerous pattern detection
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command_str, re.IGNORECASE):
                return {
                    "valid": False,
                    "error": "Potentially dangerous command blocked",
                    "pattern": pattern
                }
        
        # Path traversal protection
        for arg in args:
            if any(restricted in arg for restricted in self.RESTRICTED_PATHS):
                return {
                    "valid": False,
                    "error": f"Access to restricted path denied: {arg}"
                }
        
        return {"valid": True, "args": args}
    
    async def execute_safe(self, command_str: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute command with comprehensive security and error handling"""
        validation = self.validate_command(command_str)
        
        if not validation["valid"]:
            raise ValueError(validation["error"])
        
        try:
            # Execute without shell=True for maximum security
            result = subprocess.run(
                validation["args"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd='/tmp',  # Restricted working directory
                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}  # Minimal PATH
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "command": command_str,
                "safe_mode": self.safe_mode,
                "execution_time": timeout
            }
            
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out after {timeout} seconds")
        except FileNotFoundError:
            raise ValueError(f"Command not found: {validation['args'][0]}")
        except Exception as e:
            raise RuntimeError(f"Execution failed: {str(e)}") 