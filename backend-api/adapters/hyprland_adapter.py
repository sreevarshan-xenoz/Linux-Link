"""
Hyprland Adapter

Provides integration with Hyprland window manager using hyprctl commands
and IPC socket communication for workspace and window management.
"""

import os
import json
import socket
import subprocess
import logging
from typing import List, Union, Dict, Any, Optional

# Import from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from desktop_controller import WindowManagerAdapter, Workspace, Window, Monitor

logger = logging.getLogger(__name__)


class HyprlandAdapter(WindowManagerAdapter):
    """Adapter for Hyprland window manager"""
    
    def __init__(self):
        self.hyprland_signature = os.getenv('HYPRLAND_INSTANCE_SIGNATURE')
        self.socket_path = self._get_socket_path()
        self.command_socket_path = self._get_command_socket_path()
        
        if not self.socket_path:
            raise RuntimeError("Hyprland socket not found")
        
        logger.info(f"Hyprland adapter initialized with socket: {self.socket_path}")
    
    def _get_socket_path(self) -> Optional[str]:
        """Get Hyprland IPC socket path"""
        if self.hyprland_signature:
            socket_path = f"/tmp/hypr/{self.hyprland_signature}/.socket.sock"
            if os.path.exists(socket_path):
                return socket_path
        
        # Fallback: search for socket
        import glob
        socket_patterns = [
            "/tmp/hypr/*/hyprland.sock",
            "/tmp/hypr/*/.socket.sock"
        ]
        
        for pattern in socket_patterns:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
        
        return None
    
    def _get_command_socket_path(self) -> Optional[str]:
        """Get Hyprland command socket path"""
        if self.hyprland_signature:
            socket_path = f"/tmp/hypr/{self.hyprland_signature}/.socket2.sock"
            if os.path.exists(socket_path):
                return socket_path
        
        # Fallback: search for command socket
        import glob
        socket_patterns = [
            "/tmp/hypr/*/.socket2.sock"
        ]
        
        for pattern in socket_patterns:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
        
        return None
    
    def _execute_hyprctl(self, command: str, json_output: bool = True) -> Union[Dict, str]:
        """
        Execute hyprctl command.
        
        Args:
            command: hyprctl command to execute
            json_output: Whether to request JSON output
            
        Returns:
            Command output (parsed JSON if json_output=True)
        """
        try:
            cmd = ['hyprctl']
            if json_output:
                cmd.append('-j')
            cmd.extend(command.split())
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode != 0:
                logger.error(f"hyprctl command failed: {result.stderr}")
                return {} if json_output else ""
            
            if json_output:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse hyprctl JSON output: {e}")
                    return {}
            else:
                return result.stdout.strip()
        
        except subprocess.TimeoutExpired:
            logger.error(f"hyprctl command timed out: {command}")
            return {} if json_output else ""
        except FileNotFoundError:
            logger.error("hyprctl command not found")
            return {} if json_output else ""
        except Exception as e:
            logger.error(f"hyprctl command error: {e}")
            return {} if json_output else ""
    
    def _send_socket_command(self, command: str) -> str:
        """
        Send command to Hyprland via socket.
        
        Args:
            command: Command to send
            
        Returns:
            Response from socket
        """
        if not self.command_socket_path:
            logger.error("Hyprland command socket not available")
            return ""
        
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.command_socket_path)
            sock.send(command.encode())
            
            response = ""
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                response += data.decode()
            
            sock.close()
            return response.strip()
        
        except Exception as e:
            logger.error(f"Socket command failed: {e}")
            return ""
    
    def get_workspaces(self) -> List[Workspace]:
        """Get list of workspaces from Hyprland"""
        try:
            # Get workspaces
            workspaces_data = self._execute_hyprctl("workspaces")
            if not workspaces_data:
                return []
            
            # Get windows for each workspace
            windows_data = self._execute_hyprctl("clients")
            windows_by_workspace = {}
            
            if windows_data:
                for window_data in windows_data:
                    workspace_id = window_data.get('workspace', {}).get('id', 1)
                    if workspace_id not in windows_by_workspace:
                        windows_by_workspace[workspace_id] = []
                    
                    window = Window(
                        id=window_data.get('address', ''),
                        title=window_data.get('title', 'Unknown'),
                        class_name=window_data.get('class', 'unknown'),
                        workspace=workspace_id,
                        geometry={
                            'x': window_data.get('at', [0, 0])[0],
                            'y': window_data.get('at', [0, 0])[1],
                            'width': window_data.get('size', [800, 600])[0],
                            'height': window_data.get('size', [800, 600])[1]
                        },
                        focused=window_data.get('focusHistoryID', 0) == 0,
                        floating=window_data.get('floating', False),
                        fullscreen=window_data.get('fullscreen', False),
                        minimized=window_data.get('hidden', False)
                    )
                    windows_by_workspace[workspace_id].append(window)
            
            # Get active workspace
            active_workspace_data = self._execute_hyprctl("activeworkspace")
            active_workspace_id = active_workspace_data.get('id', 1) if active_workspace_data else 1
            
            # Build workspace list
            workspaces = []
            for workspace_data in workspaces_data:
                workspace_id = workspace_data.get('id', 1)
                workspace_name = workspace_data.get('name', str(workspace_id))
                monitor = workspace_data.get('monitor', 'Unknown')
                
                workspace = Workspace(
                    id=workspace_id,
                    name=workspace_name,
                    active=(workspace_id == active_workspace_id),
                    windows=windows_by_workspace.get(workspace_id, []),
                    monitor=monitor
                )
                workspaces.append(workspace)
            
            # Sort by workspace ID
            workspaces.sort(key=lambda w: int(w.id) if str(w.id).isdigit() else 999)
            
            logger.info(f"Retrieved {len(workspaces)} workspaces from Hyprland")
            return workspaces
        
        except Exception as e:
            logger.error(f"Failed to get workspaces: {e}")
            return []
    
    def get_windows(self) -> List[Window]:
        """Get list of all windows from Hyprland"""
        try:
            windows_data = self._execute_hyprctl("clients")
            if not windows_data:
                return []
            
            windows = []
            for window_data in windows_data:
                window = Window(
                    id=window_data.get('address', ''),
                    title=window_data.get('title', 'Unknown'),
                    class_name=window_data.get('class', 'unknown'),
                    workspace=window_data.get('workspace', {}).get('id', 1),
                    geometry={
                        'x': window_data.get('at', [0, 0])[0],
                        'y': window_data.get('at', [0, 0])[1],
                        'width': window_data.get('size', [800, 600])[0],
                        'height': window_data.get('size', [800, 600])[1]
                    },
                    focused=window_data.get('focusHistoryID', 0) == 0,
                    floating=window_data.get('floating', False),
                    fullscreen=window_data.get('fullscreen', False),
                    minimized=window_data.get('hidden', False)
                )
                windows.append(window)
            
            logger.info(f"Retrieved {len(windows)} windows from Hyprland")
            return windows
        
        except Exception as e:
            logger.error(f"Failed to get windows: {e}")
            return []
    
    def switch_workspace(self, workspace_id: Union[int, str]) -> bool:
        """Switch to specified workspace"""
        try:
            command = f"workspace {workspace_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch workspace {workspace_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Switched to workspace {workspace_id}")
            else:
                logger.warning(f"Failed to switch to workspace {workspace_id}: {response}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to switch workspace: {e}")
            return False
    
    def focus_window(self, window_id: Union[int, str]) -> bool:
        """Focus specified window"""
        try:
            # Use address format for Hyprland
            if not str(window_id).startswith('0x'):
                window_id = f"address:{window_id}"
            
            command = f"focuswindow {window_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch focuswindow {window_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Focused window {window_id}")
            else:
                logger.warning(f"Failed to focus window {window_id}: {response}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to focus window: {e}")
            return False
    
    def close_window(self, window_id: Union[int, str]) -> bool:
        """Close specified window"""
        try:
            # Use address format for Hyprland
            if not str(window_id).startswith('0x'):
                window_id = f"address:{window_id}"
            
            command = f"closewindow {window_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch closewindow {window_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Closed window {window_id}")
            else:
                logger.warning(f"Failed to close window {window_id}: {response}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to close window: {e}")
            return False
    
    def move_window(self, window_id: Union[int, str], x: int, y: int) -> bool:
        """Move window to specified position"""
        try:
            # Use address format for Hyprland
            if not str(window_id).startswith('0x'):
                window_id = f"address:{window_id}"
            
            command = f"movewindowpixel exact {x} {y},{window_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch movewindowpixel exact {x} {y},{window_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Moved window {window_id} to ({x}, {y})")
            else:
                logger.warning(f"Failed to move window {window_id}: {response}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to move window: {e}")
            return False
    
    def resize_window(self, window_id: Union[int, str], width: int, height: int) -> bool:
        """Resize window to specified dimensions"""
        try:
            # Use address format for Hyprland
            if not str(window_id).startswith('0x'):
                window_id = f"address:{window_id}"
            
            command = f"resizewindowpixel exact {width} {height},{window_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch resizewindowpixel exact {width} {height},{window_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Resized window {window_id} to {width}x{height}")
            else:
                logger.warning(f"Failed to resize window {window_id}: {response}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to resize window: {e}")
            return False
    
    def get_monitors(self) -> List[Monitor]:
        """Get list of monitors from Hyprland"""
        try:
            monitors_data = self._execute_hyprctl("monitors")
            if not monitors_data:
                return []
            
            monitors = []
            for monitor_data in monitors_data:
                monitor = Monitor(
                    id=monitor_data.get('id', 0),
                    name=monitor_data.get('name', 'Unknown'),
                    width=monitor_data.get('width', 1920),
                    height=monitor_data.get('height', 1080),
                    x=monitor_data.get('x', 0),
                    y=monitor_data.get('y', 0),
                    active=monitor_data.get('focused', False),
                    primary=monitor_data.get('id', 0) == 0  # First monitor is usually primary
                )
                monitors.append(monitor)
            
            logger.info(f"Retrieved {len(monitors)} monitors from Hyprland")
            return monitors
        
        except Exception as e:
            logger.error(f"Failed to get monitors: {e}")
            return []
    
    def get_active_window(self) -> Optional[Window]:
        """Get currently active window"""
        try:
            window_data = self._execute_hyprctl("activewindow")
            if not window_data:
                return None
            
            window = Window(
                id=window_data.get('address', ''),
                title=window_data.get('title', 'Unknown'),
                class_name=window_data.get('class', 'unknown'),
                workspace=window_data.get('workspace', {}).get('id', 1),
                geometry={
                    'x': window_data.get('at', [0, 0])[0],
                    'y': window_data.get('at', [0, 0])[1],
                    'width': window_data.get('size', [800, 600])[0],
                    'height': window_data.get('size', [800, 600])[1]
                },
                focused=True,
                floating=window_data.get('floating', False),
                fullscreen=window_data.get('fullscreen', False),
                minimized=window_data.get('hidden', False)
            )
            
            return window
        
        except Exception as e:
            logger.error(f"Failed to get active window: {e}")
            return None
    
    def set_wallpaper(self, image_path: str, monitor: str = None) -> bool:
        """Set wallpaper using hyprpaper or similar"""
        try:
            # Try hyprpaper first
            if monitor:
                command = f"hyprctl hyprpaper wallpaper \"{monitor},{image_path}\""
            else:
                command = f"hyprctl hyprpaper wallpaper \"{image_path}\""
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.info(f"Set wallpaper: {image_path}")
                return True
            else:
                logger.warning(f"Failed to set wallpaper: {result.stderr}")
                return False
        
        except Exception as e:
            logger.error(f"Failed to set wallpaper: {e}")
            return False
    
    def toggle_fullscreen(self, window_id: Union[int, str] = None) -> bool:
        """Toggle fullscreen for window"""
        try:
            if window_id:
                # Focus window first, then toggle fullscreen
                self.focus_window(window_id)
            
            command = "fullscreen"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl("dispatch fullscreen", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Toggled fullscreen for window {window_id or 'active'}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to toggle fullscreen: {e}")
            return False
    
    def move_window_to_workspace(self, window_id: Union[int, str], workspace_id: Union[int, str]) -> bool:
        """Move window to specified workspace"""
        try:
            # Use address format for Hyprland
            if not str(window_id).startswith('0x'):
                window_id = f"address:{window_id}"
            
            command = f"movetoworkspace {workspace_id},{window_id}"
            response = self._send_socket_command(command)
            
            # Alternative: use hyprctl dispatch
            if not response:
                result = self._execute_hyprctl(f"dispatch movetoworkspace {workspace_id},{window_id}", json_output=False)
                success = "ok" in result.lower() or result == ""
            else:
                success = "ok" in response.lower() or response == ""
            
            if success:
                logger.info(f"Moved window {window_id} to workspace {workspace_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to move window to workspace: {e}")
            return False