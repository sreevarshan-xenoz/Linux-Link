"""
i3/Sway Adapter

Provides integration with i3 and Sway window managers using their IPC protocol.
Both window managers use the same IPC interface, so this adapter works for both.
"""

import os
import json
import socket
import struct
import subprocess
import logging
from typing import List, Union, Dict, Any, Optional

# Import from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from desktop_controller import WindowManagerAdapter, Workspace, Window, Monitor

logger = logging.getLogger(__name__)


class I3SwayAdapter(WindowManagerAdapter):
    """Unified adapter for i3 and Sway window managers"""
    
    # i3/Sway IPC message types
    IPC_COMMAND = 0
    IPC_GET_WORKSPACES = 1
    IPC_SUBSCRIBE = 2
    IPC_GET_OUTPUTS = 3
    IPC_GET_TREE = 4
    IPC_GET_MARKS = 5
    IPC_GET_BAR_CONFIG = 6
    IPC_GET_VERSION = 7
    IPC_GET_BINDING_MODES = 8
    IPC_GET_CONFIG = 9
    IPC_SEND_TICK = 10
    IPC_SYNC = 11
    
    def __init__(self, wm_type: str = None):
        """
        Initialize adapter for i3 or Sway.
        
        Args:
            wm_type: 'i3' or 'sway', auto-detected if None
        """
        self.wm_type = wm_type or self._detect_wm_type()
        self.socket_path = self._get_socket_path()
        
        if not self.socket_path:
            raise RuntimeError(f"{self.wm_type} socket not found")
        
        logger.info(f"{self.wm_type} adapter initialized with socket: {self.socket_path}")
    
    def _detect_wm_type(self) -> str:
        """Detect whether we're running i3 or Sway"""
        # Check environment variables first
        if os.getenv('SWAYSOCK'):
            return 'sway'
        elif os.getenv('I3SOCK'):
            return 'i3'
        
        # Check for running processes
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                processes = result.stdout.lower()
                if 'sway' in processes and 'i3' not in processes:
                    return 'sway'
                elif 'i3' in processes:
                    return 'i3'
        except:
            pass
        
        # Default to i3
        return 'i3'
    
    def _get_socket_path(self) -> Optional[str]:
        """Get i3/Sway IPC socket path"""
        # Check environment variables
        if self.wm_type == 'sway':
            socket_path = os.getenv('SWAYSOCK')
            if socket_path and os.path.exists(socket_path):
                return socket_path
        else:  # i3
            socket_path = os.getenv('I3SOCK')
            if socket_path and os.path.exists(socket_path):
                return socket_path
        
        # Try to get socket path from command
        try:
            if self.wm_type == 'sway':
                result = subprocess.run(['sway', '--get-socketpath'], 
                                      capture_output=True, text=True, timeout=2)
            else:  # i3
                result = subprocess.run(['i3', '--get-socketpath'], 
                                      capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                socket_path = result.stdout.strip()
                if os.path.exists(socket_path):
                    return socket_path
        except:
            pass
        
        # Search common locations
        import glob
        
        # Get user ID (Windows compatible)
        try:
            uid = os.getuid()
        except AttributeError:
            # Windows doesn't have getuid, use a fallback
            uid = 1000
        
        if self.wm_type == 'sway':
            patterns = [
                f"/run/user/{uid}/sway-ipc.*.sock",
                "/tmp/sway-ipc.*.sock"
            ]
        else:  # i3
            patterns = [
                f"/run/user/{uid}/i3/ipc-socket.*",
                "/tmp/i3-*.sock"
            ]
        
        for pattern in patterns:
            matches = glob.glob(pattern)
            if matches:
                return matches[0]
        
        return None
    
    def _send_ipc_message(self, message_type: int, payload: str = "") -> Dict:
        """
        Send IPC message to i3/Sway.
        
        Args:
            message_type: IPC message type constant
            payload: Message payload
            
        Returns:
            Parsed JSON response
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.socket_path)
            
            # Prepare message
            payload_bytes = payload.encode('utf-8')
            message = b'i3-ipc' + struct.pack('<II', len(payload_bytes), message_type) + payload_bytes
            
            # Send message
            sock.send(message)
            
            # Read response header
            header = sock.recv(14)  # 6 bytes magic + 4 bytes length + 4 bytes type
            if len(header) < 14:
                raise Exception("Incomplete header received")
            
            magic = header[:6]
            if magic != b'i3-ipc':
                raise Exception("Invalid magic string in response")
            
            length, response_type = struct.unpack('<II', header[6:14])
            
            # Read response payload
            response_data = b''
            while len(response_data) < length:
                chunk = sock.recv(length - len(response_data))
                if not chunk:
                    break
                response_data += chunk
            
            sock.close()
            
            # Parse JSON response
            if response_data:
                return json.loads(response_data.decode('utf-8'))
            else:
                return {}
        
        except Exception as e:
            logger.error(f"IPC message failed: {e}")
            return {}
    
    def _execute_command(self, command: str) -> bool:
        """Execute i3/Sway command"""
        try:
            response = self._send_ipc_message(self.IPC_COMMAND, command)
            
            # Check if command was successful
            if isinstance(response, list) and len(response) > 0:
                return response[0].get('success', False)
            
            return False
        
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False
    
    def get_workspaces(self) -> List[Workspace]:
        """Get list of workspaces from i3/Sway"""
        try:
            workspaces_data = self._send_ipc_message(self.IPC_GET_WORKSPACES)
            if not workspaces_data:
                return []
            
            # Get window tree to associate windows with workspaces
            tree_data = self._send_ipc_message(self.IPC_GET_TREE)
            windows_by_workspace = self._extract_windows_from_tree(tree_data)
            
            workspaces = []
            for workspace_data in workspaces_data:
                workspace_name = workspace_data.get('name', 'Unknown')
                workspace_num = workspace_data.get('num', workspace_name)
                
                workspace = Workspace(
                    id=workspace_num,
                    name=workspace_name,
                    active=workspace_data.get('focused', False),
                    windows=windows_by_workspace.get(workspace_name, []),
                    monitor=workspace_data.get('output', 'Unknown')
                )
                workspaces.append(workspace)
            
            # Sort by workspace number/name
            workspaces.sort(key=lambda w: (int(w.id) if str(w.id).isdigit() else 999, str(w.name)))
            
            logger.info(f"Retrieved {len(workspaces)} workspaces from {self.wm_type}")
            return workspaces
        
        except Exception as e:
            logger.error(f"Failed to get workspaces: {e}")
            return []
    
    def _extract_windows_from_tree(self, tree_data: Dict) -> Dict[str, List[Window]]:
        """Extract windows from i3/Sway tree structure"""
        windows_by_workspace = {}
        
        def traverse_tree(node, workspace_name=None):
            # Update workspace name if this is a workspace node
            if node.get('type') == 'workspace':
                workspace_name = node.get('name', workspace_name)
            
            # If this is a window (con type with window property)
            if (node.get('type') == 'con' and 
                node.get('window') and 
                workspace_name):
                
                window = Window(
                    id=str(node.get('window', '')),
                    title=node.get('name', 'Unknown'),
                    class_name=node.get('window_properties', {}).get('class', 'unknown'),
                    workspace=workspace_name,
                    geometry={
                        'x': node.get('rect', {}).get('x', 0),
                        'y': node.get('rect', {}).get('y', 0),
                        'width': node.get('rect', {}).get('width', 800),
                        'height': node.get('rect', {}).get('height', 600)
                    },
                    focused=node.get('focused', False),
                    floating=node.get('type') == 'floating_con',
                    fullscreen=node.get('fullscreen_mode', 0) > 0,
                    minimized=False  # i3/Sway doesn't have minimized windows
                )
                
                if workspace_name not in windows_by_workspace:
                    windows_by_workspace[workspace_name] = []
                windows_by_workspace[workspace_name].append(window)
            
            # Recursively traverse child nodes
            for child in node.get('nodes', []):
                traverse_tree(child, workspace_name)
            
            # Also traverse floating nodes
            for child in node.get('floating_nodes', []):
                traverse_tree(child, workspace_name)
        
        if tree_data:
            traverse_tree(tree_data)
        
        return windows_by_workspace
    
    def get_windows(self) -> List[Window]:
        """Get list of all windows from i3/Sway"""
        try:
            tree_data = self._send_ipc_message(self.IPC_GET_TREE)
            windows_by_workspace = self._extract_windows_from_tree(tree_data)
            
            # Flatten all windows
            all_windows = []
            for windows in windows_by_workspace.values():
                all_windows.extend(windows)
            
            logger.info(f"Retrieved {len(all_windows)} windows from {self.wm_type}")
            return all_windows
        
        except Exception as e:
            logger.error(f"Failed to get windows: {e}")
            return []
    
    def switch_workspace(self, workspace_id: Union[int, str]) -> bool:
        """Switch to specified workspace"""
        try:
            command = f"workspace {workspace_id}"
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Switched to workspace {workspace_id}")
            else:
                logger.warning(f"Failed to switch to workspace {workspace_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to switch workspace: {e}")
            return False
    
    def focus_window(self, window_id: Union[int, str]) -> bool:
        """Focus specified window"""
        try:
            # Use window ID criteria
            command = f"[id=\"{window_id}\"] focus"
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Focused window {window_id}")
            else:
                logger.warning(f"Failed to focus window {window_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to focus window: {e}")
            return False
    
    def close_window(self, window_id: Union[int, str]) -> bool:
        """Close specified window"""
        try:
            # Use window ID criteria
            command = f"[id=\"{window_id}\"] kill"
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Closed window {window_id}")
            else:
                logger.warning(f"Failed to close window {window_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to close window: {e}")
            return False
    
    def move_window(self, window_id: Union[int, str], x: int, y: int) -> bool:
        """Move window to specified position"""
        try:
            # First focus the window, then move it
            focus_command = f"[id=\"{window_id}\"] focus"
            move_command = f"[id=\"{window_id}\"] floating enable, move position {x} {y}"
            
            focus_success = self._execute_command(focus_command)
            move_success = self._execute_command(move_command)
            
            success = focus_success and move_success
            
            if success:
                logger.info(f"Moved window {window_id} to ({x}, {y})")
            else:
                logger.warning(f"Failed to move window {window_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to move window: {e}")
            return False
    
    def resize_window(self, window_id: Union[int, str], width: int, height: int) -> bool:
        """Resize window to specified dimensions"""
        try:
            # Focus window and resize
            focus_command = f"[id=\"{window_id}\"] focus"
            resize_command = f"[id=\"{window_id}\"] floating enable, resize set {width} {height}"
            
            focus_success = self._execute_command(focus_command)
            resize_success = self._execute_command(resize_command)
            
            success = focus_success and resize_success
            
            if success:
                logger.info(f"Resized window {window_id} to {width}x{height}")
            else:
                logger.warning(f"Failed to resize window {window_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to resize window: {e}")
            return False
    
    def get_monitors(self) -> List[Monitor]:
        """Get list of monitors from i3/Sway"""
        try:
            outputs_data = self._send_ipc_message(self.IPC_GET_OUTPUTS)
            if not outputs_data:
                return []
            
            monitors = []
            for output_data in outputs_data:
                # Skip inactive outputs
                if not output_data.get('active', False):
                    continue
                
                rect = output_data.get('rect', {})
                
                monitor = Monitor(
                    id=len(monitors),
                    name=output_data.get('name', 'Unknown'),
                    width=rect.get('width', 1920),
                    height=rect.get('height', 1080),
                    x=rect.get('x', 0),
                    y=rect.get('y', 0),
                    active=output_data.get('active', False),
                    primary=output_data.get('primary', False)
                )
                monitors.append(monitor)
            
            logger.info(f"Retrieved {len(monitors)} monitors from {self.wm_type}")
            return monitors
        
        except Exception as e:
            logger.error(f"Failed to get monitors: {e}")
            return []
    
    def toggle_fullscreen(self, window_id: Union[int, str] = None) -> bool:
        """Toggle fullscreen for window"""
        try:
            if window_id:
                command = f"[id=\"{window_id}\"] fullscreen toggle"
            else:
                command = "fullscreen toggle"
            
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Toggled fullscreen for window {window_id or 'focused'}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to toggle fullscreen: {e}")
            return False
    
    def move_window_to_workspace(self, window_id: Union[int, str], workspace_id: Union[int, str]) -> bool:
        """Move window to specified workspace"""
        try:
            command = f"[id=\"{window_id}\"] move container to workspace {workspace_id}"
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Moved window {window_id} to workspace {workspace_id}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to move window to workspace: {e}")
            return False
    
    def set_layout(self, layout: str, window_id: Union[int, str] = None) -> bool:
        """Set layout for container"""
        try:
            valid_layouts = ['default', 'stacked', 'tabbed', 'splitv', 'splith']
            if layout not in valid_layouts:
                logger.warning(f"Invalid layout: {layout}")
                return False
            
            if window_id:
                command = f"[id=\"{window_id}\"] layout {layout}"
            else:
                command = f"layout {layout}"
            
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Set layout to {layout}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to set layout: {e}")
            return False
    
    def split_container(self, direction: str, window_id: Union[int, str] = None) -> bool:
        """Split container in specified direction"""
        try:
            if direction not in ['horizontal', 'vertical', 'h', 'v']:
                logger.warning(f"Invalid split direction: {direction}")
                return False
            
            # Normalize direction
            if direction in ['horizontal', 'h']:
                split_cmd = 'splith'
            else:
                split_cmd = 'splitv'
            
            if window_id:
                command = f"[id=\"{window_id}\"] split {split_cmd}"
            else:
                command = f"split {split_cmd}"
            
            success = self._execute_command(command)
            
            if success:
                logger.info(f"Split container {direction}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to split container: {e}")
            return False
    
    def get_version(self) -> Dict[str, Any]:
        """Get i3/Sway version information"""
        try:
            version_data = self._send_ipc_message(self.IPC_GET_VERSION)
            return version_data
        
        except Exception as e:
            logger.error(f"Failed to get version: {e}")
            return {}


# Convenience classes for specific window managers
class I3Adapter(I3SwayAdapter):
    """Specific adapter for i3 window manager"""
    def __init__(self):
        super().__init__('i3')


class SwayAdapter(I3SwayAdapter):
    """Specific adapter for Sway window manager"""
    def __init__(self):
        super().__init__('sway')