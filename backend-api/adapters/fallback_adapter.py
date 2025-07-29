"""
Fallback Adapter for Unsupported Window Managers

Provides basic functionality for unknown or unsupported window managers
using generic X11/Wayland tools where possible.
"""

import os
import subprocess
import logging
from typing import List, Union, Dict

# Import from parent directory
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from desktop_controller import WindowManagerAdapter, Workspace, Window, Monitor

logger = logging.getLogger(__name__)


class FallbackAdapter(WindowManagerAdapter):
    """Fallback adapter for unsupported window managers"""
    
    def __init__(self):
        self.display_server = self._detect_display_server()
        logger.info(f"Fallback adapter initialized for {self.display_server}")
    
    def _detect_display_server(self) -> str:
        """Detect if running on X11 or Wayland"""
        if os.getenv('WAYLAND_DISPLAY'):
            return 'wayland'
        elif os.getenv('DISPLAY'):
            return 'x11'
        else:
            return 'unknown'
    
    def get_workspaces(self) -> List[Workspace]:
        """Get list of workspaces (limited functionality)"""
        # For unsupported WMs, return a single default workspace
        windows = self.get_windows()
        
        workspace = Workspace(
            id=1,
            name="Desktop",
            active=True,
            windows=windows,
            monitor=None
        )
        
        return [workspace]
    
    def get_windows(self) -> List[Window]:
        """Get list of windows using generic tools"""
        windows = []
        
        try:
            if self.display_server == 'x11':
                windows = self._get_x11_windows()
            elif self.display_server == 'wayland':
                windows = self._get_wayland_windows()
        except Exception as e:
            logger.warning(f"Failed to get windows: {e}")
        
        return windows
    
    def _get_x11_windows(self) -> List[Window]:
        """Get windows using X11 tools"""
        windows = []
        
        try:
            # Try using wmctrl if available
            result = subprocess.run(['wmctrl', '-l'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split(None, 3)
                        if len(parts) >= 4:
                            window_id = parts[0]
                            desktop = parts[1]
                            hostname = parts[2]
                            title = parts[3]
                            
                            # Get window geometry using xwininfo
                            geometry = self._get_window_geometry_x11(window_id)
                            
                            window = Window(
                                id=window_id,
                                title=title,
                                class_name="unknown",
                                workspace=desktop,
                                geometry=geometry,
                                focused=False  # Can't easily determine focus
                            )
                            windows.append(window)
        
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"wmctrl not available or failed: {e}")
            
            # Fallback to xwininfo
            try:
                result = subprocess.run(['xwininfo', '-root', '-tree'], 
                                      capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    # Parse xwininfo output (simplified)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '"' in line and 'x' in line:
                            # This is a very basic parser
                            window = Window(
                                id="unknown",
                                title=line.split('"')[1] if '"' in line else "Unknown",
                                class_name="unknown",
                                workspace=1,
                                geometry={"x": 0, "y": 0, "width": 800, "height": 600},
                                focused=False
                            )
                            windows.append(window)
            
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("xwininfo also not available")
        
        return windows
    
    def _get_wayland_windows(self) -> List[Window]:
        """Get windows using Wayland tools (very limited)"""
        windows = []
        
        # Wayland doesn't provide easy window enumeration
        # This is a placeholder that could be extended with compositor-specific tools
        logger.info("Wayland window enumeration not implemented in fallback adapter")
        
        return windows
    
    def _get_window_geometry_x11(self, window_id: str) -> Dict[str, int]:
        """Get window geometry using xwininfo"""
        try:
            result = subprocess.run(['xwininfo', '-id', window_id], 
                                  capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                geometry = {"x": 0, "y": 0, "width": 800, "height": 600}
                
                for line in result.stdout.split('\n'):
                    if 'Absolute upper-left X:' in line:
                        geometry['x'] = int(line.split(':')[1].strip())
                    elif 'Absolute upper-left Y:' in line:
                        geometry['y'] = int(line.split(':')[1].strip())
                    elif 'Width:' in line:
                        geometry['width'] = int(line.split(':')[1].strip())
                    elif 'Height:' in line:
                        geometry['height'] = int(line.split(':')[1].strip())
                
                return geometry
        
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
        
        return {"x": 0, "y": 0, "width": 800, "height": 600}
    
    def switch_workspace(self, workspace_id: Union[int, str]) -> bool:
        """Switch workspace (not supported in fallback)"""
        logger.warning("Workspace switching not supported in fallback adapter")
        return False
    
    def focus_window(self, window_id: Union[int, str]) -> bool:
        """Focus window using generic tools"""
        try:
            if self.display_server == 'x11':
                # Try using wmctrl
                result = subprocess.run(['wmctrl', '-i', '-a', str(window_id)], 
                                      capture_output=True, text=True, timeout=2)
                return result.returncode == 0
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("wmctrl not available for window focusing")
        
        return False
    
    def close_window(self, window_id: Union[int, str]) -> bool:
        """Close window using generic tools"""
        try:
            if self.display_server == 'x11':
                # Try using wmctrl
                result = subprocess.run(['wmctrl', '-i', '-c', str(window_id)], 
                                      capture_output=True, text=True, timeout=2)
                return result.returncode == 0
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("wmctrl not available for window closing")
        
        return False
    
    def move_window(self, window_id: Union[int, str], x: int, y: int) -> bool:
        """Move window (not supported in fallback)"""
        logger.warning("Window moving not supported in fallback adapter")
        return False
    
    def resize_window(self, window_id: Union[int, str], width: int, height: int) -> bool:
        """Resize window (not supported in fallback)"""
        logger.warning("Window resizing not supported in fallback adapter")
        return False
    
    def get_monitors(self) -> List[Monitor]:
        """Get monitors using generic tools"""
        monitors = []
        
        try:
            if self.display_server == 'x11':
                monitors = self._get_x11_monitors()
            elif self.display_server == 'wayland':
                monitors = self._get_wayland_monitors()
        except Exception as e:
            logger.warning(f"Failed to get monitors: {e}")
        
        # Fallback to single monitor
        if not monitors:
            monitors = [Monitor(
                id=0,
                name="Unknown",
                width=1920,
                height=1080,
                x=0,
                y=0,
                active=True,
                primary=True
            )]
        
        return monitors
    
    def _get_x11_monitors(self) -> List[Monitor]:
        """Get monitors using X11 tools"""
        monitors = []
        
        try:
            # Try xrandr
            result = subprocess.run(['xrandr', '--query'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ' connected' in line:
                        parts = line.split()
                        name = parts[0]
                        
                        # Parse geometry (e.g., "1920x1080+0+0")
                        geometry_str = None
                        for part in parts:
                            if 'x' in part and '+' in part:
                                geometry_str = part
                                break
                        
                        if geometry_str:
                            try:
                                # Parse "1920x1080+0+0"
                                size_part, pos_part = geometry_str.split('+', 1)
                                width, height = map(int, size_part.split('x'))
                                x, y = map(int, pos_part.split('+'))
                                
                                monitor = Monitor(
                                    id=len(monitors),
                                    name=name,
                                    width=width,
                                    height=height,
                                    x=x,
                                    y=y,
                                    active=True,
                                    primary='primary' in line
                                )
                                monitors.append(monitor)
                            
                            except ValueError:
                                continue
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("xrandr not available")
        
        return monitors
    
    def _get_wayland_monitors(self) -> List[Monitor]:
        """Get monitors using Wayland tools"""
        monitors = []
        
        # Try wlr-randr if available (works with wlroots-based compositors)
        try:
            result = subprocess.run(['wlr-randr'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse wlr-randr output (simplified)
                lines = result.stdout.split('\n')
                current_monitor = None
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith(' '):
                        # New monitor
                        current_monitor = {
                            'name': line.split()[0],
                            'width': 1920,
                            'height': 1080,
                            'x': 0,
                            'y': 0
                        }
                    elif 'current' in line and current_monitor:
                        # Parse current resolution
                        try:
                            parts = line.split()
                            for part in parts:
                                if 'x' in part:
                                    width, height = map(int, part.split('x'))
                                    current_monitor['width'] = width
                                    current_monitor['height'] = height
                                    break
                            
                            monitor = Monitor(
                                id=len(monitors),
                                name=current_monitor['name'],
                                width=current_monitor['width'],
                                height=current_monitor['height'],
                                x=current_monitor['x'],
                                y=current_monitor['y'],
                                active=True,
                                primary=len(monitors) == 0
                            )
                            monitors.append(monitor)
                        
                        except ValueError:
                            continue
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.debug("wlr-randr not available")
        
        return monitors