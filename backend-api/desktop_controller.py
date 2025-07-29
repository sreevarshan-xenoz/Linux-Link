"""
Linux-Link Desktop Controller

Provides desktop environment integration with window manager detection
and control capabilities for various Linux desktop environments.
"""

import os
import subprocess
import json
import logging
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class WindowManagerType(Enum):
    HYPRLAND = "hyprland"
    I3 = "i3"
    SWAY = "sway"
    GNOME = "gnome"
    KDE = "kde"
    XFCE = "xfce"
    BSPWM = "bspwm"
    AWESOME = "awesome"
    OPENBOX = "openbox"
    UNKNOWN = "unknown"


@dataclass
class Workspace:
    """Represents a workspace/desktop"""
    id: Union[int, str]
    name: str
    active: bool
    windows: List['Window']
    monitor: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['windows'] = [window.to_dict() for window in self.windows]
        return data


@dataclass
class Window:
    """Represents a window"""
    id: Union[int, str]
    title: str
    class_name: str
    workspace: Union[int, str]
    geometry: Dict[str, int]
    focused: bool
    floating: bool = False
    fullscreen: bool = False
    minimized: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class Monitor:
    """Represents a monitor/display"""
    id: Union[int, str]
    name: str
    width: int
    height: int
    x: int
    y: int
    active: bool
    primary: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class DesktopControllerError(Exception):
    """Base exception for desktop controller operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class WindowManagerAdapter(ABC):
    """Abstract base class for window manager adapters"""
    
    @abstractmethod
    def get_workspaces(self) -> List[Workspace]:
        """Get list of workspaces"""
        pass
    
    @abstractmethod
    def get_windows(self) -> List[Window]:
        """Get list of windows"""
        pass
    
    @abstractmethod
    def switch_workspace(self, workspace_id: Union[int, str]) -> bool:
        """Switch to specified workspace"""
        pass
    
    @abstractmethod
    def focus_window(self, window_id: Union[int, str]) -> bool:
        """Focus specified window"""
        pass
    
    @abstractmethod
    def close_window(self, window_id: Union[int, str]) -> bool:
        """Close specified window"""
        pass
    
    @abstractmethod
    def move_window(self, window_id: Union[int, str], x: int, y: int) -> bool:
        """Move window to specified position"""
        pass
    
    @abstractmethod
    def resize_window(self, window_id: Union[int, str], width: int, height: int) -> bool:
        """Resize window to specified dimensions"""
        pass
    
    @abstractmethod
    def get_monitors(self) -> List[Monitor]:
        """Get list of monitors"""
        pass


class WindowManagerDetector:
    """Detects the current window manager and desktop environment"""
    
    def __init__(self):
        self.detection_methods = [
            self._detect_by_process,
            self._detect_by_environment,
            self._detect_by_socket,
            self._detect_by_command
        ]
    
    def detect_window_manager(self) -> WindowManagerType:
        """
        Detect the current window manager using multiple methods.
        
        Returns:
            WindowManagerType enum value
        """
        logger.info("Starting window manager detection...")
        
        for method in self.detection_methods:
            try:
                wm_type = method()
                if wm_type != WindowManagerType.UNKNOWN:
                    logger.info(f"Window manager detected: {wm_type.value}")
                    return wm_type
            except Exception as e:
                logger.debug(f"Detection method failed: {e}")
                continue
        
        logger.warning("Could not detect window manager, defaulting to UNKNOWN")
        return WindowManagerType.UNKNOWN
    
    def _detect_by_process(self) -> WindowManagerType:
        """Detect by running processes"""
        try:
            # Get list of running processes
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                return WindowManagerType.UNKNOWN
            
            processes = result.stdout.lower()
            
            # Check for specific window manager processes
            if 'hyprland' in processes:
                return WindowManagerType.HYPRLAND
            elif 'i3' in processes and 'sway' not in processes:
                return WindowManagerType.I3
            elif 'sway' in processes:
                return WindowManagerType.SWAY
            elif 'gnome-shell' in processes:
                return WindowManagerType.GNOME
            elif 'kwin' in processes or 'plasmashell' in processes:
                return WindowManagerType.KDE
            elif 'xfwm4' in processes:
                return WindowManagerType.XFCE
            elif 'bspwm' in processes:
                return WindowManagerType.BSPWM
            elif 'awesome' in processes:
                return WindowManagerType.AWESOME
            elif 'openbox' in processes:
                return WindowManagerType.OPENBOX
            
            return WindowManagerType.UNKNOWN
        
        except Exception as e:
            logger.debug(f"Process detection failed: {e}")
            return WindowManagerType.UNKNOWN
    
    def _detect_by_environment(self) -> WindowManagerType:
        """Detect by environment variables"""
        try:
            # Check common environment variables
            desktop_session = os.getenv('DESKTOP_SESSION', '').lower()
            xdg_current_desktop = os.getenv('XDG_CURRENT_DESKTOP', '').lower()
            wayland_display = os.getenv('WAYLAND_DISPLAY', '')
            
            # Hyprland detection
            if 'hyprland' in desktop_session or os.getenv('HYPRLAND_INSTANCE_SIGNATURE'):
                return WindowManagerType.HYPRLAND
            
            # Sway detection
            if 'sway' in desktop_session or os.getenv('SWAYSOCK'):
                return WindowManagerType.SWAY
            
            # i3 detection
            if 'i3' in desktop_session or os.getenv('I3SOCK'):
                return WindowManagerType.I3
            
            # GNOME detection
            if 'gnome' in xdg_current_desktop or 'gnome' in desktop_session:
                return WindowManagerType.GNOME
            
            # KDE detection
            if 'kde' in xdg_current_desktop or 'plasma' in desktop_session:
                return WindowManagerType.KDE
            
            # XFCE detection
            if 'xfce' in xdg_current_desktop or 'xfce' in desktop_session:
                return WindowManagerType.XFCE
            
            return WindowManagerType.UNKNOWN
        
        except Exception as e:
            logger.debug(f"Environment detection failed: {e}")
            return WindowManagerType.UNKNOWN
    
    def _detect_by_socket(self) -> WindowManagerType:
        """Detect by checking for window manager sockets"""
        try:
            # Check for Hyprland socket
            hyprland_signature = os.getenv('HYPRLAND_INSTANCE_SIGNATURE')
            if hyprland_signature:
                socket_path = f"/tmp/hypr/{hyprland_signature}/.socket.sock"
                if os.path.exists(socket_path):
                    return WindowManagerType.HYPRLAND
            
            # Check for Sway socket
            sway_sock = os.getenv('SWAYSOCK')
            if sway_sock and os.path.exists(sway_sock):
                return WindowManagerType.SWAY
            
            # Check for i3 socket
            i3_sock = os.getenv('I3SOCK')
            if i3_sock and os.path.exists(i3_sock):
                return WindowManagerType.I3
            
            # Check common socket locations
            socket_paths = [
                '/tmp/hypr/*/hyprland.sock',
                '/run/user/*/sway-ipc.*.sock',
                '/run/user/*/i3/ipc-socket.*'
            ]
            
            import glob
            for pattern in socket_paths:
                matches = glob.glob(pattern)
                if matches:
                    if 'hypr' in pattern:
                        return WindowManagerType.HYPRLAND
                    elif 'sway' in pattern:
                        return WindowManagerType.SWAY
                    elif 'i3' in pattern:
                        return WindowManagerType.I3
            
            return WindowManagerType.UNKNOWN
        
        except Exception as e:
            logger.debug(f"Socket detection failed: {e}")
            return WindowManagerType.UNKNOWN
    
    def _detect_by_command(self) -> WindowManagerType:
        """Detect by trying window manager specific commands"""
        try:
            # Try Hyprland command
            try:
                result = subprocess.run(['hyprctl', 'version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'hyprland' in result.stdout.lower():
                    return WindowManagerType.HYPRLAND
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Try i3 command
            try:
                result = subprocess.run(['i3-msg', '-t', 'get_version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return WindowManagerType.I3
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Try Sway command
            try:
                result = subprocess.run(['swaymsg', '-t', 'get_version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return WindowManagerType.SWAY
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            # Try GNOME command
            try:
                result = subprocess.run(['gnome-shell', '--version'], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0 and 'gnome' in result.stdout.lower():
                    return WindowManagerType.GNOME
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
            
            return WindowManagerType.UNKNOWN
        
        except Exception as e:
            logger.debug(f"Command detection failed: {e}")
            return WindowManagerType.UNKNOWN
    
    def get_detection_info(self) -> Dict[str, Any]:
        """
        Get detailed information about the detection process.
        
        Returns:
            Dictionary with detection details
        """
        info = {
            "detected_wm": self.detect_window_manager().value,
            "environment_vars": {
                "DESKTOP_SESSION": os.getenv('DESKTOP_SESSION'),
                "XDG_CURRENT_DESKTOP": os.getenv('XDG_CURRENT_DESKTOP'),
                "WAYLAND_DISPLAY": os.getenv('WAYLAND_DISPLAY'),
                "DISPLAY": os.getenv('DISPLAY'),
                "HYPRLAND_INSTANCE_SIGNATURE": os.getenv('HYPRLAND_INSTANCE_SIGNATURE'),
                "SWAYSOCK": os.getenv('SWAYSOCK'),
                "I3SOCK": os.getenv('I3SOCK')
            },
            "available_commands": {},
            "running_processes": []
        }
        
        # Check available commands
        commands_to_check = [
            'hyprctl', 'i3-msg', 'swaymsg', 'gnome-shell', 
            'kwin_x11', 'xfwm4', 'bspwm', 'awesome', 'openbox'
        ]
        
        for cmd in commands_to_check:
            try:
                result = subprocess.run(['which', cmd], 
                                      capture_output=True, text=True, timeout=1)
                info["available_commands"][cmd] = result.returncode == 0
            except:
                info["available_commands"][cmd] = False
        
        # Get relevant running processes
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                processes = result.stdout.lower()
                wm_processes = [
                    'hyprland', 'i3', 'sway', 'gnome-shell', 'kwin', 
                    'plasmashell', 'xfwm4', 'bspwm', 'awesome', 'openbox'
                ]
                
                for process in wm_processes:
                    if process in processes:
                        info["running_processes"].append(process)
        except:
            pass
        
        return info


class DesktopController:
    """Main desktop controller that manages window manager adapters"""
    
    def __init__(self):
        self.detector = WindowManagerDetector()
        self.wm_type = None
        self.adapter = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the desktop controller with appropriate adapter"""
        self.wm_type = self.detector.detect_window_manager()
        self.adapter = self._get_adapter()
        
        if self.adapter:
            logger.info(f"Desktop controller initialized for {self.wm_type.value}")
        else:
            logger.warning(f"No adapter available for {self.wm_type.value}")
    
    def _get_adapter(self) -> Optional[WindowManagerAdapter]:
        """Get appropriate adapter for detected window manager"""
        # Import adapters here to avoid circular imports
        try:
            if self.wm_type == WindowManagerType.HYPRLAND:
                try:
                    from adapters.hyprland_adapter import HyprlandAdapter
                    return HyprlandAdapter()
                except ImportError:
                    logger.info("Hyprland adapter not available, using fallback")
            elif self.wm_type == WindowManagerType.I3:
                try:
                    from adapters.i3_adapter import I3Adapter
                    return I3Adapter()
                except ImportError:
                    logger.info("i3 adapter not available, using fallback")
            elif self.wm_type == WindowManagerType.SWAY:
                try:
                    from adapters.sway_adapter import SwayAdapter
                    return SwayAdapter()
                except ImportError:
                    logger.info("Sway adapter not available, using fallback")
            elif self.wm_type == WindowManagerType.GNOME:
                try:
                    from adapters.gnome_adapter import GnomeAdapter
                    return GnomeAdapter()
                except ImportError:
                    logger.info("GNOME adapter not available, using fallback")
            elif self.wm_type == WindowManagerType.KDE:
                try:
                    from adapters.kde_adapter import KdeAdapter
                    return KdeAdapter()
                except ImportError:
                    logger.info("KDE adapter not available, using fallback")
            
            # Always fall back to the fallback adapter
            from adapters.fallback_adapter import FallbackAdapter
            return FallbackAdapter()
            
        except ImportError as e:
            logger.warning(f"Could not import fallback adapter: {e}")
            return None
    
    def is_supported(self) -> bool:
        """Check if current window manager is supported"""
        return self.adapter is not None
    
    def get_window_manager_info(self) -> Dict[str, Any]:
        """Get information about the current window manager"""
        return {
            "type": self.wm_type.value,
            "supported": self.is_supported(),
            "detection_info": self.detector.get_detection_info()
        }
    
    def get_workspaces(self) -> List[Workspace]:
        """Get list of workspaces"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.get_workspaces()
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to get workspaces: {str(e)}",
                "GET_WORKSPACES_FAILED",
                {"wm_type": self.wm_type.value, "error": str(e)}
            )
    
    def get_windows(self) -> List[Window]:
        """Get list of windows"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.get_windows()
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to get windows: {str(e)}",
                "GET_WINDOWS_FAILED",
                {"wm_type": self.wm_type.value, "error": str(e)}
            )
    
    def switch_workspace(self, workspace_id: Union[int, str]) -> bool:
        """Switch to specified workspace"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.switch_workspace(workspace_id)
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to switch workspace: {str(e)}",
                "SWITCH_WORKSPACE_FAILED",
                {"wm_type": self.wm_type.value, "workspace_id": workspace_id, "error": str(e)}
            )
    
    def focus_window(self, window_id: Union[int, str]) -> bool:
        """Focus specified window"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.focus_window(window_id)
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to focus window: {str(e)}",
                "FOCUS_WINDOW_FAILED",
                {"wm_type": self.wm_type.value, "window_id": window_id, "error": str(e)}
            )
    
    def close_window(self, window_id: Union[int, str]) -> bool:
        """Close specified window"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.close_window(window_id)
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to close window: {str(e)}",
                "CLOSE_WINDOW_FAILED",
                {"wm_type": self.wm_type.value, "window_id": window_id, "error": str(e)}
            )
    
    def get_monitors(self) -> List[Monitor]:
        """Get list of monitors"""
        if not self.adapter:
            raise DesktopControllerError(
                "Window manager not supported",
                "WM_NOT_SUPPORTED",
                {"wm_type": self.wm_type.value}
            )
        
        try:
            return self.adapter.get_monitors()
        except Exception as e:
            raise DesktopControllerError(
                f"Failed to get monitors: {str(e)}",
                "GET_MONITORS_FAILED",
                {"wm_type": self.wm_type.value, "error": str(e)}
            )


# Global desktop controller instance
_desktop_controller = None


def get_desktop_controller() -> DesktopController:
    """
    Get global desktop controller instance.
    
    Returns:
        DesktopController instance
    """
    global _desktop_controller
    if _desktop_controller is None:
        _desktop_controller = DesktopController()
    
    return _desktop_controller


def reinitialize_desktop_controller():
    """Reinitialize desktop controller (useful for testing or WM changes)"""
    global _desktop_controller
    _desktop_controller = None
    return get_desktop_controller()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    controller = get_desktop_controller()
    
    print(f"Window Manager: {controller.wm_type.value}")
    print(f"Supported: {controller.is_supported()}")
    
    info = controller.get_window_manager_info()
    print(f"Detection Info: {json.dumps(info, indent=2)}")
    
    if controller.is_supported():
        try:
            workspaces = controller.get_workspaces()
            print(f"Workspaces: {len(workspaces)}")
            
            windows = controller.get_windows()
            print(f"Windows: {len(windows)}")
        except Exception as e:
            print(f"Error: {e}")