"""
Linux-Link Voice Processor

Provides natural language command processing and voice command execution
for hands-free system control and automation.
"""

import os
import re
import json
import logging
import subprocess
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import time

logger = logging.getLogger(__name__)


class CommandType(Enum):
    SYSTEM = "system"
    MEDIA = "media"
    DESKTOP = "desktop"
    FILE = "file"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class VoiceCommand:
    """Represents a voice command definition"""
    trigger: str
    command_type: CommandType
    actions: List[str]
    description: str
    parameters: Dict[str, Any] = None
    confidence_threshold: float = 0.7
    custom: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['command_type'] = self.command_type.value
        return data


@dataclass
class CommandResult:
    """Represents the result of command execution"""
    success: bool
    command: str
    command_type: CommandType
    actions_executed: List[str]
    message: str
    confidence: float = 1.0
    execution_time: float = 0.0
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['command_type'] = self.command_type.value
        return data


class VoiceProcessorError(Exception):
    """Base exception for voice processor operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class NaturalLanguageParser:
    """Parser for natural language voice commands"""
    
    def __init__(self):
        self.patterns = self._load_command_patterns()
        logger.info("Natural language parser initialized")
    
    def _load_command_patterns(self) -> Dict[str, List[Dict]]:
        """Load command patterns for natural language processing"""
        return {
            'media': [
                {
                    'patterns': [r'play\s+music', r'start\s+music', r'play\s+audio'],
                    'action': 'media_play',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'pause\s+music', r'stop\s+music', r'pause\s+audio'],
                    'action': 'media_pause',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'next\s+song', r'next\s+track', r'skip\s+song'],
                    'action': 'media_next',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'previous\s+song', r'previous\s+track', r'back\s+song'],
                    'action': 'media_previous',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'volume\s+up', r'increase\s+volume', r'louder'],
                    'action': 'volume_up',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'volume\s+down', r'decrease\s+volume', r'quieter'],
                    'action': 'volume_down',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'mute', r'silence'],
                    'action': 'volume_mute',
                    'confidence': 0.9
                }
            ],
            'desktop': [
                {
                    'patterns': [r'switch\s+to\s+workspace\s+(\d+)', r'go\s+to\s+workspace\s+(\d+)'],
                    'action': 'switch_workspace',
                    'confidence': 0.9,
                    'parameters': ['workspace_id']
                },
                {
                    'patterns': [r'open\s+terminal', r'launch\s+terminal'],
                    'action': 'open_terminal',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'close\s+window', r'close\s+current\s+window'],
                    'action': 'close_window',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'minimize\s+window', r'hide\s+window'],
                    'action': 'minimize_window',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'maximize\s+window', r'fullscreen'],
                    'action': 'maximize_window',
                    'confidence': 0.8
                }
            ],
            'system': [
                {
                    'patterns': [r'lock\s+screen', r'lock\s+computer'],
                    'action': 'lock_screen',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'shutdown', r'power\s+off'],
                    'action': 'shutdown',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'restart', r'reboot'],
                    'action': 'restart',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'sleep', r'suspend'],
                    'action': 'sleep',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'what\s+time\s+is\s+it', r'current\s+time'],
                    'action': 'get_time',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'system\s+status', r'system\s+info'],
                    'action': 'system_status',
                    'confidence': 0.8
                }
            ],
            'file': [
                {
                    'patterns': [r'open\s+file\s+manager', r'open\s+files'],
                    'action': 'open_file_manager',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'open\s+(.+)', r'launch\s+(.+)'],
                    'action': 'open_application',
                    'confidence': 0.7,
                    'parameters': ['application']
                }
            ],
            'navigation': [
                {
                    'patterns': [r'go\s+back', r'navigate\s+back'],
                    'action': 'navigate_back',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'go\s+forward', r'navigate\s+forward'],
                    'action': 'navigate_forward',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'refresh\s+page', r'reload\s+page'],
                    'action': 'refresh_page',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'scroll\s+up'],
                    'action': 'scroll_up',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'scroll\s+down'],
                    'action': 'scroll_down',
                    'confidence': 0.8
                }
            ],
            'communication': [
                {
                    'patterns': [r'open\s+email', r'launch\s+mail'],
                    'action': 'open_email',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'open\s+browser', r'launch\s+browser'],
                    'action': 'open_browser',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'open\s+chat', r'launch\s+messenger'],
                    'action': 'open_chat',
                    'confidence': 0.8
                }
            ],
            'productivity': [
                {
                    'patterns': [r'open\s+calculator', r'launch\s+calculator'],
                    'action': 'open_calculator',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'open\s+text\s+editor', r'launch\s+editor'],
                    'action': 'open_text_editor',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'take\s+screenshot', r'capture\s+screen'],
                    'action': 'take_screenshot',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'open\s+calendar', r'show\s+calendar'],
                    'action': 'open_calendar',
                    'confidence': 0.8
                }
            ],
            'shortcuts': [
                {
                    'patterns': [r'copy\s+text', r'copy\s+selection'],
                    'action': 'copy_text',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'paste\s+text', r'paste\s+clipboard'],
                    'action': 'paste_text',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'select\s+all'],
                    'action': 'select_all',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'undo\s+action', r'undo\s+last'],
                    'action': 'undo',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'redo\s+action', r'redo\s+last'],
                    'action': 'redo',
                    'confidence': 0.8
                }
            ],
            'quick_actions': [
                {
                    'patterns': [r'show\s+desktop', r'minimize\s+all'],
                    'action': 'show_desktop',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'switch\s+application', r'alt\s+tab'],
                    'action': 'switch_application',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'open\s+run\s+dialog', r'show\s+launcher'],
                    'action': 'open_launcher',
                    'confidence': 0.8
                },
                {
                    'patterns': [r'show\s+notifications'],
                    'action': 'show_notifications',
                    'confidence': 0.8
                }
            ],
            'help': [
                {
                    'patterns': [r'help', r'what\s+can\s+you\s+do', r'list\s+commands'],
                    'action': 'show_help',
                    'confidence': 0.9
                },
                {
                    'patterns': [r'repeat\s+last\s+command'],
                    'action': 'repeat_command',
                    'confidence': 0.8
                }
            ]
        }
    
    def parse_command(self, text: str) -> Dict[str, Any]:
        """
        Parse natural language text into command structure.
        
        Args:
            text: Natural language command text
            
        Returns:
            Dictionary with parsed command information
        """
        text = text.lower().strip()
        best_match = None
        best_confidence = 0.0
        
        for category, patterns in self.patterns.items():
            for pattern_info in patterns:
                for pattern in pattern_info['patterns']:
                    match = re.search(pattern, text)
                    if match:
                        confidence = pattern_info['confidence']
                        
                        # Adjust confidence based on exact match
                        if text == match.group(0):
                            confidence += 0.1
                        
                        if confidence > best_confidence:
                            best_confidence = confidence
                            best_match = {
                                'category': category,
                                'action': pattern_info['action'],
                                'confidence': confidence,
                                'parameters': {},
                                'raw_text': text
                            }
                            
                            # Extract parameters if defined
                            if 'parameters' in pattern_info and match.groups():
                                for i, param_name in enumerate(pattern_info['parameters']):
                                    if i < len(match.groups()):
                                        best_match['parameters'][param_name] = match.group(i + 1)
        
        if best_match:
            return best_match
        else:
            return {
                'category': 'unknown',
                'action': 'unknown',
                'confidence': 0.0,
                'parameters': {},
                'raw_text': text
            }
    
    def get_suggestions(self, partial_text: str, limit: int = 5) -> List[str]:
        """Get command suggestions based on partial text"""
        suggestions = []
        partial_text = partial_text.lower().strip()
        
        for category, patterns in self.patterns.items():
            for pattern_info in patterns:
                for pattern in pattern_info['patterns']:
                    # Convert regex pattern to readable suggestion
                    readable = pattern.replace(r'\s+', ' ').replace(r'\d+', '[number]')
                    readable = re.sub(r'[()\\]', '', readable)
                    
                    if partial_text in readable or readable.startswith(partial_text):
                        suggestions.append(readable)
                        
                        if len(suggestions) >= limit:
                            return suggestions
        
        return suggestions


class CommandExecutor:
    """Executes parsed voice commands"""
    
    def __init__(self):
        self.command_handlers = self._setup_command_handlers()
        logger.info("Command executor initialized")
    
    def _setup_command_handlers(self) -> Dict[str, Callable]:
        """Setup command handler functions"""
        return {
            # Media commands
            'media_play': self._handle_media_play,
            'media_pause': self._handle_media_pause,
            'media_next': self._handle_media_next,
            'media_previous': self._handle_media_previous,
            'volume_up': self._handle_volume_up,
            'volume_down': self._handle_volume_down,
            'volume_mute': self._handle_volume_mute,
            
            # Desktop commands
            'switch_workspace': self._handle_switch_workspace,
            'open_terminal': self._handle_open_terminal,
            'close_window': self._handle_close_window,
            'minimize_window': self._handle_minimize_window,
            'maximize_window': self._handle_maximize_window,
            
            # System commands
            'lock_screen': self._handle_lock_screen,
            'shutdown': self._handle_shutdown,
            'restart': self._handle_restart,
            'sleep': self._handle_sleep,
            'get_time': self._handle_get_time,
            'system_status': self._handle_system_status,
            
            # File commands
            'open_file_manager': self._handle_open_file_manager,
            'open_application': self._handle_open_application,
            
            # Navigation commands
            'navigate_back': self._handle_navigate_back,
            'navigate_forward': self._handle_navigate_forward,
            'refresh_page': self._handle_refresh_page,
            'scroll_up': self._handle_scroll_up,
            'scroll_down': self._handle_scroll_down,
            
            # Communication commands
            'open_email': self._handle_open_email,
            'open_browser': self._handle_open_browser,
            'open_chat': self._handle_open_chat,
            
            # Productivity commands
            'open_calculator': self._handle_open_calculator,
            'open_text_editor': self._handle_open_text_editor,
            'take_screenshot': self._handle_take_screenshot,
            'open_calendar': self._handle_open_calendar,
            
            # Shortcut commands
            'copy_text': self._handle_copy_text,
            'paste_text': self._handle_paste_text,
            'select_all': self._handle_select_all,
            'undo': self._handle_undo,
            'redo': self._handle_redo,
            
            # Quick action commands
            'show_desktop': self._handle_show_desktop,
            'switch_application': self._handle_switch_application,
            'open_launcher': self._handle_open_launcher,
            'show_notifications': self._handle_show_notifications,
            
            # Help commands
            'show_help': self._handle_show_help,
            'repeat_command': self._handle_repeat_command
        }
    
    def execute_command(self, parsed_command: Dict[str, Any]) -> CommandResult:
        """Execute a parsed command"""
        start_time = time.time()
        action = parsed_command.get('action', 'unknown')
        
        try:
            if action in self.command_handlers:
                handler = self.command_handlers[action]
                result = handler(parsed_command)
                
                execution_time = time.time() - start_time
                result.execution_time = execution_time
                
                logger.info(f"Command executed: {action} (success: {result.success}, time: {execution_time:.2f}s)")
                return result
            else:
                return CommandResult(
                    success=False,
                    command=parsed_command.get('raw_text', ''),
                    command_type=CommandType.UNKNOWN,
                    actions_executed=[],
                    message=f"Unknown command: {action}",
                    confidence=parsed_command.get('confidence', 0.0),
                    execution_time=time.time() - start_time
                )
        
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return CommandResult(
                success=False,
                command=parsed_command.get('raw_text', ''),
                command_type=CommandType.UNKNOWN,
                actions_executed=[],
                message=f"Command execution failed: {str(e)}",
                confidence=parsed_command.get('confidence', 0.0),
                execution_time=time.time() - start_time
            )
    
    # Media command handlers
    def _handle_media_play(self, parsed_command: Dict) -> CommandResult:
        """Handle media play command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            success = mc.play()
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['media_play'],
                message="Started media playback" if success else "Failed to start playback",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_media_pause(self, parsed_command: Dict) -> CommandResult:
        """Handle media pause command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            success = mc.pause()
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['media_pause'],
                message="Paused media playback" if success else "Failed to pause playback",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_media_next(self, parsed_command: Dict) -> CommandResult:
        """Handle media next command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            success = mc.next_track()
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['media_next'],
                message="Skipped to next track" if success else "Failed to skip track",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_media_previous(self, parsed_command: Dict) -> CommandResult:
        """Handle media previous command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            success = mc.previous_track()
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['media_previous'],
                message="Skipped to previous track" if success else "Failed to skip track",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_volume_up(self, parsed_command: Dict) -> CommandResult:
        """Handle volume up command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            current_volume = mc.get_system_volume()
            new_volume = min(1.0, current_volume + 0.1)
            success = mc.set_system_volume(new_volume)
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['volume_up'],
                message=f"Volume increased to {int(new_volume * 100)}%" if success else "Failed to increase volume",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_volume_down(self, parsed_command: Dict) -> CommandResult:
        """Handle volume down command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            current_volume = mc.get_system_volume()
            new_volume = max(0.0, current_volume - 0.1)
            success = mc.set_system_volume(new_volume)
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['volume_down'],
                message=f"Volume decreased to {int(new_volume * 100)}%" if success else "Failed to decrease volume",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_volume_mute(self, parsed_command: Dict) -> CommandResult:
        """Handle volume mute command"""
        try:
            from media_controller import get_media_controller
            mc = get_media_controller()
            success = mc.toggle_system_mute()
            muted = mc.is_system_muted()
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.MEDIA,
                actions_executed=['volume_mute'],
                message=f"Audio {'muted' if muted else 'unmuted'}" if success else "Failed to toggle mute",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Desktop command handlers
    def _handle_switch_workspace(self, parsed_command: Dict) -> CommandResult:
        """Handle switch workspace command"""
        try:
            from desktop_controller import get_desktop_controller
            dc = get_desktop_controller()
            workspace_id = parsed_command['parameters'].get('workspace_id', '1')
            success = dc.switch_workspace(workspace_id)
            
            return CommandResult(
                success=success,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=['switch_workspace'],
                message=f"Switched to workspace {workspace_id}" if success else f"Failed to switch to workspace {workspace_id}",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_terminal(self, parsed_command: Dict) -> CommandResult:
        """Handle open terminal command"""
        try:
            # Try common terminal emulators
            terminals = ['gnome-terminal', 'konsole', 'xfce4-terminal', 'alacritty', 'kitty', 'xterm']
            
            for terminal in terminals:
                try:
                    subprocess.Popen([terminal], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.DESKTOP,
                        actions_executed=['open_terminal'],
                        message=f"Opened terminal ({terminal})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=[],
                message="No terminal emulator found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_close_window(self, parsed_command: Dict) -> CommandResult:
        """Handle close window command"""
        try:
            from desktop_controller import get_desktop_controller
            dc = get_desktop_controller()
            
            # Get active window and close it
            windows = dc.get_windows()
            active_window = next((w for w in windows if w.focused), None)
            
            if active_window:
                success = dc.close_window(active_window.id)
                return CommandResult(
                    success=success,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.DESKTOP,
                    actions_executed=['close_window'],
                    message=f"Closed window: {active_window.title}" if success else "Failed to close window",
                    confidence=parsed_command['confidence']
                )
            else:
                return CommandResult(
                    success=False,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.DESKTOP,
                    actions_executed=[],
                    message="No active window found",
                    confidence=parsed_command['confidence']
                )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_minimize_window(self, parsed_command: Dict) -> CommandResult:
        """Handle minimize window command"""
        # This is a placeholder - actual implementation would depend on window manager
        return CommandResult(
            success=False,
            command=parsed_command['raw_text'],
            command_type=CommandType.DESKTOP,
            actions_executed=[],
            message="Window minimize not implemented",
            confidence=parsed_command['confidence']
        )
    
    def _handle_maximize_window(self, parsed_command: Dict) -> CommandResult:
        """Handle maximize window command"""
        try:
            from desktop_controller import get_desktop_controller
            dc = get_desktop_controller()
            
            # Try to toggle fullscreen for active window
            if hasattr(dc.adapter, 'toggle_fullscreen'):
                success = dc.adapter.toggle_fullscreen()
                return CommandResult(
                    success=success,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.DESKTOP,
                    actions_executed=['maximize_window'],
                    message="Toggled window fullscreen" if success else "Failed to toggle fullscreen",
                    confidence=parsed_command['confidence']
                )
            else:
                return CommandResult(
                    success=False,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.DESKTOP,
                    actions_executed=[],
                    message="Fullscreen toggle not supported",
                    confidence=parsed_command['confidence']
                )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # System command handlers
    def _handle_lock_screen(self, parsed_command: Dict) -> CommandResult:
        """Handle lock screen command"""
        try:
            # Try common screen lockers
            lockers = ['loginctl lock-session', 'gnome-screensaver-command -l', 'xscreensaver-command -lock']
            
            for locker in lockers:
                try:
                    subprocess.run(locker.split(), check=True, timeout=5)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.SYSTEM,
                        actions_executed=['lock_screen'],
                        message="Screen locked",
                        confidence=parsed_command['confidence']
                    )
                except (subprocess.CalledProcessError, FileNotFoundError):
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="No screen locker found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_shutdown(self, parsed_command: Dict) -> CommandResult:
        """Handle shutdown command"""
        return CommandResult(
            success=False,
            command=parsed_command['raw_text'],
            command_type=CommandType.SYSTEM,
            actions_executed=[],
            message="Shutdown command disabled for safety",
            confidence=parsed_command['confidence']
        )
    
    def _handle_restart(self, parsed_command: Dict) -> CommandResult:
        """Handle restart command"""
        return CommandResult(
            success=False,
            command=parsed_command['raw_text'],
            command_type=CommandType.SYSTEM,
            actions_executed=[],
            message="Restart command disabled for safety",
            confidence=parsed_command['confidence']
        )
    
    def _handle_sleep(self, parsed_command: Dict) -> CommandResult:
        """Handle sleep command"""
        try:
            subprocess.run(['systemctl', 'suspend'], check=True, timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['sleep'],
                message="System suspended",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_get_time(self, parsed_command: Dict) -> CommandResult:
        """Handle get time command"""
        try:
            import datetime
            current_time = datetime.datetime.now().strftime("%I:%M %p")
            
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['get_time'],
                message=f"Current time is {current_time}",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_system_status(self, parsed_command: Dict) -> CommandResult:
        """Handle system status command"""
        try:
            from monitoring import monitor
            stats = monitor.get_stats()
            
            cpu_percent = stats.get('cpu', {}).get('percent', [0])[0]
            memory_percent = stats.get('memory', {}).get('percent', 0)
            
            message = f"CPU: {cpu_percent}%, Memory: {memory_percent}%"
            
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['system_status'],
                message=message,
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # File command handlers
    def _handle_open_file_manager(self, parsed_command: Dict) -> CommandResult:
        """Handle open file manager command"""
        try:
            # Try common file managers
            file_managers = ['nautilus', 'dolphin', 'thunar', 'pcmanfm', 'nemo']
            
            for fm in file_managers:
                try:
                    subprocess.Popen([fm], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_file_manager'],
                        message=f"Opened file manager ({fm})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No file manager found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_application(self, parsed_command: Dict) -> CommandResult:
        """Handle open application command"""
        try:
            app_name = parsed_command['parameters'].get('application', '').strip()
            
            if not app_name:
                return CommandResult(
                    success=False,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.FILE,
                    actions_executed=[],
                    message="No application specified",
                    confidence=parsed_command['confidence']
                )
            
            # Try to launch the application
            try:
                subprocess.Popen([app_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return CommandResult(
                    success=True,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.FILE,
                    actions_executed=['open_application'],
                    message=f"Opened application: {app_name}",
                    confidence=parsed_command['confidence']
                )
            except FileNotFoundError:
                return CommandResult(
                    success=False,
                    command=parsed_command['raw_text'],
                    command_type=CommandType.FILE,
                    actions_executed=[],
                    message=f"Application not found: {app_name}",
                    confidence=parsed_command['confidence']
                )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Navigation command handlers
    def _handle_navigate_back(self, parsed_command: Dict) -> CommandResult:
        """Handle navigate back command"""
        try:
            # Send Alt+Left key combination
            subprocess.run(['xdotool', 'key', 'alt+Left'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['navigate_back'],
                message="Navigated back",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for navigation",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_navigate_forward(self, parsed_command: Dict) -> CommandResult:
        """Handle navigate forward command"""
        try:
            subprocess.run(['xdotool', 'key', 'alt+Right'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['navigate_forward'],
                message="Navigated forward",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for navigation",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_refresh_page(self, parsed_command: Dict) -> CommandResult:
        """Handle refresh page command"""
        try:
            subprocess.run(['xdotool', 'key', 'F5'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['refresh_page'],
                message="Page refreshed",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for page refresh",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_scroll_up(self, parsed_command: Dict) -> CommandResult:
        """Handle scroll up command"""
        try:
            subprocess.run(['xdotool', 'key', 'Page_Up'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['scroll_up'],
                message="Scrolled up",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for scrolling",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_scroll_down(self, parsed_command: Dict) -> CommandResult:
        """Handle scroll down command"""
        try:
            subprocess.run(['xdotool', 'key', 'Page_Down'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['scroll_down'],
                message="Scrolled down",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for scrolling",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Communication command handlers
    def _handle_open_email(self, parsed_command: Dict) -> CommandResult:
        """Handle open email command"""
        try:
            email_clients = ['thunderbird', 'evolution', 'kmail', 'geary']
            
            for client in email_clients:
                try:
                    subprocess.Popen([client], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_email'],
                        message=f"Opened email client ({client})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No email client found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_browser(self, parsed_command: Dict) -> CommandResult:
        """Handle open browser command"""
        try:
            browsers = ['firefox', 'google-chrome', 'chromium', 'brave', 'opera']
            
            for browser in browsers:
                try:
                    subprocess.Popen([browser], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_browser'],
                        message=f"Opened browser ({browser})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No browser found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_chat(self, parsed_command: Dict) -> CommandResult:
        """Handle open chat command"""
        try:
            chat_apps = ['discord', 'slack', 'telegram-desktop', 'signal-desktop', 'element-desktop']
            
            for app in chat_apps:
                try:
                    subprocess.Popen([app], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_chat'],
                        message=f"Opened chat application ({app})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No chat application found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Productivity command handlers
    def _handle_open_calculator(self, parsed_command: Dict) -> CommandResult:
        """Handle open calculator command"""
        try:
            calculators = ['gnome-calculator', 'kcalc', 'galculator', 'qalculate-gtk']
            
            for calc in calculators:
                try:
                    subprocess.Popen([calc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_calculator'],
                        message=f"Opened calculator ({calc})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No calculator found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_text_editor(self, parsed_command: Dict) -> CommandResult:
        """Handle open text editor command"""
        try:
            editors = ['gedit', 'kate', 'mousepad', 'leafpad', 'code', 'atom']
            
            for editor in editors:
                try:
                    subprocess.Popen([editor], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_text_editor'],
                        message=f"Opened text editor ({editor})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No text editor found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_take_screenshot(self, parsed_command: Dict) -> CommandResult:
        """Handle take screenshot command"""
        try:
            screenshot_tools = ['gnome-screenshot', 'spectacle', 'scrot', 'flameshot']
            
            for tool in screenshot_tools:
                try:
                    subprocess.Popen([tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.SYSTEM,
                        actions_executed=['take_screenshot'],
                        message=f"Taking screenshot ({tool})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="No screenshot tool found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_calendar(self, parsed_command: Dict) -> CommandResult:
        """Handle open calendar command"""
        try:
            calendar_apps = ['gnome-calendar', 'korganizer', 'evolution', 'thunderbird']
            
            for app in calendar_apps:
                try:
                    subprocess.Popen([app], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.FILE,
                        actions_executed=['open_calendar'],
                        message=f"Opened calendar ({app})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.FILE,
                actions_executed=[],
                message="No calendar application found",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Shortcut command handlers
    def _handle_copy_text(self, parsed_command: Dict) -> CommandResult:
        """Handle copy text command"""
        try:
            subprocess.run(['xdotool', 'key', 'ctrl+c'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['copy_text'],
                message="Text copied to clipboard",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for copy operation",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_paste_text(self, parsed_command: Dict) -> CommandResult:
        """Handle paste text command"""
        try:
            subprocess.run(['xdotool', 'key', 'ctrl+v'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['paste_text'],
                message="Text pasted from clipboard",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for paste operation",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_select_all(self, parsed_command: Dict) -> CommandResult:
        """Handle select all command"""
        try:
            subprocess.run(['xdotool', 'key', 'ctrl+a'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['select_all'],
                message="Selected all text",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for select all",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_undo(self, parsed_command: Dict) -> CommandResult:
        """Handle undo command"""
        try:
            subprocess.run(['xdotool', 'key', 'ctrl+z'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['undo'],
                message="Undo action performed",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for undo",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_redo(self, parsed_command: Dict) -> CommandResult:
        """Handle redo command"""
        try:
            subprocess.run(['xdotool', 'key', 'ctrl+y'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['redo'],
                message="Redo action performed",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=[],
                message="xdotool not available for redo",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Quick action command handlers
    def _handle_show_desktop(self, parsed_command: Dict) -> CommandResult:
        """Handle show desktop command"""
        try:
            subprocess.run(['xdotool', 'key', 'super+d'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=['show_desktop'],
                message="Showing desktop",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=[],
                message="xdotool not available for show desktop",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_switch_application(self, parsed_command: Dict) -> CommandResult:
        """Handle switch application command"""
        try:
            subprocess.run(['xdotool', 'key', 'alt+Tab'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=['switch_application'],
                message="Switching application",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=[],
                message="xdotool not available for app switching",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_open_launcher(self, parsed_command: Dict) -> CommandResult:
        """Handle open launcher command"""
        try:
            # Try common launcher shortcuts
            launchers = [
                ['xdotool', 'key', 'super'],  # GNOME Activities
                ['xdotool', 'key', 'alt+F2'],  # Run dialog
                ['rofi', '-show', 'run'],      # Rofi launcher
                ['dmenu_run']                  # dmenu launcher
            ]
            
            for launcher in launchers:
                try:
                    subprocess.run(launcher, timeout=5)
                    return CommandResult(
                        success=True,
                        command=parsed_command['raw_text'],
                        command_type=CommandType.DESKTOP,
                        actions_executed=['open_launcher'],
                        message=f"Opened launcher ({launcher[0]})",
                        confidence=parsed_command['confidence']
                    )
                except FileNotFoundError:
                    continue
            
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=[],
                message="No launcher available",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_show_notifications(self, parsed_command: Dict) -> CommandResult:
        """Handle show notifications command"""
        try:
            subprocess.run(['xdotool', 'key', 'super+n'], timeout=5)
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=['show_notifications'],
                message="Showing notifications",
                confidence=parsed_command['confidence']
            )
        except FileNotFoundError:
            return CommandResult(
                success=False,
                command=parsed_command['raw_text'],
                command_type=CommandType.DESKTOP,
                actions_executed=[],
                message="xdotool not available for notifications",
                confidence=parsed_command['confidence']
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    # Help command handlers
    def _handle_show_help(self, parsed_command: Dict) -> CommandResult:
        """Handle show help command"""
        try:
            # Get available commands
            from voice_processor import get_voice_processor
            vp = get_voice_processor()
            commands = vp.get_available_commands()
            
            # Create help message with common commands
            common_commands = [
                "play music", "pause music", "next song", "volume up",
                "switch to workspace [number]", "open terminal", "close window",
                "lock screen", "what time is it", "take screenshot",
                "open browser", "open calculator", "show desktop"
            ]
            
            help_message = f"Available commands: {', '.join(common_commands[:10])}... (and {len(commands) - 10} more)"
            
            return CommandResult(
                success=True,
                command=parsed_command['raw_text'],
                command_type=CommandType.SYSTEM,
                actions_executed=['show_help'],
                message=help_message,
                confidence=parsed_command['confidence'],
                details={'total_commands': len(commands), 'common_commands': common_commands}
            )
        except Exception as e:
            return self._create_error_result(parsed_command, str(e))
    
    def _handle_repeat_command(self, parsed_command: Dict) -> CommandResult:
        """Handle repeat last command"""
        # This would require storing command history
        return CommandResult(
            success=False,
            command=parsed_command['raw_text'],
            command_type=CommandType.SYSTEM,
            actions_executed=[],
            message="Command history not implemented yet",
            confidence=parsed_command['confidence']
        )
    
    def _create_error_result(self, parsed_command: Dict, error_message: str) -> CommandResult:
        """Create error result"""
        return CommandResult(
            success=False,
            command=parsed_command.get('raw_text', ''),
            command_type=CommandType.UNKNOWN,
            actions_executed=[],
            message=f"Error: {error_message}",
            confidence=parsed_command.get('confidence', 0.0)
        )


class VoiceProcessor:
    """Main voice processor that handles natural language commands"""
    
    def __init__(self):
        self.parser = NaturalLanguageParser()
        self.executor = CommandExecutor()
        self.custom_commands = {}
        self.command_history = []
        self.max_history = 50
        self._load_custom_commands()
        logger.info("Voice processor initialized")
    
    def process_command(self, text: str) -> CommandResult:
        """
        Process a voice command from text input.
        
        Args:
            text: Voice command as text
            
        Returns:
            CommandResult with execution details
        """
        try:
            # Check for custom commands first
            custom_result = self._check_custom_commands(text)
            if custom_result:
                return custom_result
            
            # Parse natural language
            parsed_command = self.parser.parse_command(text)
            
            # Check confidence threshold
            if parsed_command['confidence'] < 0.5:
                return CommandResult(
                    success=False,
                    command=text,
                    command_type=CommandType.UNKNOWN,
                    actions_executed=[],
                    message=f"Command not recognized. Did you mean: {', '.join(self.parser.get_suggestions(text, 3))}?",
                    confidence=parsed_command['confidence']
                )
            
            # Execute command
            result = self.executor.execute_command(parsed_command)
            
            # Add to command history
            self._add_to_history(text, result)
            
            return result
        
        except Exception as e:
            logger.error(f"Voice command processing failed: {e}")
            return CommandResult(
                success=False,
                command=text,
                command_type=CommandType.UNKNOWN,
                actions_executed=[],
                message=f"Processing failed: {str(e)}",
                confidence=0.0
            )
    
    def _check_custom_commands(self, text: str) -> Optional[CommandResult]:
        """Check if text matches any custom commands"""
        text_lower = text.lower().strip()
        
        for trigger_key, command_info in self.custom_commands.items():
            trigger = command_info.get('trigger', trigger_key)
            
            if trigger.lower() in text_lower:
                try:
                    # Update usage statistics
                    command_info['usage_count'] = command_info.get('usage_count', 0) + 1
                    command_info['last_used'] = time.time()
                    self._save_custom_commands()
                    
                    # Execute custom command actions
                    actions_executed = []
                    for action in command_info['actions']:
                        # Enhanced action execution with parameter substitution
                        processed_action = self._process_action_parameters(action, text, command_info.get('parameters', {}))
                        subprocess.run(processed_action, shell=True, timeout=10)
                        actions_executed.append(processed_action)
                    
                    return CommandResult(
                        success=True,
                        command=text,
                        command_type=CommandType.CUSTOM,
                        actions_executed=actions_executed,
                        message=f"Executed custom command: {trigger}",
                        confidence=1.0
                    )
                except Exception as e:
                    return CommandResult(
                        success=False,
                        command=text,
                        command_type=CommandType.CUSTOM,
                        actions_executed=[],
                        message=f"Custom command failed: {str(e)}",
                        confidence=1.0
                    )
        
        return None
    
    def _process_action_parameters(self, action: str, original_text: str, parameters: Dict[str, Any]) -> str:
        """Process action string with parameter substitution"""
        processed_action = action
        
        # Replace common placeholders
        processed_action = processed_action.replace('{original_text}', original_text)
        processed_action = processed_action.replace('{timestamp}', str(int(time.time())))
        
        # Replace custom parameters
        for param_name, param_value in parameters.items():
            placeholder = f'{{{param_name}}}'
            processed_action = processed_action.replace(placeholder, str(param_value))
        
        return processed_action
    
    def add_custom_command(self, trigger: str, actions: List[str], description: str, 
                          parameters: Dict[str, Any] = None, category: str = "custom") -> bool:
        """Add a custom voice command"""
        try:
            # Validate trigger
            if not trigger or not trigger.strip():
                raise ValueError("Trigger cannot be empty")
            
            # Validate actions
            if not actions or not isinstance(actions, list):
                raise ValueError("Actions must be a non-empty list")
            
            # Store custom command
            self.custom_commands[trigger.lower().strip()] = {
                'trigger': trigger,
                'actions': actions,
                'description': description,
                'parameters': parameters or {},
                'category': category,
                'created_at': time.time(),
                'usage_count': 0,
                'last_used': None
            }
            
            # Save to persistent storage
            self._save_custom_commands()
            
            logger.info(f"Added custom command: {trigger}")
            return True
        except Exception as e:
            logger.error(f"Failed to add custom command: {e}")
            return False
    
    def remove_custom_command(self, trigger: str) -> bool:
        """Remove a custom voice command"""
        try:
            trigger_key = trigger.lower().strip()
            if trigger_key in self.custom_commands:
                del self.custom_commands[trigger_key]
                self._save_custom_commands()
                logger.info(f"Removed custom command: {trigger}")
                return True
            else:
                return False
        except Exception as e:
            logger.error(f"Failed to remove custom command: {e}")
            return False
    
    def update_custom_command(self, trigger: str, actions: List[str] = None, 
                             description: str = None, parameters: Dict[str, Any] = None) -> bool:
        """Update an existing custom command"""
        try:
            trigger_key = trigger.lower().strip()
            if trigger_key not in self.custom_commands:
                return False
            
            command = self.custom_commands[trigger_key]
            
            if actions is not None:
                command['actions'] = actions
            if description is not None:
                command['description'] = description
            if parameters is not None:
                command['parameters'] = parameters
            
            command['updated_at'] = time.time()
            self._save_custom_commands()
            
            logger.info(f"Updated custom command: {trigger}")
            return True
        except Exception as e:
            logger.error(f"Failed to update custom command: {e}")
            return False
    
    def get_custom_commands(self) -> List[Dict[str, Any]]:
        """Get list of custom commands"""
        commands = []
        for trigger_key, info in self.custom_commands.items():
            command_info = {
                'trigger': info.get('trigger', trigger_key),
                'actions': info['actions'],
                'description': info['description'],
                'category': info.get('category', 'custom'),
                'parameters': info.get('parameters', {}),
                'created_at': info['created_at'],
                'usage_count': info.get('usage_count', 0),
                'last_used': info.get('last_used')
            }
            
            if 'updated_at' in info:
                command_info['updated_at'] = info['updated_at']
            
            commands.append(command_info)
        
        # Sort by usage count and creation time
        commands.sort(key=lambda x: (x['usage_count'], x['created_at']), reverse=True)
        return commands
    
    def export_custom_commands(self) -> str:
        """Export custom commands to JSON string"""
        try:
            export_data = {
                'version': '1.0',
                'exported_at': time.time(),
                'commands': self.get_custom_commands()
            }
            return json.dumps(export_data, indent=2)
        except Exception as e:
            logger.error(f"Failed to export custom commands: {e}")
            return ""
    
    def import_custom_commands(self, json_data: str, overwrite: bool = False) -> Dict[str, Any]:
        """Import custom commands from JSON string"""
        try:
            import_data = json.loads(json_data)
            
            if 'commands' not in import_data:
                raise ValueError("Invalid import data format")
            
            imported_count = 0
            skipped_count = 0
            errors = []
            
            for command in import_data['commands']:
                trigger = command.get('trigger', '')
                
                if not overwrite and trigger.lower().strip() in self.custom_commands:
                    skipped_count += 1
                    continue
                
                try:
                    success = self.add_custom_command(
                        trigger=trigger,
                        actions=command.get('actions', []),
                        description=command.get('description', ''),
                        parameters=command.get('parameters', {}),
                        category=command.get('category', 'imported')
                    )
                    
                    if success:
                        imported_count += 1
                    else:
                        errors.append(f"Failed to import command: {trigger}")
                
                except Exception as e:
                    errors.append(f"Error importing {trigger}: {str(e)}")
            
            return {
                'success': True,
                'imported': imported_count,
                'skipped': skipped_count,
                'errors': errors
            }
        
        except Exception as e:
            logger.error(f"Failed to import custom commands: {e}")
            return {
                'success': False,
                'error': str(e),
                'imported': 0,
                'skipped': 0,
                'errors': []
            }
    
    def _load_custom_commands(self):
        """Load custom commands from persistent storage"""
        try:
            commands_file = os.path.expanduser('~/.linux_link_voice_commands.json')
            if os.path.exists(commands_file):
                with open(commands_file, 'r') as f:
                    data = json.load(f)
                    self.custom_commands = data.get('commands', {})
                    logger.info(f"Loaded {len(self.custom_commands)} custom commands")
        except Exception as e:
            logger.debug(f"Could not load custom commands: {e}")
            self.custom_commands = {}
    
    def _save_custom_commands(self):
        """Save custom commands to persistent storage"""
        try:
            commands_file = os.path.expanduser('~/.linux_link_voice_commands.json')
            data = {
                'version': '1.0',
                'saved_at': time.time(),
                'commands': self.custom_commands
            }
            
            with open(commands_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            logger.debug(f"Saved {len(self.custom_commands)} custom commands")
        except Exception as e:
            logger.error(f"Failed to save custom commands: {e}")
    
    def search_commands(self, query: str, include_builtin: bool = True, 
                       include_custom: bool = True) -> List[Dict[str, Any]]:
        """Search for commands matching query"""
        results = []
        query_lower = query.lower().strip()
        
        if include_builtin:
            # Search built-in commands
            for category, patterns in self.parser.patterns.items():
                for pattern_info in patterns:
                    for pattern in pattern_info['patterns']:
                        readable = pattern.replace(r'\s+', ' ').replace(r'\d+', '[number]')
                        readable = re.sub(r'[()\\]', '', readable)
                        
                        if query_lower in readable.lower() or query_lower in pattern_info['action'].lower():
                            results.append({
                                'trigger': readable,
                                'category': category,
                                'action': pattern_info['action'],
                                'confidence': pattern_info['confidence'],
                                'custom': False,
                                'match_type': 'builtin'
                            })
        
        if include_custom:
            # Search custom commands
            for trigger_key, info in self.custom_commands.items():
                trigger = info.get('trigger', trigger_key)
                description = info.get('description', '')
                
                if (query_lower in trigger.lower() or 
                    query_lower in description.lower() or
                    any(query_lower in action.lower() for action in info['actions'])):
                    
                    results.append({
                        'trigger': trigger,
                        'category': info.get('category', 'custom'),
                        'description': description,
                        'actions': info['actions'],
                        'custom': True,
                        'match_type': 'custom',
                        'usage_count': info.get('usage_count', 0)
                    })
        
        # Sort results by relevance
        def relevance_score(item):
            score = 0
            trigger = item.get('trigger', '').lower()
            
            # Exact match gets highest score
            if query_lower == trigger:
                score += 100
            # Starts with query gets high score
            elif trigger.startswith(query_lower):
                score += 50
            # Contains query gets medium score
            elif query_lower in trigger:
                score += 25
            
            # Custom commands with high usage get bonus
            if item.get('custom') and item.get('usage_count', 0) > 0:
                score += item['usage_count']
            
            return score
        
        results.sort(key=relevance_score, reverse=True)
        return results[:20]  # Limit to top 20 results
    
    def _add_to_history(self, command_text: str, result: CommandResult):
        """Add command to history"""
        try:
            history_entry = {
                'timestamp': time.time(),
                'command': command_text,
                'success': result.success,
                'message': result.message,
                'confidence': result.confidence,
                'execution_time': result.execution_time,
                'command_type': result.command_type.value
            }
            
            self.command_history.append(history_entry)
            
            # Keep only recent history
            if len(self.command_history) > self.max_history:
                self.command_history = self.command_history[-self.max_history:]
        
        except Exception as e:
            logger.debug(f"Failed to add command to history: {e}")
    
    def get_command_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent command history"""
        return self.command_history[-limit:] if self.command_history else []
    
    def clear_command_history(self) -> bool:
        """Clear command history"""
        try:
            self.command_history = []
            return True
        except Exception as e:
            logger.error(f"Failed to clear command history: {e}")
            return False
    
    def get_command_statistics(self) -> Dict[str, Any]:
        """Get command usage statistics"""
        try:
            total_commands = len(self.command_history)
            successful_commands = sum(1 for entry in self.command_history if entry['success'])
            
            # Command type distribution
            type_counts = {}
            for entry in self.command_history:
                cmd_type = entry['command_type']
                type_counts[cmd_type] = type_counts.get(cmd_type, 0) + 1
            
            # Average confidence and execution time
            if self.command_history:
                avg_confidence = sum(entry['confidence'] for entry in self.command_history) / total_commands
                avg_execution_time = sum(entry['execution_time'] for entry in self.command_history) / total_commands
            else:
                avg_confidence = 0.0
                avg_execution_time = 0.0
            
            # Most used custom commands
            custom_usage = []
            for trigger_key, info in self.custom_commands.items():
                if info.get('usage_count', 0) > 0:
                    custom_usage.append({
                        'trigger': info.get('trigger', trigger_key),
                        'usage_count': info['usage_count'],
                        'last_used': info.get('last_used')
                    })
            
            custom_usage.sort(key=lambda x: x['usage_count'], reverse=True)
            
            return {
                'total_commands': total_commands,
                'successful_commands': successful_commands,
                'success_rate': successful_commands / total_commands if total_commands > 0 else 0.0,
                'command_type_distribution': type_counts,
                'average_confidence': avg_confidence,
                'average_execution_time': avg_execution_time,
                'custom_commands_count': len(self.custom_commands),
                'most_used_custom_commands': custom_usage[:10]
            }
        
        except Exception as e:
            logger.error(f"Failed to get command statistics: {e}")
            return {}
    
    def get_available_commands(self) -> List[Dict[str, Any]]:
        """Get list of all available commands"""
        commands = []
        
        # Add built-in commands
        for category, patterns in self.parser.patterns.items():
            for pattern_info in patterns:
                for pattern in pattern_info['patterns']:
                    readable = pattern.replace(r'\s+', ' ').replace(r'\d+', '[number]')
                    readable = re.sub(r'[()\\]', '', readable)
                    
                    commands.append({
                        'trigger': readable,
                        'category': category,
                        'action': pattern_info['action'],
                        'confidence': pattern_info['confidence'],
                        'custom': False
                    })
        
        # Add custom commands
        for trigger, info in self.custom_commands.items():
            commands.append({
                'trigger': trigger,
                'category': 'custom',
                'action': 'custom',
                'confidence': 1.0,
                'custom': True,
                'description': info['description']
            })
        
        return commands
    
    def get_command_suggestions(self, partial_text: str, limit: int = 5) -> List[str]:
        """Get command suggestions for partial text"""
        return self.parser.get_suggestions(partial_text, limit)


# Global voice processor instance
_voice_processor = None


def get_voice_processor() -> VoiceProcessor:
    """
    Get global voice processor instance.
    
    Returns:
        VoiceProcessor instance
    """
    global _voice_processor
    if _voice_processor is None:
        _voice_processor = VoiceProcessor()
    
    return _voice_processor


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    vp = get_voice_processor()
    
    test_commands = [
        "play music",
        "switch to workspace 2",
        "what time is it",
        "open terminal",
        "volume up",
        "unknown command"
    ]
    
    for cmd in test_commands:
        print(f"\nTesting: '{cmd}'")
        result = vp.process_command(cmd)
        print(f"Result: {result.message} (success: {result.success}, confidence: {result.confidence})")