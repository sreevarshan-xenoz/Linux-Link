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
            'open_application': self._handle_open_application
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
            return self.executor.execute_command(parsed_command)
        
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
        
        for trigger, command_info in self.custom_commands.items():
            if trigger.lower() in text_lower:
                try:
                    # Execute custom command actions
                    actions_executed = []
                    for action in command_info['actions']:
                        # This is a simplified implementation
                        # In practice, you'd want more sophisticated action execution
                        subprocess.run(action, shell=True, timeout=10)
                        actions_executed.append(action)
                    
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
    
    def add_custom_command(self, trigger: str, actions: List[str], description: str) -> bool:
        """Add a custom voice command"""
        try:
            self.custom_commands[trigger] = {
                'actions': actions,
                'description': description,
                'created_at': time.time()
            }
            logger.info(f"Added custom command: {trigger}")
            return True
        except Exception as e:
            logger.error(f"Failed to add custom command: {e}")
            return False
    
    def remove_custom_command(self, trigger: str) -> bool:
        """Remove a custom voice command"""
        try:
            if trigger in self.custom_commands:
                del self.custom_commands[trigger]
                logger.info(f"Removed custom command: {trigger}")
                return True
            else:
                return False
        except Exception as e:
            logger.error(f"Failed to remove custom command: {e}")
            return False
    
    def get_custom_commands(self) -> List[Dict[str, Any]]:
        """Get list of custom commands"""
        commands = []
        for trigger, info in self.custom_commands.items():
            commands.append({
                'trigger': trigger,
                'actions': info['actions'],
                'description': info['description'],
                'created_at': info['created_at']
            })
        return commands
    
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