"""
Linux-Link Media Controller

Provides media playback control and clipboard integration using MPRIS protocol
and system audio controls for comprehensive media management.
"""

import os
import subprocess
import logging
import json
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from enum import Enum
import time

logger = logging.getLogger(__name__)


class PlaybackStatus(Enum):
    PLAYING = "Playing"
    PAUSED = "Paused"
    STOPPED = "Stopped"


class LoopStatus(Enum):
    NONE = "None"
    TRACK = "Track"
    PLAYLIST = "Playlist"


@dataclass
class MediaMetadata:
    """Represents media metadata"""
    title: str = "Unknown"
    artist: str = "Unknown"
    album: str = "Unknown"
    album_art: Optional[str] = None
    duration: int = 0  # in microseconds
    track_number: Optional[int] = None
    url: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


@dataclass
class MediaStatus:
    """Represents current media player status"""
    player: str
    status: PlaybackStatus
    metadata: MediaMetadata
    position: int = 0  # in microseconds
    volume: float = 1.0  # 0.0 to 1.0
    can_play: bool = True
    can_pause: bool = True
    can_seek: bool = True
    can_go_next: bool = True
    can_go_previous: bool = True
    shuffle: bool = False
    loop_status: LoopStatus = LoopStatus.NONE
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        data['loop_status'] = self.loop_status.value
        data['metadata'] = self.metadata.to_dict()
        return data


class MediaControllerError(Exception):
    """Base exception for media controller operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class MPRISController:
    """Controller for MPRIS-compatible media players"""
    
    def __init__(self):
        self.dbus_available = self._check_dbus_availability()
        logger.info(f"MPRIS controller initialized (D-Bus available: {self.dbus_available})")
    
    def _check_dbus_availability(self) -> bool:
        """Check if D-Bus is available"""
        try:
            result = subprocess.run(['which', 'dbus-send'], 
                                  capture_output=True, text=True, timeout=2)
            return result.returncode == 0
        except:
            return False
    
    def _execute_dbus_command(self, command: List[str]) -> str:
        """Execute D-Bus command and return output"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.warning(f"D-Bus command failed: {result.stderr}")
                return ""
        except subprocess.TimeoutExpired:
            logger.error("D-Bus command timed out")
            return ""
        except Exception as e:
            logger.error(f"D-Bus command error: {e}")
            return ""
    
    def get_available_players(self) -> List[str]:
        """Get list of available MPRIS players"""
        if not self.dbus_available:
            return []
        
        try:
            # List all D-Bus services
            command = [
                'dbus-send', '--session', '--dest=org.freedesktop.DBus',
                '--type=method_call', '--print-reply',
                '/org/freedesktop/DBus', 'org.freedesktop.DBus.ListNames'
            ]
            
            output = self._execute_dbus_command(command)
            if not output:
                return []
            
            # Extract MPRIS player names
            players = []
            for line in output.split('\n'):
                if 'org.mpris.MediaPlayer2.' in line:
                    # Extract player name from D-Bus service name
                    start = line.find('org.mpris.MediaPlayer2.') + len('org.mpris.MediaPlayer2.')
                    end = line.find('"', start)
                    if end > start:
                        player_name = line[start:end]
                        players.append(player_name)
            
            logger.info(f"Found MPRIS players: {players}")
            return players
        
        except Exception as e:
            logger.error(f"Failed to get available players: {e}")
            return []
    
    def get_player_status(self, player: str) -> Optional[MediaStatus]:
        """Get status of specific MPRIS player"""
        if not self.dbus_available:
            return None
        
        try:
            service_name = f"org.mpris.MediaPlayer2.{player}"
            
            # Get playback status
            status_cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call', '--print-reply',
                '/org/mpris/MediaPlayer2',
                'org.freedesktop.DBus.Properties.Get',
                'string:org.mpris.MediaPlayer2.Player',
                'string:PlaybackStatus'
            ]
            
            status_output = self._execute_dbus_command(status_cmd)
            playback_status = PlaybackStatus.STOPPED
            
            if 'Playing' in status_output:
                playback_status = PlaybackStatus.PLAYING
            elif 'Paused' in status_output:
                playback_status = PlaybackStatus.PAUSED
            
            # Get metadata
            metadata_cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call', '--print-reply',
                '/org/mpris/MediaPlayer2',
                'org.freedesktop.DBus.Properties.Get',
                'string:org.mpris.MediaPlayer2.Player',
                'string:Metadata'
            ]
            
            metadata_output = self._execute_dbus_command(metadata_cmd)
            metadata = self._parse_metadata(metadata_output)
            
            # Get position
            position_cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call', '--print-reply',
                '/org/mpris/MediaPlayer2',
                'org.freedesktop.DBus.Properties.Get',
                'string:org.mpris.MediaPlayer2.Player',
                'string:Position'
            ]
            
            position_output = self._execute_dbus_command(position_cmd)
            position = self._parse_position(position_output)
            
            # Get volume
            volume_cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call', '--print-reply',
                '/org/mpris/MediaPlayer2',
                'org.freedesktop.DBus.Properties.Get',
                'string:org.mpris.MediaPlayer2.Player',
                'string:Volume'
            ]
            
            volume_output = self._execute_dbus_command(volume_cmd)
            volume = self._parse_volume(volume_output)
            
            return MediaStatus(
                player=player,
                status=playback_status,
                metadata=metadata,
                position=position,
                volume=volume
            )
        
        except Exception as e:
            logger.error(f"Failed to get player status for {player}: {e}")
            return None
    
    def _parse_metadata(self, metadata_output: str) -> MediaMetadata:
        """Parse metadata from D-Bus output"""
        metadata = MediaMetadata()
        
        try:
            # This is a simplified parser - D-Bus output parsing is complex
            lines = metadata_output.split('\n')
            
            for line in lines:
                if 'xesam:title' in line:
                    # Extract title
                    start = line.find('"') + 1
                    end = line.rfind('"')
                    if end > start:
                        metadata.title = line[start:end]
                
                elif 'xesam:artist' in line:
                    # Extract artist
                    start = line.find('"') + 1
                    end = line.rfind('"')
                    if end > start:
                        metadata.artist = line[start:end]
                
                elif 'xesam:album' in line:
                    # Extract album
                    start = line.find('"') + 1
                    end = line.rfind('"')
                    if end > start:
                        metadata.album = line[start:end]
                
                elif 'mpris:length' in line:
                    # Extract duration
                    try:
                        # Find the number in the line
                        import re
                        numbers = re.findall(r'\d+', line)
                        if numbers:
                            metadata.duration = int(numbers[-1])
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Error parsing metadata: {e}")
        
        return metadata
    
    def _parse_position(self, position_output: str) -> int:
        """Parse position from D-Bus output"""
        try:
            import re
            numbers = re.findall(r'\d+', position_output)
            if numbers:
                return int(numbers[-1])
        except:
            pass
        return 0
    
    def _parse_volume(self, volume_output: str) -> float:
        """Parse volume from D-Bus output"""
        try:
            import re
            # Look for decimal numbers
            numbers = re.findall(r'\d+\.?\d*', volume_output)
            if numbers:
                return float(numbers[-1])
        except:
            pass
        return 1.0
    
    def send_player_command(self, player: str, command: str) -> bool:
        """Send command to MPRIS player"""
        if not self.dbus_available:
            return False
        
        try:
            service_name = f"org.mpris.MediaPlayer2.{player}"
            
            cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call',
                '/org/mpris/MediaPlayer2',
                f'org.mpris.MediaPlayer2.Player.{command}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            success = result.returncode == 0
            
            if success:
                logger.info(f"Sent command {command} to player {player}")
            else:
                logger.warning(f"Failed to send command {command} to player {player}: {result.stderr}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to send command to player: {e}")
            return False
    
    def set_player_volume(self, player: str, volume: float) -> bool:
        """Set volume for MPRIS player"""
        if not self.dbus_available:
            return False
        
        try:
            service_name = f"org.mpris.MediaPlayer2.{player}"
            
            cmd = [
                'dbus-send', '--session', '--dest=' + service_name,
                '--type=method_call',
                '/org/mpris/MediaPlayer2',
                'org.freedesktop.DBus.Properties.Set',
                'string:org.mpris.MediaPlayer2.Player',
                'string:Volume',
                f'variant:double:{volume}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            success = result.returncode == 0
            
            if success:
                logger.info(f"Set volume to {volume} for player {player}")
            else:
                logger.warning(f"Failed to set volume for player {player}: {result.stderr}")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to set player volume: {e}")
            return False


class AudioController:
    """Controller for system audio using PulseAudio/PipeWire/ALSA"""
    
    def __init__(self):
        self.audio_system = self._detect_audio_system()
        logger.info(f"Audio controller initialized with {self.audio_system}")
    
    def _detect_audio_system(self) -> str:
        """Detect available audio system"""
        # Check for PulseAudio
        try:
            result = subprocess.run(['which', 'pactl'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return 'pulseaudio'
        except:
            pass
        
        # Check for PipeWire
        try:
            result = subprocess.run(['which', 'wpctl'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return 'pipewire'
        except:
            pass
        
        # Check for ALSA
        try:
            result = subprocess.run(['which', 'amixer'], 
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                return 'alsa'
        except:
            pass
        
        return 'unknown'
    
    def get_volume(self) -> float:
        """Get system volume (0.0 to 1.0)"""
        try:
            if self.audio_system == 'pulseaudio':
                return self._get_pulseaudio_volume()
            elif self.audio_system == 'pipewire':
                return self._get_pipewire_volume()
            elif self.audio_system == 'alsa':
                return self._get_alsa_volume()
            else:
                logger.warning("No supported audio system found")
                return 0.5
        
        except Exception as e:
            logger.error(f"Failed to get volume: {e}")
            return 0.5
    
    def set_volume(self, volume: float) -> bool:
        """Set system volume (0.0 to 1.0)"""
        try:
            # Clamp volume to valid range
            volume = max(0.0, min(1.0, volume))
            
            if self.audio_system == 'pulseaudio':
                return self._set_pulseaudio_volume(volume)
            elif self.audio_system == 'pipewire':
                return self._set_pipewire_volume(volume)
            elif self.audio_system == 'alsa':
                return self._set_alsa_volume(volume)
            else:
                logger.warning("No supported audio system found")
                return False
        
        except Exception as e:
            logger.error(f"Failed to set volume: {e}")
            return False
    
    def _get_pulseaudio_volume(self) -> float:
        """Get PulseAudio volume"""
        try:
            result = subprocess.run(['pactl', 'get-sink-volume', '@DEFAULT_SINK@'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse output like "Volume: front-left: 32768 /  50% / -18.06 dB"
                import re
                percentages = re.findall(r'(\d+)%', result.stdout)
                if percentages:
                    return int(percentages[0]) / 100.0
        
        except Exception as e:
            logger.debug(f"PulseAudio volume get failed: {e}")
        
        return 0.5
    
    def _set_pulseaudio_volume(self, volume: float) -> bool:
        """Set PulseAudio volume"""
        try:
            percentage = int(volume * 100)
            result = subprocess.run(['pactl', 'set-sink-volume', '@DEFAULT_SINK@', f'{percentage}%'], 
                                  capture_output=True, text=True, timeout=5)
            
            success = result.returncode == 0
            if success:
                logger.info(f"Set PulseAudio volume to {percentage}%")
            
            return success
        
        except Exception as e:
            logger.error(f"PulseAudio volume set failed: {e}")
            return False
    
    def _get_pipewire_volume(self) -> float:
        """Get PipeWire volume"""
        try:
            result = subprocess.run(['wpctl', 'get-volume', '@DEFAULT_AUDIO_SINK@'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse output like "Volume: 0.50"
                import re
                volumes = re.findall(r'Volume: ([\d.]+)', result.stdout)
                if volumes:
                    return float(volumes[0])
        
        except Exception as e:
            logger.debug(f"PipeWire volume get failed: {e}")
        
        return 0.5
    
    def _set_pipewire_volume(self, volume: float) -> bool:
        """Set PipeWire volume"""
        try:
            result = subprocess.run(['wpctl', 'set-volume', '@DEFAULT_AUDIO_SINK@', str(volume)], 
                                  capture_output=True, text=True, timeout=5)
            
            success = result.returncode == 0
            if success:
                logger.info(f"Set PipeWire volume to {volume}")
            
            return success
        
        except Exception as e:
            logger.error(f"PipeWire volume set failed: {e}")
            return False
    
    def _get_alsa_volume(self) -> float:
        """Get ALSA volume"""
        try:
            result = subprocess.run(['amixer', 'get', 'Master'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse output to find percentage
                import re
                percentages = re.findall(r'\[(\d+)%\]', result.stdout)
                if percentages:
                    return int(percentages[0]) / 100.0
        
        except Exception as e:
            logger.debug(f"ALSA volume get failed: {e}")
        
        return 0.5
    
    def _set_alsa_volume(self, volume: float) -> bool:
        """Set ALSA volume"""
        try:
            percentage = int(volume * 100)
            result = subprocess.run(['amixer', 'set', 'Master', f'{percentage}%'], 
                                  capture_output=True, text=True, timeout=5)
            
            success = result.returncode == 0
            if success:
                logger.info(f"Set ALSA volume to {percentage}%")
            
            return success
        
        except Exception as e:
            logger.error(f"ALSA volume set failed: {e}")
            return False
    
    def is_muted(self) -> bool:
        """Check if audio is muted"""
        try:
            if self.audio_system == 'pulseaudio':
                result = subprocess.run(['pactl', 'get-sink-mute', '@DEFAULT_SINK@'], 
                                      capture_output=True, text=True, timeout=5)
                return 'yes' in result.stdout.lower()
            
            elif self.audio_system == 'pipewire':
                result = subprocess.run(['wpctl', 'get-volume', '@DEFAULT_AUDIO_SINK@'], 
                                      capture_output=True, text=True, timeout=5)
                return '[MUTED]' in result.stdout
            
            elif self.audio_system == 'alsa':
                result = subprocess.run(['amixer', 'get', 'Master'], 
                                      capture_output=True, text=True, timeout=5)
                return '[off]' in result.stdout
        
        except Exception as e:
            logger.error(f"Failed to check mute status: {e}")
        
        return False
    
    def toggle_mute(self) -> bool:
        """Toggle audio mute"""
        try:
            if self.audio_system == 'pulseaudio':
                result = subprocess.run(['pactl', 'set-sink-mute', '@DEFAULT_SINK@', 'toggle'], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif self.audio_system == 'pipewire':
                result = subprocess.run(['wpctl', 'set-mute', '@DEFAULT_AUDIO_SINK@', 'toggle'], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            
            elif self.audio_system == 'alsa':
                result = subprocess.run(['amixer', 'set', 'Master', 'toggle'], 
                                      capture_output=True, text=True, timeout=5)
                return result.returncode == 0
        
        except Exception as e:
            logger.error(f"Failed to toggle mute: {e}")
        
        return False
    
    def get_audio_devices(self) -> List[Dict[str, Any]]:
        """Get list of available audio devices"""
        devices = []
        
        try:
            if self.audio_system == 'pulseaudio':
                devices = self._get_pulseaudio_devices()
            elif self.audio_system == 'pipewire':
                devices = self._get_pipewire_devices()
            elif self.audio_system == 'alsa':
                devices = self._get_alsa_devices()
        
        except Exception as e:
            logger.error(f"Failed to get audio devices: {e}")
        
        return devices
    
    def _get_pulseaudio_devices(self) -> List[Dict[str, Any]]:
        """Get PulseAudio devices"""
        devices = []
        
        try:
            # Get sinks (output devices)
            result = subprocess.run(['pactl', 'list', 'short', 'sinks'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            devices.append({
                                'id': parts[0],
                                'name': parts[1],
                                'type': 'output',
                                'description': parts[1]
                            })
            
            # Get sources (input devices)
            result = subprocess.run(['pactl', 'list', 'short', 'sources'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line and not line.endswith('.monitor'):  # Skip monitor sources
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            devices.append({
                                'id': parts[0],
                                'name': parts[1],
                                'type': 'input',
                                'description': parts[1]
                            })
        
        except Exception as e:
            logger.debug(f"PulseAudio device enumeration failed: {e}")
        
        return devices
    
    def _get_pipewire_devices(self) -> List[Dict[str, Any]]:
        """Get PipeWire devices"""
        devices = []
        
        try:
            # Get audio sinks
            result = subprocess.run(['wpctl', 'status'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                in_sinks = False
                in_sources = False
                
                for line in lines:
                    line = line.strip()
                    
                    if 'Audio' in line and 'Sinks:' in line:
                        in_sinks = True
                        in_sources = False
                        continue
                    elif 'Audio' in line and 'Sources:' in line:
                        in_sinks = False
                        in_sources = True
                        continue
                    elif line.startswith('Video') or line.startswith('Settings'):
                        in_sinks = False
                        in_sources = False
                        continue
                    
                    if (in_sinks or in_sources) and line and not line.startswith('├') and not line.startswith('│'):
                        # Parse device line
                        import re
                        match = re.search(r'(\d+)\.\s+(.+)', line)
                        if match:
                            device_id = match.group(1)
                            device_name = match.group(2).strip()
                            
                            devices.append({
                                'id': device_id,
                                'name': device_name,
                                'type': 'output' if in_sinks else 'input',
                                'description': device_name
                            })
        
        except Exception as e:
            logger.debug(f"PipeWire device enumeration failed: {e}")
        
        return devices
    
    def _get_alsa_devices(self) -> List[Dict[str, Any]]:
        """Get ALSA devices"""
        devices = []
        
        try:
            # Get playback devices
            result = subprocess.run(['aplay', '-l'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                import re
                for line in result.stdout.split('\n'):
                    match = re.search(r'card (\d+): (.+) \[(.+)\], device (\d+): (.+) \[(.+)\]', line)
                    if match:
                        card_id = match.group(1)
                        card_name = match.group(2)
                        device_id = match.group(4)
                        device_name = match.group(5)
                        
                        devices.append({
                            'id': f'hw:{card_id},{device_id}',
                            'name': f'{card_name} - {device_name}',
                            'type': 'output',
                            'description': f'Card {card_id}, Device {device_id}'
                        })
            
            # Get capture devices
            result = subprocess.run(['arecord', '-l'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                import re
                for line in result.stdout.split('\n'):
                    match = re.search(r'card (\d+): (.+) \[(.+)\], device (\d+): (.+) \[(.+)\]', line)
                    if match:
                        card_id = match.group(1)
                        card_name = match.group(2)
                        device_id = match.group(4)
                        device_name = match.group(5)
                        
                        devices.append({
                            'id': f'hw:{card_id},{device_id}',
                            'name': f'{card_name} - {device_name}',
                            'type': 'input',
                            'description': f'Card {card_id}, Device {device_id}'
                        })
        
        except Exception as e:
            logger.debug(f"ALSA device enumeration failed: {e}")
        
        return devices
    
    def set_default_device(self, device_id: str, device_type: str = 'output') -> bool:
        """Set default audio device"""
        try:
            if self.audio_system == 'pulseaudio':
                if device_type == 'output':
                    result = subprocess.run(['pactl', 'set-default-sink', device_id], 
                                          capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['pactl', 'set-default-source', device_id], 
                                          capture_output=True, text=True, timeout=5)
                
                success = result.returncode == 0
                if success:
                    logger.info(f"Set default {device_type} device to {device_id}")
                return success
            
            elif self.audio_system == 'pipewire':
                result = subprocess.run(['wpctl', 'set-default', device_id], 
                                      capture_output=True, text=True, timeout=5)
                success = result.returncode == 0
                if success:
                    logger.info(f"Set default device to {device_id}")
                return success
            
            else:
                logger.warning("Setting default device not supported for ALSA")
                return False
        
        except Exception as e:
            logger.error(f"Failed to set default device: {e}")
            return False
    
    def get_audio_info(self) -> Dict[str, Any]:
        """Get comprehensive audio system information"""
        return {
            'audio_system': self.audio_system,
            'volume': self.get_volume(),
            'muted': self.is_muted(),
            'devices': self.get_audio_devices(),
            'supported_operations': {
                'volume_control': True,
                'mute_control': True,
                'device_switching': self.audio_system in ['pulseaudio', 'pipewire'],
                'device_enumeration': True
            }
        }


class ClipboardController:
    """Controller for clipboard operations"""
    
    def __init__(self):
        self.clipboard_tool = self._detect_clipboard_tool()
        logger.info(f"Clipboard controller initialized with {self.clipboard_tool}")
    
    def _detect_clipboard_tool(self) -> str:
        """Detect available clipboard tool"""
        tools = ['xclip', 'xsel', 'wl-clipboard']
        
        for tool in tools:
            try:
                result = subprocess.run(['which', tool], 
                                      capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return tool
            except:
                continue
        
        return 'unknown'
    
    def get_clipboard_text(self) -> str:
        """Get text from clipboard"""
        try:
            if self.clipboard_tool == 'xclip':
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-o'], 
                                      capture_output=True, text=True, timeout=5)
                return result.stdout if result.returncode == 0 else ""
            
            elif self.clipboard_tool == 'xsel':
                result = subprocess.run(['xsel', '--clipboard', '--output'], 
                                      capture_output=True, text=True, timeout=5)
                return result.stdout if result.returncode == 0 else ""
            
            elif self.clipboard_tool == 'wl-clipboard':
                result = subprocess.run(['wl-paste'], 
                                      capture_output=True, text=True, timeout=5)
                return result.stdout if result.returncode == 0 else ""
            
            else:
                logger.warning("No supported clipboard tool found")
                return ""
        
        except Exception as e:
            logger.error(f"Failed to get clipboard text: {e}")
            return ""
    
    def set_clipboard_text(self, text: str) -> bool:
        """Set text to clipboard"""
        try:
            if self.clipboard_tool == 'xclip':
                process = subprocess.Popen(['xclip', '-selection', 'clipboard'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate(input=text)
                return process.returncode == 0
            
            elif self.clipboard_tool == 'xsel':
                process = subprocess.Popen(['xsel', '--clipboard', '--input'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate(input=text)
                return process.returncode == 0
            
            elif self.clipboard_tool == 'wl-clipboard':
                process = subprocess.Popen(['wl-copy'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate(input=text)
                return process.returncode == 0
            
            else:
                logger.warning("No supported clipboard tool found")
                return False
        
        except Exception as e:
            logger.error(f"Failed to set clipboard text: {e}")
            return False
    
    def get_clipboard_image(self) -> Optional[bytes]:
        """Get image from clipboard"""
        try:
            if self.clipboard_tool == 'xclip':
                # Try to get PNG image
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-t', 'image/png', '-o'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0 and result.stdout:
                    return result.stdout
                
                # Try to get JPEG image
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-t', 'image/jpeg', '-o'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0 and result.stdout:
                    return result.stdout
            
            elif self.clipboard_tool == 'wl-clipboard':
                # Try to get PNG image
                result = subprocess.run(['wl-paste', '--type', 'image/png'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0 and result.stdout:
                    return result.stdout
                
                # Try to get JPEG image
                result = subprocess.run(['wl-paste', '--type', 'image/jpeg'], 
                                      capture_output=True, timeout=5)
                if result.returncode == 0 and result.stdout:
                    return result.stdout
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get clipboard image: {e}")
            return None
    
    def set_clipboard_image(self, image_data: bytes, image_type: str = 'image/png') -> bool:
        """Set image to clipboard"""
        try:
            if self.clipboard_tool == 'xclip':
                process = subprocess.Popen(['xclip', '-selection', 'clipboard', '-t', image_type], 
                                         stdin=subprocess.PIPE)
                process.communicate(input=image_data)
                return process.returncode == 0
            
            elif self.clipboard_tool == 'wl-clipboard':
                process = subprocess.Popen(['wl-copy', '--type', image_type], 
                                         stdin=subprocess.PIPE)
                process.communicate(input=image_data)
                return process.returncode == 0
            
            else:
                logger.warning("Image clipboard not supported with current tool")
                return False
        
        except Exception as e:
            logger.error(f"Failed to set clipboard image: {e}")
            return False
    
    def get_clipboard_types(self) -> List[str]:
        """Get available clipboard content types"""
        types = []
        
        try:
            if self.clipboard_tool == 'xclip':
                result = subprocess.run(['xclip', '-selection', 'clipboard', '-t', 'TARGETS', '-o'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    types = [line.strip() for line in result.stdout.split('\n') if line.strip()]
            
            elif self.clipboard_tool == 'wl-clipboard':
                result = subprocess.run(['wl-paste', '--list-types'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    types = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        
        except Exception as e:
            logger.debug(f"Failed to get clipboard types: {e}")
        
        return types
    
    def has_clipboard_content(self, content_type: str = 'text') -> bool:
        """Check if clipboard has specific content type"""
        try:
            types = self.get_clipboard_types()
            
            if content_type == 'text':
                text_types = ['text/plain', 'TEXT', 'STRING', 'UTF8_STRING']
                return any(t in types for t in text_types)
            
            elif content_type == 'image':
                image_types = ['image/png', 'image/jpeg', 'image/gif', 'image/bmp']
                return any(t in types for t in image_types)
            
            else:
                return content_type in types
        
        except Exception as e:
            logger.debug(f"Failed to check clipboard content: {e}")
            return False
    
    def clear_clipboard(self) -> bool:
        """Clear clipboard contents"""
        try:
            if self.clipboard_tool == 'xclip':
                process = subprocess.Popen(['xclip', '-selection', 'clipboard'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate(input='')
                return process.returncode == 0
            
            elif self.clipboard_tool == 'xsel':
                process = subprocess.Popen(['xsel', '--clipboard', '--clear'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate()
                return process.returncode == 0
            
            elif self.clipboard_tool == 'wl-clipboard':
                process = subprocess.Popen(['wl-copy', '--clear'], 
                                         stdin=subprocess.PIPE, text=True)
                process.communicate()
                return process.returncode == 0
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to clear clipboard: {e}")
            return False
    
    def get_clipboard_info(self) -> Dict[str, Any]:
        """Get comprehensive clipboard information"""
        return {
            'tool': self.clipboard_tool,
            'has_text': self.has_clipboard_content('text'),
            'has_image': self.has_clipboard_content('image'),
            'available_types': self.get_clipboard_types(),
            'text_preview': self.get_clipboard_text()[:100] if self.has_clipboard_content('text') else None
        }


class MediaController:
    """Main media controller that manages MPRIS players and system audio"""
    
    def __init__(self):
        self.mpris = MPRISController()
        self.audio = AudioController()
        self.clipboard = ClipboardController()
        logger.info("Media controller initialized")
    
    def get_available_players(self) -> List[str]:
        """Get list of available media players"""
        return self.mpris.get_available_players()
    
    def get_active_player(self) -> Optional[str]:
        """Get currently active/playing media player"""
        players = self.get_available_players()
        
        for player in players:
            status = self.mpris.get_player_status(player)
            if status and status.status == PlaybackStatus.PLAYING:
                return player
        
        # If no playing player, return first available
        return players[0] if players else None
    
    def get_media_status(self, player: str = None) -> Optional[MediaStatus]:
        """Get media status for specific player or active player"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return None
        
        return self.mpris.get_player_status(player)
    
    def play_pause(self, player: str = None) -> bool:
        """Toggle play/pause for player"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'PlayPause')
    
    def play(self, player: str = None) -> bool:
        """Play media"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'Play')
    
    def pause(self, player: str = None) -> bool:
        """Pause media"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'Pause')
    
    def stop(self, player: str = None) -> bool:
        """Stop media"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'Stop')
    
    def next_track(self, player: str = None) -> bool:
        """Skip to next track"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'Next')
    
    def previous_track(self, player: str = None) -> bool:
        """Skip to previous track"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.send_player_command(player, 'Previous')
    
    def set_player_volume(self, volume: float, player: str = None) -> bool:
        """Set volume for specific player"""
        if not player:
            player = self.get_active_player()
        
        if not player:
            return False
        
        return self.mpris.set_player_volume(player, volume)
    
    def get_system_volume(self) -> float:
        """Get system volume"""
        return self.audio.get_volume()
    
    def set_system_volume(self, volume: float) -> bool:
        """Set system volume"""
        return self.audio.set_volume(volume)
    
    def is_system_muted(self) -> bool:
        """Check if system audio is muted"""
        return self.audio.is_muted()
    
    def toggle_system_mute(self) -> bool:
        """Toggle system audio mute"""
        return self.audio.toggle_mute()
    
    def get_audio_devices(self) -> List[Dict[str, Any]]:
        """Get list of available audio devices"""
        return self.audio.get_audio_devices()
    
    def set_default_audio_device(self, device_id: str, device_type: str = 'output') -> bool:
        """Set default audio device"""
        return self.audio.set_default_device(device_id, device_type)
    
    def get_audio_info(self) -> Dict[str, Any]:
        """Get comprehensive audio system information"""
        return self.audio.get_audio_info()
    
    def get_clipboard_text(self) -> str:
        """Get text from clipboard"""
        return self.clipboard.get_clipboard_text()
    
    def set_clipboard_text(self, text: str) -> bool:
        """Set text to clipboard"""
        return self.clipboard.set_clipboard_text(text)
    
    def get_clipboard_image(self) -> Optional[bytes]:
        """Get image from clipboard"""
        return self.clipboard.get_clipboard_image()
    
    def set_clipboard_image(self, image_data: bytes, image_type: str = 'image/png') -> bool:
        """Set image to clipboard"""
        return self.clipboard.set_clipboard_image(image_data, image_type)
    
    def get_clipboard_types(self) -> List[str]:
        """Get available clipboard content types"""
        return self.clipboard.get_clipboard_types()
    
    def has_clipboard_content(self, content_type: str = 'text') -> bool:
        """Check if clipboard has specific content type"""
        return self.clipboard.has_clipboard_content(content_type)
    
    def clear_clipboard(self) -> bool:
        """Clear clipboard contents"""
        return self.clipboard.clear_clipboard()
    
    def get_clipboard_info(self) -> Dict[str, Any]:
        """Get comprehensive clipboard information"""
        return self.clipboard.get_clipboard_info()
    
    def sync_clipboard_to_mobile(self) -> Dict[str, Any]:
        """Sync clipboard content to mobile device"""
        clipboard_info = self.get_clipboard_info()
        
        sync_data = {
            'has_text': clipboard_info['has_text'],
            'has_image': clipboard_info['has_image'],
            'text_content': None,
            'image_content': None,
            'image_type': None
        }
        
        if clipboard_info['has_text']:
            sync_data['text_content'] = self.get_clipboard_text()
        
        if clipboard_info['has_image']:
            image_data = self.get_clipboard_image()
            if image_data:
                import base64
                sync_data['image_content'] = base64.b64encode(image_data).decode('utf-8')
                
                # Determine image type from clipboard types
                types = clipboard_info['available_types']
                if 'image/png' in types:
                    sync_data['image_type'] = 'image/png'
                elif 'image/jpeg' in types:
                    sync_data['image_type'] = 'image/jpeg'
                else:
                    sync_data['image_type'] = 'image/png'  # Default
        
        return sync_data
    
    def sync_clipboard_from_mobile(self, mobile_data: Dict[str, Any]) -> bool:
        """Sync clipboard content from mobile device"""
        success = True
        
        try:
            if mobile_data.get('text_content'):
                if not self.set_clipboard_text(mobile_data['text_content']):
                    success = False
                    logger.warning("Failed to sync text to clipboard")
            
            elif mobile_data.get('image_content'):
                import base64
                image_data = base64.b64decode(mobile_data['image_content'])
                image_type = mobile_data.get('image_type', 'image/png')
                
                if not self.set_clipboard_image(image_data, image_type):
                    success = False
                    logger.warning("Failed to sync image to clipboard")
            
            if success:
                logger.info("Successfully synced clipboard from mobile")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to sync clipboard from mobile: {e}")
            return False
    
    def get_comprehensive_status(self) -> Dict[str, Any]:
        """Get comprehensive media and system status"""
        players = self.get_available_players()
        active_player = self.get_active_player()
        
        status = {
            "available_players": players,
            "active_player": active_player,
            "media_status": None,
            "system_audio": self.get_audio_info(),
            "clipboard": self.get_clipboard_info()
        }
        
        if active_player:
            media_status = self.get_media_status(active_player)
            if media_status:
                status["media_status"] = media_status.to_dict()
        
        return status


# Global media controller instance
_media_controller = None


def get_media_controller() -> MediaController:
    """
    Get global media controller instance.
    
    Returns:
        MediaController instance
    """
    global _media_controller
    if _media_controller is None:
        _media_controller = MediaController()
    
    return _media_controller


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    mc = get_media_controller()
    
    print("Available players:", mc.get_available_players())
    print("Active player:", mc.get_active_player())
    print("System volume:", mc.get_system_volume())
    print("System muted:", mc.is_system_muted())
    
    status = mc.get_comprehensive_status()
    print("Comprehensive status:", json.dumps(status, indent=2, default=str))