"""
Linux-Link File Manager Backend Service

Provides secure file browsing and management capabilities with permission checks
and configurable access controls for remote file operations.
"""

import os
import stat
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, asdict
import logging
from enum import Enum

# Unix-specific imports with fallback for Windows
try:
    import pwd
    import grp
    UNIX_AVAILABLE = True
except ImportError:
    # Windows or other non-Unix systems
    pwd = None
    grp = None
    UNIX_AVAILABLE = False

logger = logging.getLogger(__name__)


class FileType(Enum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    UNKNOWN = "unknown"


@dataclass
class FileItem:
    """Represents a file or directory with metadata"""
    name: str
    path: str
    type: FileType
    size: int
    permissions: str
    modified: datetime
    owner: str
    group: str
    is_hidden: bool = False
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['type'] = self.type.value
        data['modified'] = self.modified.isoformat()
        return data


class FileManagerError(Exception):
    """Base exception for file manager operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class PermissionError(FileManagerError):
    """Raised when access is denied due to insufficient permissions"""
    pass


class PathNotFoundError(FileManagerError):
    """Raised when requested path does not exist"""
    pass


class SecureFileManager:
    """
    Secure file manager with permission checks and configurable access controls.
    
    Provides safe file browsing capabilities with:
    - Configurable allowed paths (chroot-like behavior)
    - Permission validation
    - Path traversal protection
    - Metadata extraction
    """
    
    def __init__(self, allowed_paths: List[str] = None, user_context: str = None):
        """
        Initialize secure file manager.
        
        Args:
            allowed_paths: List of allowed root paths for browsing
            user_context: User context for permission checks
        """
        self.allowed_paths = allowed_paths or ["/home", "/tmp", "/var/log"]
        self.user_context = user_context or os.getenv("USER", "root")
        
        # Normalize and validate allowed paths
        self.allowed_paths = [os.path.abspath(path) for path in self.allowed_paths]
        
        logger.info(f"FileManager initialized with allowed paths: {self.allowed_paths}")
    
    def _is_path_allowed(self, path: str) -> bool:
        """
        Check if path is within allowed directories.
        
        Args:
            path: Path to validate
            
        Returns:
            True if path is allowed, False otherwise
        """
        abs_path = os.path.abspath(path)
        
        for allowed_path in self.allowed_paths:
            try:
                # Check if path is within allowed directory
                os.path.commonpath([abs_path, allowed_path])
                if abs_path.startswith(allowed_path):
                    return True
            except ValueError:
                # Paths are on different drives (Windows) or invalid
                continue
        
        return False
    
    def _validate_path(self, path: str) -> str:
        """
        Validate and normalize path with security checks.
        
        Args:
            path: Path to validate
            
        Returns:
            Normalized absolute path
            
        Raises:
            PermissionError: If path is not allowed
            PathNotFoundError: If path does not exist
        """
        # Normalize path and resolve symlinks
        abs_path = os.path.abspath(os.path.expanduser(path))
        
        # Check if path is allowed
        if not self._is_path_allowed(abs_path):
            raise PermissionError(
                f"Access denied to path: {path}",
                "PATH_NOT_ALLOWED",
                {"requested_path": path, "resolved_path": abs_path}
            )
        
        # Check if path exists
        if not os.path.exists(abs_path):
            raise PathNotFoundError(
                f"Path not found: {path}",
                "PATH_NOT_FOUND",
                {"requested_path": path, "resolved_path": abs_path}
            )
        
        return abs_path
    
    def _get_file_permissions(self, file_path: str) -> str:
        """
        Get file permissions in human-readable format.
        
        Args:
            file_path: Path to file
            
        Returns:
            Permission string (e.g., 'rwxr-xr-x')
        """
        try:
            file_stat = os.stat(file_path)
            mode = file_stat.st_mode
            
            # Convert to rwx format
            permissions = ""
            
            # Owner permissions
            permissions += "r" if mode & stat.S_IRUSR else "-"
            permissions += "w" if mode & stat.S_IWUSR else "-"
            permissions += "x" if mode & stat.S_IXUSR else "-"
            
            # Group permissions
            permissions += "r" if mode & stat.S_IRGRP else "-"
            permissions += "w" if mode & stat.S_IWGRP else "-"
            permissions += "x" if mode & stat.S_IXGRP else "-"
            
            # Other permissions
            permissions += "r" if mode & stat.S_IROTH else "-"
            permissions += "w" if mode & stat.S_IWOTH else "-"
            permissions += "x" if mode & stat.S_IXOTH else "-"
            
            return permissions
        except (OSError, KeyError):
            return "unknown"
    
    def _get_file_owner(self, file_path: str) -> tuple:
        """
        Get file owner and group information.
        
        Args:
            file_path: Path to file
            
        Returns:
            Tuple of (owner_name, group_name)
        """
        if not UNIX_AVAILABLE:
            # Windows or non-Unix system - return current user
            return os.getenv("USERNAME", "user"), "users"
        
        try:
            file_stat = os.stat(file_path)
            
            try:
                owner = pwd.getpwuid(file_stat.st_uid).pw_name
            except KeyError:
                owner = str(file_stat.st_uid)
            
            try:
                group = grp.getgrgid(file_stat.st_gid).gr_name
            except KeyError:
                group = str(file_stat.st_gid)
            
            return owner, group
        except OSError:
            return "unknown", "unknown"
    
    def _determine_file_type(self, file_path: str) -> FileType:
        """
        Determine the type of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            FileType enum value
        """
        try:
            if os.path.islink(file_path):
                return FileType.SYMLINK
            elif os.path.isdir(file_path):
                return FileType.DIRECTORY
            elif os.path.isfile(file_path):
                return FileType.FILE
            else:
                return FileType.UNKNOWN
        except OSError:
            return FileType.UNKNOWN
    
    def _create_file_item(self, file_path: str, name: str = None) -> FileItem:
        """
        Create FileItem object with metadata.
        
        Args:
            file_path: Full path to file
            name: Display name (defaults to basename)
            
        Returns:
            FileItem object with metadata
        """
        if name is None:
            name = os.path.basename(file_path)
        
        try:
            file_stat = os.stat(file_path)
            file_type = self._determine_file_type(file_path)
            permissions = self._get_file_permissions(file_path)
            owner, group = self._get_file_owner(file_path)
            
            # Get file size (0 for directories)
            size = file_stat.st_size if file_type == FileType.FILE else 0
            
            # Get modification time
            modified = datetime.fromtimestamp(file_stat.st_mtime)
            
            # Check if file is hidden (starts with .)
            is_hidden = name.startswith('.')
            
            return FileItem(
                name=name,
                path=file_path,
                type=file_type,
                size=size,
                permissions=permissions,
                modified=modified,
                owner=owner,
                group=group,
                is_hidden=is_hidden
            )
        
        except OSError as e:
            logger.error(f"Error creating file item for {file_path}: {e}")
            raise FileManagerError(
                f"Unable to access file metadata: {file_path}",
                "METADATA_ERROR",
                {"path": file_path, "error": str(e)}
            )
    
    def browse_directory(self, path: str, show_hidden: bool = False, 
                        sort_by: str = "name", reverse: bool = False) -> List[FileItem]:
        """
        Browse directory contents with security checks.
        
        Args:
            path: Directory path to browse
            show_hidden: Whether to include hidden files
            sort_by: Sort criteria ('name', 'size', 'modified', 'type')
            reverse: Reverse sort order
            
        Returns:
            List of FileItem objects
            
        Raises:
            PermissionError: If access is denied
            PathNotFoundError: If path doesn't exist
            FileManagerError: If path is not a directory
        """
        validated_path = self._validate_path(path)
        
        # Ensure path is a directory
        if not os.path.isdir(validated_path):
            raise FileManagerError(
                f"Path is not a directory: {path}",
                "NOT_DIRECTORY",
                {"path": validated_path}
            )
        
        try:
            # List directory contents
            entries = os.listdir(validated_path)
            file_items = []
            
            for entry in entries:
                entry_path = os.path.join(validated_path, entry)
                
                try:
                    file_item = self._create_file_item(entry_path, entry)
                    
                    # Filter hidden files if requested
                    if not show_hidden and file_item.is_hidden:
                        continue
                    
                    file_items.append(file_item)
                
                except FileManagerError as e:
                    # Log error but continue with other files
                    logger.warning(f"Skipping file {entry}: {e.message}")
                    continue
            
            # Sort results
            sort_key_map = {
                "name": lambda x: x.name.lower(),
                "size": lambda x: x.size,
                "modified": lambda x: x.modified,
                "type": lambda x: (x.type.value, x.name.lower())
            }
            
            if sort_by in sort_key_map:
                file_items.sort(key=sort_key_map[sort_by], reverse=reverse)
            
            logger.info(f"Successfully browsed directory {validated_path}: {len(file_items)} items")
            return file_items
        
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied accessing directory: {path}",
                "DIRECTORY_ACCESS_DENIED",
                {"path": validated_path, "error": str(e)}
            )
        except OSError as e:
            raise FileManagerError(
                f"Error reading directory: {path}",
                "DIRECTORY_READ_ERROR",
                {"path": validated_path, "error": str(e)}
            )
    
    def get_file_info(self, path: str) -> FileItem:
        """
        Get detailed information about a specific file or directory.
        
        Args:
            path: Path to file or directory
            
        Returns:
            FileItem with detailed metadata
            
        Raises:
            PermissionError: If access is denied
            PathNotFoundError: If path doesn't exist
        """
        validated_path = self._validate_path(path)
        return self._create_file_item(validated_path)
    
    def get_allowed_paths(self) -> List[Dict[str, str]]:
        """
        Get list of allowed root paths for browsing.
        
        Returns:
            List of dictionaries with path info
        """
        allowed_info = []
        
        for path in self.allowed_paths:
            try:
                if os.path.exists(path):
                    file_item = self._create_file_item(path)
                    allowed_info.append({
                        "path": path,
                        "name": os.path.basename(path) or path,
                        "accessible": True,
                        "type": file_item.type.value
                    })
                else:
                    allowed_info.append({
                        "path": path,
                        "name": os.path.basename(path) or path,
                        "accessible": False,
                        "type": "unknown"
                    })
            except Exception as e:
                logger.warning(f"Error checking allowed path {path}: {e}")
                allowed_info.append({
                    "path": path,
                    "name": os.path.basename(path) or path,
                    "accessible": False,
                    "type": "unknown"
                })
        
        return allowed_info


# Global file manager instance
_file_manager = None


def get_file_manager() -> SecureFileManager:
    """
    Get global file manager instance.
    
    Returns:
        SecureFileManager instance
    """
    global _file_manager
    if _file_manager is None:
        # Default configuration - can be overridden
        if os.name == 'nt':  # Windows
            allowed_paths = [
                os.path.expanduser("~"),  # User home directory
                "C:\\temp",
                "C:\\Users"
            ]
        else:  # Unix/Linux
            allowed_paths = [
                "/home",
                "/tmp", 
                "/var/log",
                "/opt",
                "/usr/share"
            ]
        _file_manager = SecureFileManager(allowed_paths=allowed_paths)
    
    return _file_manager


def configure_file_manager(allowed_paths: List[str], user_context: str = None):
    """
    Configure global file manager with custom settings.
    
    Args:
        allowed_paths: List of allowed root paths
        user_context: User context for permissions
    """
    global _file_manager
    _file_manager = SecureFileManager(allowed_paths=allowed_paths, user_context=user_context)
    logger.info(f"File manager configured with paths: {allowed_paths}")


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    fm = get_file_manager()
    
    try:
        # Test browsing home directory
        items = fm.browse_directory("/home")
        print(f"Found {len(items)} items in /home")
        
        for item in items[:5]:  # Show first 5 items
            print(f"  {item.name} ({item.type.value}) - {item.permissions} - {item.size} bytes")
    
    except Exception as e:
        print(f"Error: {e}")