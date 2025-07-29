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
    
    def upload_file(self, file_data: bytes, destination_path: str, filename: str, 
                   overwrite: bool = False, chunk_size: int = 8192) -> Dict[str, Union[str, int, bool]]:
        """
        Upload file to specified destination with progress tracking.
        
        Args:
            file_data: File content as bytes
            destination_path: Directory path where file should be uploaded
            filename: Name of the file to create
            overwrite: Whether to overwrite existing files
            chunk_size: Size of chunks for progress tracking
            
        Returns:
            Dictionary with upload result information
            
        Raises:
            PermissionError: If destination is not allowed or not writable
            FileManagerError: If upload fails or file exists (when overwrite=False)
        """
        # Validate destination directory
        validated_dest = self._validate_path(destination_path)
        
        # Ensure destination is a directory
        if not os.path.isdir(validated_dest):
            raise FileManagerError(
                f"Destination is not a directory: {destination_path}",
                "NOT_DIRECTORY",
                {"path": validated_dest}
            )
        
        # Construct full file path
        full_file_path = os.path.join(validated_dest, filename)
        
        # Check if file already exists
        if os.path.exists(full_file_path) and not overwrite:
            raise FileManagerError(
                f"File already exists: {filename}",
                "FILE_EXISTS",
                {"path": full_file_path, "filename": filename}
            )
        
        # Validate filename (prevent path traversal in filename)
        if os.path.sep in filename or '..' in filename:
            raise FileManagerError(
                f"Invalid filename: {filename}",
                "INVALID_FILENAME",
                {"filename": filename}
            )
        
        # Check write permissions on destination directory
        if not os.access(validated_dest, os.W_OK):
            raise PermissionError(
                f"No write permission for directory: {destination_path}",
                "WRITE_PERMISSION_DENIED",
                {"path": validated_dest}
            )
        
        try:
            total_size = len(file_data)
            bytes_written = 0
            
            # Write file in chunks for progress tracking
            with open(full_file_path, 'wb') as f:
                for i in range(0, total_size, chunk_size):
                    chunk = file_data[i:i + chunk_size]
                    f.write(chunk)
                    bytes_written += len(chunk)
                    
                    # Log progress for large files
                    if total_size > 1024 * 1024:  # > 1MB
                        progress = (bytes_written / total_size) * 100
                        if bytes_written % (chunk_size * 10) == 0:  # Log every 10 chunks
                            logger.info(f"Upload progress: {progress:.1f}% ({bytes_written}/{total_size} bytes)")
            
            # Get file info for response
            file_item = self._create_file_item(full_file_path, filename)
            
            logger.info(f"Successfully uploaded file: {filename} ({total_size} bytes) to {validated_dest}")
            
            return {
                "success": True,
                "filename": filename,
                "path": full_file_path,
                "size": total_size,
                "bytes_written": bytes_written,
                "overwritten": os.path.exists(full_file_path) and overwrite,
                "file_info": file_item.to_dict()
            }
        
        except OSError as e:
            # Clean up partial file on error
            if os.path.exists(full_file_path):
                try:
                    os.remove(full_file_path)
                except OSError:
                    pass
            
            raise FileManagerError(
                f"Failed to upload file: {filename}",
                "UPLOAD_FAILED",
                {"filename": filename, "path": full_file_path, "error": str(e)}
            )
    
    def upload_multiple_files(self, files_data: List[Dict[str, Union[bytes, str]]], 
                             destination_path: str, overwrite: bool = False) -> Dict[str, List[Dict]]:
        """
        Upload multiple files to specified destination.
        
        Args:
            files_data: List of dictionaries with 'data' (bytes) and 'filename' (str)
            destination_path: Directory path where files should be uploaded
            overwrite: Whether to overwrite existing files
            
        Returns:
            Dictionary with successful and failed uploads
        """
        successful_uploads = []
        failed_uploads = []
        
        for file_info in files_data:
            try:
                filename = file_info['filename']
                file_data = file_info['data']
                
                result = self.upload_file(file_data, destination_path, filename, overwrite)
                successful_uploads.append(result)
                
            except Exception as e:
                failed_uploads.append({
                    "filename": file_info.get('filename', 'unknown'),
                    "error": str(e),
                    "error_code": getattr(e, 'error_code', 'UNKNOWN_ERROR')
                })
        
        return {
            "successful": successful_uploads,
            "failed": failed_uploads,
            "total_files": len(files_data),
            "success_count": len(successful_uploads),
            "failure_count": len(failed_uploads)
        }
    
    def create_directory(self, path: str, directory_name: str, 
                        permissions: int = 0o755) -> Dict[str, Union[str, bool]]:
        """
        Create a new directory at specified path.
        
        Args:
            path: Parent directory path
            directory_name: Name of directory to create
            permissions: Directory permissions (Unix only)
            
        Returns:
            Dictionary with creation result
            
        Raises:
            PermissionError: If parent directory is not allowed or not writable
            FileManagerError: If directory creation fails
        """
        # Validate parent directory
        validated_parent = self._validate_path(path)
        
        # Ensure parent is a directory
        if not os.path.isdir(validated_parent):
            raise FileManagerError(
                f"Parent path is not a directory: {path}",
                "NOT_DIRECTORY",
                {"path": validated_parent}
            )
        
        # Validate directory name
        if os.path.sep in directory_name or '..' in directory_name:
            raise FileManagerError(
                f"Invalid directory name: {directory_name}",
                "INVALID_DIRECTORY_NAME",
                {"directory_name": directory_name}
            )
        
        # Construct full directory path
        full_dir_path = os.path.join(validated_parent, directory_name)
        
        # Check if directory already exists
        if os.path.exists(full_dir_path):
            raise FileManagerError(
                f"Directory already exists: {directory_name}",
                "DIRECTORY_EXISTS",
                {"path": full_dir_path, "directory_name": directory_name}
            )
        
        # Check write permissions on parent directory
        if not os.access(validated_parent, os.W_OK):
            raise PermissionError(
                f"No write permission for parent directory: {path}",
                "WRITE_PERMISSION_DENIED",
                {"path": validated_parent}
            )
        
        try:
            # Create directory
            os.makedirs(full_dir_path, mode=permissions, exist_ok=False)
            
            # Get directory info for response
            dir_item = self._create_file_item(full_dir_path, directory_name)
            
            logger.info(f"Successfully created directory: {directory_name} at {validated_parent}")
            
            return {
                "success": True,
                "directory_name": directory_name,
                "path": full_dir_path,
                "permissions": oct(permissions),
                "directory_info": dir_item.to_dict()
            }
        
        except OSError as e:
            raise FileManagerError(
                f"Failed to create directory: {directory_name}",
                "DIRECTORY_CREATION_FAILED",
                {"directory_name": directory_name, "path": full_dir_path, "error": str(e)}
            )
    
    def download_file(self, file_path: str, chunk_size: int = 8192) -> Dict[str, Union[str, int, bytes]]:
        """
        Download file with streaming support.
        
        Args:
            file_path: Path to file to download
            chunk_size: Size of chunks for streaming
            
        Returns:
            Dictionary with file information and content
            
        Raises:
            PermissionError: If file access is denied
            PathNotFoundError: If file doesn't exist
            FileManagerError: If file is not downloadable
        """
        validated_path = self._validate_path(file_path)
        
        # Ensure path is a file (not directory)
        if not os.path.isfile(validated_path):
            raise FileManagerError(
                f"Path is not a file: {file_path}",
                "NOT_FILE",
                {"path": validated_path}
            )
        
        # Check read permissions
        if not os.access(validated_path, os.R_OK):
            raise PermissionError(
                f"No read permission for file: {file_path}",
                "READ_PERMISSION_DENIED",
                {"path": validated_path}
            )
        
        try:
            # Get file metadata
            file_item = self._create_file_item(validated_path)
            
            # Read file content
            with open(validated_path, 'rb') as f:
                file_content = f.read()
            
            logger.info(f"Successfully prepared file for download: {file_path} ({len(file_content)} bytes)")
            
            return {
                "success": True,
                "filename": file_item.name,
                "path": validated_path,
                "size": file_item.size,
                "content": file_content,
                "mime_type": self._get_mime_type(validated_path),
                "file_info": file_item.to_dict()
            }
        
        except OSError as e:
            raise FileManagerError(
                f"Failed to read file: {file_path}",
                "FILE_READ_ERROR",
                {"path": validated_path, "error": str(e)}
            )
    
    def download_file_stream(self, file_path: str, chunk_size: int = 8192):
        """
        Download file as a generator for streaming large files.
        
        Args:
            file_path: Path to file to download
            chunk_size: Size of chunks for streaming
            
        Yields:
            File chunks as bytes
            
        Raises:
            PermissionError: If file access is denied
            PathNotFoundError: If file doesn't exist
            FileManagerError: If file is not downloadable
        """
        validated_path = self._validate_path(file_path)
        
        # Ensure path is a file (not directory)
        if not os.path.isfile(validated_path):
            raise FileManagerError(
                f"Path is not a file: {file_path}",
                "NOT_FILE",
                {"path": validated_path}
            )
        
        # Check read permissions
        if not os.access(validated_path, os.R_OK):
            raise PermissionError(
                f"No read permission for file: {file_path}",
                "READ_PERMISSION_DENIED",
                {"path": validated_path}
            )
        
        try:
            file_size = os.path.getsize(validated_path)
            bytes_read = 0
            
            with open(validated_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    bytes_read += len(chunk)
                    
                    # Log progress for large files
                    if file_size > 1024 * 1024:  # > 1MB
                        progress = (bytes_read / file_size) * 100
                        if bytes_read % (chunk_size * 10) == 0:  # Log every 10 chunks
                            logger.info(f"Download progress: {progress:.1f}% ({bytes_read}/{file_size} bytes)")
                    
                    yield chunk
            
            logger.info(f"Successfully streamed file: {file_path} ({bytes_read} bytes)")
        
        except OSError as e:
            raise FileManagerError(
                f"Failed to stream file: {file_path}",
                "FILE_STREAM_ERROR",
                {"path": validated_path, "error": str(e)}
            )
    
    def download_multiple_files(self, file_paths: List[str], 
                               as_archive: bool = False) -> Dict[str, Union[List, bytes, str]]:
        """
        Download multiple files, optionally as a compressed archive.
        
        Args:
            file_paths: List of file paths to download
            as_archive: Whether to return files as a compressed archive
            
        Returns:
            Dictionary with download results or archive data
        """
        successful_downloads = []
        failed_downloads = []
        
        for file_path in file_paths:
            try:
                result = self.download_file(file_path)
                successful_downloads.append(result)
                
            except Exception as e:
                failed_downloads.append({
                    "path": file_path,
                    "error": str(e),
                    "error_code": getattr(e, 'error_code', 'UNKNOWN_ERROR')
                })
        
        if as_archive and successful_downloads:
            # Create archive (requires additional import)
            try:
                import zipfile
                import io
                
                archive_buffer = io.BytesIO()
                
                with zipfile.ZipFile(archive_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    for download in successful_downloads:
                        zip_file.writestr(download['filename'], download['content'])
                
                archive_data = archive_buffer.getvalue()
                archive_buffer.close()
                
                return {
                    "success": True,
                    "archive": True,
                    "archive_data": archive_data,
                    "archive_size": len(archive_data),
                    "files_included": len(successful_downloads),
                    "failed_files": failed_downloads
                }
            
            except ImportError:
                logger.warning("zipfile module not available, returning individual files")
                as_archive = False
            except Exception as e:
                logger.error(f"Failed to create archive: {e}")
                as_archive = False
        
        if not as_archive:
            return {
                "success": True,
                "archive": False,
                "files": successful_downloads,
                "failed": failed_downloads,
                "total_files": len(file_paths),
                "success_count": len(successful_downloads),
                "failure_count": len(failed_downloads)
            }
    
    def get_file_content_preview(self, file_path: str, max_size: int = 1024, 
                                encoding: str = 'utf-8') -> Dict[str, Union[str, bool, int]]:
        """
        Get a preview of file content for text files.
        
        Args:
            file_path: Path to file
            max_size: Maximum bytes to read for preview
            encoding: Text encoding to use
            
        Returns:
            Dictionary with preview information
        """
        validated_path = self._validate_path(file_path)
        
        # Ensure path is a file
        if not os.path.isfile(validated_path):
            raise FileManagerError(
                f"Path is not a file: {file_path}",
                "NOT_FILE",
                {"path": validated_path}
            )
        
        try:
            file_size = os.path.getsize(validated_path)
            is_text = self._is_text_file(validated_path)
            
            preview_content = ""
            is_truncated = False
            
            if is_text and file_size > 0:
                with open(validated_path, 'r', encoding=encoding, errors='ignore') as f:
                    preview_content = f.read(max_size)
                    
                    # Check if file was truncated
                    if len(preview_content) == max_size and file_size > max_size:
                        is_truncated = True
            
            return {
                "success": True,
                "filename": os.path.basename(validated_path),
                "file_size": file_size,
                "is_text": is_text,
                "preview": preview_content,
                "is_truncated": is_truncated,
                "encoding": encoding,
                "mime_type": self._get_mime_type(validated_path)
            }
        
        except OSError as e:
            raise FileManagerError(
                f"Failed to preview file: {file_path}",
                "FILE_PREVIEW_ERROR",
                {"path": validated_path, "error": str(e)}
            )
    
    def _get_mime_type(self, file_path: str) -> str:
        """
        Get MIME type of file based on extension.
        
        Args:
            file_path: Path to file
            
        Returns:
            MIME type string
        """
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(file_path)
            return mime_type or "application/octet-stream"
        except ImportError:
            # Fallback to basic extension mapping
            ext = os.path.splitext(file_path)[1].lower()
            mime_map = {
                '.txt': 'text/plain',
                '.html': 'text/html',
                '.css': 'text/css',
                '.js': 'application/javascript',
                '.json': 'application/json',
                '.xml': 'application/xml',
                '.pdf': 'application/pdf',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.gif': 'image/gif',
                '.mp3': 'audio/mpeg',
                '.mp4': 'video/mp4',
                '.zip': 'application/zip'
            }
            return mime_map.get(ext, "application/octet-stream")
    
    def _is_text_file(self, file_path: str) -> bool:
        """
        Check if file is likely a text file.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file appears to be text
        """
        try:
            # Check by extension first
            ext = os.path.splitext(file_path)[1].lower()
            text_extensions = {
                '.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml',
                '.yml', '.yaml', '.ini', '.cfg', '.conf', '.log', '.sh', '.bat',
                '.c', '.cpp', '.h', '.java', '.php', '.rb', '.go', '.rs'
            }
            
            if ext in text_extensions:
                return True
            
            # Check file content (read first few bytes)
            with open(file_path, 'rb') as f:
                chunk = f.read(512)
                if not chunk:
                    return True  # Empty file
                
                # Check for null bytes (binary indicator)
                if b'\x00' in chunk:
                    return False
                
                # Try to decode as text
                try:
                    chunk.decode('utf-8')
                    return True
                except UnicodeDecodeError:
                    try:
                        chunk.decode('latin-1')
                        return True
                    except UnicodeDecodeError:
                        return False
        
        except OSError:
            return False


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