from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Union, List, Dict, Any
import logging
from datetime import datetime, timedelta
import os
import jwt
from security import SecureCommandExecutor
from monitoring import monitor
from file_manager import get_file_manager, FileManagerError, PermissionError as FilePermissionError
from desktop_controller import get_desktop_controller, DesktopControllerError
from media_controller import get_media_controller, MediaControllerError
from voice_processor import get_voice_processor, VoiceProcessorError
from remote_desktop import get_remote_desktop_controller, RemoteDesktopError
from automation_engine import get_automation_engine, AutomationError
from package_manager import get_package_manager, PackageManagerError
from security import get_user_manager, get_rbac, get_activity_logger, SecurityError, UserRole

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('audit.log'),
        logging.StreamHandler()
    ]
)

app = FastAPI(
    title="LinuxLink API",
    version="0.1.0",
    description="Secure remote Linux administration API"
)

# CORS middleware for mobile app
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-this")
executor = SecureCommandExecutor(safe_mode=os.getenv("SAFE_MODE", "true").lower() == "true")

class LoginRequest(BaseModel):
    username: str
    password: str

class CommandRequest(BaseModel):
    cmd: str
    timeout: int = 30

# File Management Models
class BrowseRequest(BaseModel):
    path: str
    show_hidden: bool = False
    sort_by: str = "name"
    reverse: bool = False

class UploadRequest(BaseModel):
    destination_path: str
    filename: str
    overwrite: bool = False

class FileOperationRequest(BaseModel):
    file_path: str

class RenameRequest(BaseModel):
    old_path: str
    new_name: str

class CopyRequest(BaseModel):
    source_path: str
    destination_path: str
    new_name: str = None
    overwrite: bool = False

class MoveRequest(BaseModel):
    source_path: str
    destination_path: str
    new_name: str = None
    overwrite: bool = False

class DeleteRequest(BaseModel):
    file_path: str
    force: bool = False

class CreateDirectoryRequest(BaseModel):
    path: str
    directory_name: str
    permissions: int = 0o755

class MultipleFilesRequest(BaseModel):
    file_paths: list[str]
    as_archive: bool = False

class PreviewRequest(BaseModel):
    file_path: str
    max_size: int = 1024
    encoding: str = "utf-8"

# Desktop Control Models
class WorkspaceSwitchRequest(BaseModel):
    workspace_id: Union[int, str]

class WindowFocusRequest(BaseModel):
    window_id: Union[int, str]

class WindowCloseRequest(BaseModel):
    window_id: Union[int, str]

class WindowMoveRequest(BaseModel):
    window_id: Union[int, str]
    x: int
    y: int

class WindowResizeRequest(BaseModel):
    window_id: Union[int, str]
    width: int
    height: int

class WindowToWorkspaceRequest(BaseModel):
    window_id: Union[int, str]
    workspace_id: Union[int, str]

class WallpaperRequest(BaseModel):
    image_path: str
    monitor: str = None

class FullscreenRequest(BaseModel):
    window_id: Union[int, str] = None

# Media Control Models
class MediaPlayerRequest(BaseModel):
    player: str = None

class VolumeRequest(BaseModel):
    volume: float
    player: str = None

class ClipboardTextRequest(BaseModel):
    text: str

class ClipboardImageRequest(BaseModel):
    image_data: str  # base64 encoded
    image_type: str = "image/png"

class ClipboardSyncRequest(BaseModel):
    text_content: str = None
    image_content: str = None  # base64 encoded
    image_type: str = None

class AudioDeviceRequest(BaseModel):
    device_id: str
    device_type: str = "output"

# Voice Command Models
class VoiceCommandRequest(BaseModel):
    text: str

class CustomCommandRequest(BaseModel):
    trigger: str
    actions: List[str]
    description: str
    parameters: Dict[str, Any] = {}
    category: str = "custom"

class CustomCommandUpdateRequest(BaseModel):
    trigger: str
    actions: List[str] = None
    description: str = None
    parameters: Dict[str, Any] = None

class CommandSearchRequest(BaseModel):
    query: str
    include_builtin: bool = True
    include_custom: bool = True

class CommandImportRequest(BaseModel):
    json_data: str
    overwrite: bool = False

# Remote Desktop Models
class VNCSessionRequest(BaseModel):
    width: int = 1920
    height: int = 1080
    depth: int = 24
    password: str = None

class WaylandShareRequest(BaseModel):
    output_name: str = None
    format: str = "webm"

class InputSimulationRequest(BaseModel):
    input_type: str
    data: Dict[str, Any]
    display: str = None

class ApplicationLaunchRequest(BaseModel):
    application: str
    display: str = None

# Automation Models
class MacroCreateRequest(BaseModel):
    macro_id: str
    name: str
    description: str
    actions: List[Dict[str, Any]]

class MacroExecuteRequest(BaseModel):
    macro_id: str
    variables: Dict[str, Any] = {}

class TaskScheduleRequest(BaseModel):
    task_id: str
    macro_id: str
    schedule_expr: str
    variables: Dict[str, Any] = {}

# Package Management Models
class PackageSearchRequest(BaseModel):
    query: str
    include_aur: bool = True
    search_type: str = "name_desc"
    limit: int = 50

class AdvancedSearchRequest(BaseModel):
    filters: Dict[str, Any]

class PackageInstallRequest(BaseModel):
    package_names: List[str]
    from_aur: bool = False
    no_confirm: bool = False

class PackageRemoveRequest(BaseModel):
    package_names: List[str]
    no_confirm: bool = False
    cascade: bool = False

class SystemUpgradeRequest(BaseModel):
    include_aur: bool = True
    no_confirm: bool = False

class FileSearchRequest(BaseModel):
    file_path: str

class DependencySearchRequest(BaseModel):
    package_name: str
    reverse: bool = False

# Device Management Models
class DeviceRegistrationRequest(BaseModel):
    device_name: str
    device_type: str
    platform: str
    app_version: str
    device_info: Dict[str, Any] = {}

class DeviceUpdateRequest(BaseModel):
    device_name: str = None
    enabled: bool = None
    trusted: bool = None

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# File Management Endpoints

@app.post("/files/browse")
async def browse_directory(request: BrowseRequest, user=Depends(verify_token)):
    """Browse directory contents with security checks."""
    try:
        fm = get_file_manager()
        items = fm.browse_directory(
            path=request.path,
            show_hidden=request.show_hidden,
            sort_by=request.sort_by,
            reverse=request.reverse
        )
        
        # Convert FileItem objects to dictionaries
        items_dict = [item.to_dict() for item in items]
        
        logging.info(f"BROWSE_SUCCESS: user={user['sub']}, path='{request.path}', items={len(items_dict)}")
        return {
            "success": True,
            "path": request.path,
            "items": items_dict,
            "count": len(items_dict)
        }
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"BROWSE_ERROR: user={user['sub']}, path='{request.path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"BROWSE_CRITICAL: user={user['sub']}, path='{request.path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to browse directory")

@app.post("/files/upload")
async def upload_file(request: UploadRequest, user=Depends(verify_token)):
    """Upload file to specified destination."""
    # Note: In a real implementation, this would handle multipart file upload
    # For now, this is a placeholder that would work with base64 encoded data
    try:
        fm = get_file_manager()
        
        # This is a simplified version - in practice, you'd handle multipart upload
        # For demonstration, we'll create a simple text file
        file_data = b"Uploaded file content placeholder"
        
        result = fm.upload_file(
            file_data=file_data,
            destination_path=request.destination_path,
            filename=request.filename,
            overwrite=request.overwrite
        )
        
        logging.info(f"UPLOAD_SUCCESS: user={user['sub']}, file='{request.filename}', size={result['size']}")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"UPLOAD_ERROR: user={user['sub']}, file='{request.filename}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"UPLOAD_CRITICAL: user={user['sub']}, file='{request.filename}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to upload file")

@app.get("/files/download/{file_path:path}")
async def download_file(file_path: str, user=Depends(verify_token)):
    """Download file from specified path."""
    try:
        fm = get_file_manager()
        result = fm.download_file(file_path)
        
        logging.info(f"DOWNLOAD_SUCCESS: user={user['sub']}, file='{file_path}', size={result['size']}")
        
        # In a real implementation, you'd return a streaming response
        # For now, return file info and base64 encoded content
        import base64
        return {
            "success": True,
            "filename": result['filename'],
            "size": result['size'],
            "mime_type": result['mime_type'],
            "content_base64": base64.b64encode(result['content']).decode('utf-8'),
            "file_info": result['file_info']
        }
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"DOWNLOAD_ERROR: user={user['sub']}, file='{file_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"DOWNLOAD_CRITICAL: user={user['sub']}, file='{file_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to download file")

@app.post("/files/operations/rename")
async def rename_file(request: RenameRequest, user=Depends(verify_token)):
    """Rename a file or directory."""
    try:
        fm = get_file_manager()
        result = fm.rename_file(request.old_path, request.new_name)
        
        logging.info(f"RENAME_SUCCESS: user={user['sub']}, old='{request.old_path}', new='{request.new_name}'")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"RENAME_ERROR: user={user['sub']}, old='{request.old_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"RENAME_CRITICAL: user={user['sub']}, old='{request.old_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to rename file")

@app.post("/files/operations/copy")
async def copy_file(request: CopyRequest, user=Depends(verify_token)):
    """Copy a file or directory."""
    try:
        fm = get_file_manager()
        result = fm.copy_file(
            source_path=request.source_path,
            destination_path=request.destination_path,
            new_name=request.new_name,
            overwrite=request.overwrite
        )
        
        logging.info(f"COPY_SUCCESS: user={user['sub']}, src='{request.source_path}', dst='{request.destination_path}'")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"COPY_ERROR: user={user['sub']}, src='{request.source_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"COPY_CRITICAL: user={user['sub']}, src='{request.source_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to copy file")

@app.post("/files/operations/move")
async def move_file(request: MoveRequest, user=Depends(verify_token)):
    """Move a file or directory."""
    try:
        fm = get_file_manager()
        result = fm.move_file(
            source_path=request.source_path,
            destination_path=request.destination_path,
            new_name=request.new_name,
            overwrite=request.overwrite
        )
        
        logging.info(f"MOVE_SUCCESS: user={user['sub']}, src='{request.source_path}', dst='{request.destination_path}'")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"MOVE_ERROR: user={user['sub']}, src='{request.source_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"MOVE_CRITICAL: user={user['sub']}, src='{request.source_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to move file")

@app.post("/files/operations/delete")
async def delete_file(request: DeleteRequest, user=Depends(verify_token)):
    """Delete a file or directory."""
    try:
        fm = get_file_manager()
        result = fm.delete_file(request.file_path, force=request.force)
        
        logging.info(f"DELETE_SUCCESS: user={user['sub']}, path='{request.file_path}', force={request.force}")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"DELETE_ERROR: user={user['sub']}, path='{request.file_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"DELETE_CRITICAL: user={user['sub']}, path='{request.file_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to delete file")

@app.post("/files/operations/create-directory")
async def create_directory(request: CreateDirectoryRequest, user=Depends(verify_token)):
    """Create a new directory."""
    try:
        fm = get_file_manager()
        result = fm.create_directory(
            path=request.path,
            directory_name=request.directory_name,
            permissions=request.permissions
        )
        
        logging.info(f"MKDIR_SUCCESS: user={user['sub']}, path='{request.path}', name='{request.directory_name}'")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"MKDIR_ERROR: user={user['sub']}, path='{request.path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"MKDIR_CRITICAL: user={user['sub']}, path='{request.path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to create directory")

@app.post("/files/download-multiple")
async def download_multiple_files(request: MultipleFilesRequest, user=Depends(verify_token)):
    """Download multiple files, optionally as archive."""
    try:
        fm = get_file_manager()
        result = fm.download_multiple_files(
            file_paths=request.file_paths,
            as_archive=request.as_archive
        )
        
        if result.get('archive'):
            import base64
            result['archive_data_base64'] = base64.b64encode(result['archive_data']).decode('utf-8')
            del result['archive_data']  # Remove binary data
        
        logging.info(f"MULTI_DOWNLOAD_SUCCESS: user={user['sub']}, files={len(request.file_paths)}, archive={request.as_archive}")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"MULTI_DOWNLOAD_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"MULTI_DOWNLOAD_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to download multiple files")

@app.post("/files/preview")
async def preview_file(request: PreviewRequest, user=Depends(verify_token)):
    """Get file content preview."""
    try:
        fm = get_file_manager()
        result = fm.get_file_content_preview(
            file_path=request.file_path,
            max_size=request.max_size,
            encoding=request.encoding
        )
        
        logging.info(f"PREVIEW_SUCCESS: user={user['sub']}, file='{request.file_path}', size={result['file_size']}")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"PREVIEW_ERROR: user={user['sub']}, file='{request.file_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PREVIEW_CRITICAL: user={user['sub']}, file='{request.file_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to preview file")

@app.get("/files/properties/{file_path:path}")
async def get_file_properties(file_path: str, user=Depends(verify_token)):
    """Get detailed file properties."""
    try:
        fm = get_file_manager()
        result = fm.get_file_properties(file_path)
        
        logging.info(f"PROPERTIES_SUCCESS: user={user['sub']}, file='{file_path}'")
        return result
    
    except (FileManagerError, FilePermissionError) as e:
        logging.warning(f"PROPERTIES_ERROR: user={user['sub']}, file='{file_path}', error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PROPERTIES_CRITICAL: user={user['sub']}, file='{file_path}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get file properties")

@app.get("/files/allowed-paths")
async def get_allowed_paths(user=Depends(verify_token)):
    """Get list of allowed root paths for browsing."""
    try:
        fm = get_file_manager()
        result = fm.get_allowed_paths()
        
        logging.info(f"ALLOWED_PATHS_SUCCESS: user={user['sub']}, paths={len(result)}")
        return {
            "success": True,
            "allowed_paths": result
        }
    
    except Exception as e:
        logging.error(f"ALLOWED_PATHS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get allowed paths")

# Desktop Control Endpoints

@app.get("/desktop/info")
async def get_desktop_info(user=Depends(verify_token)):
    """Get desktop environment and window manager information."""
    try:
        dc = get_desktop_controller()
        info = dc.get_window_manager_info()
        
        logging.info(f"DESKTOP_INFO_SUCCESS: user={user['sub']}, wm={info['type']}")
        return {
            "success": True,
            "window_manager": info
        }
    
    except Exception as e:
        logging.error(f"DESKTOP_INFO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get desktop info")

@app.get("/desktop/workspaces")
async def get_workspaces(user=Depends(verify_token)):
    """Get list of workspaces and their windows."""
    try:
        dc = get_desktop_controller()
        workspaces = dc.get_workspaces()
        
        # Convert to dictionaries
        workspaces_dict = [workspace.to_dict() for workspace in workspaces]
        
        logging.info(f"WORKSPACES_SUCCESS: user={user['sub']}, count={len(workspaces_dict)}")
        return {
            "success": True,
            "workspaces": workspaces_dict,
            "count": len(workspaces_dict)
        }
    
    except DesktopControllerError as e:
        logging.warning(f"WORKSPACES_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WORKSPACES_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get workspaces")

@app.post("/desktop/workspace")
async def switch_workspace(request: WorkspaceSwitchRequest, user=Depends(verify_token)):
    """Switch to specified workspace."""
    try:
        dc = get_desktop_controller()
        success = dc.switch_workspace(request.workspace_id)
        
        if success:
            logging.info(f"WORKSPACE_SWITCH_SUCCESS: user={user['sub']}, workspace={request.workspace_id}")
            return {
                "success": True,
                "workspace_id": request.workspace_id,
                "message": f"Switched to workspace {request.workspace_id}"
            }
        else:
            logging.warning(f"WORKSPACE_SWITCH_FAILED: user={user['sub']}, workspace={request.workspace_id}")
            raise HTTPException(status_code=400, detail="Failed to switch workspace")
    
    except DesktopControllerError as e:
        logging.warning(f"WORKSPACE_SWITCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WORKSPACE_SWITCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to switch workspace")

@app.get("/desktop/windows")
async def get_windows(user=Depends(verify_token)):
    """Get list of all windows."""
    try:
        dc = get_desktop_controller()
        windows = dc.get_windows()
        
        # Convert to dictionaries
        windows_dict = [window.to_dict() for window in windows]
        
        logging.info(f"WINDOWS_SUCCESS: user={user['sub']}, count={len(windows_dict)}")
        return {
            "success": True,
            "windows": windows_dict,
            "count": len(windows_dict)
        }
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOWS_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOWS_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get windows")

@app.post("/desktop/window/focus")
async def focus_window(request: WindowFocusRequest, user=Depends(verify_token)):
    """Focus specified window."""
    try:
        dc = get_desktop_controller()
        success = dc.focus_window(request.window_id)
        
        if success:
            logging.info(f"WINDOW_FOCUS_SUCCESS: user={user['sub']}, window={request.window_id}")
            return {
                "success": True,
                "window_id": request.window_id,
                "message": f"Focused window {request.window_id}"
            }
        else:
            logging.warning(f"WINDOW_FOCUS_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to focus window")
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOW_FOCUS_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOW_FOCUS_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to focus window")

@app.post("/desktop/window/close")
async def close_window(request: WindowCloseRequest, user=Depends(verify_token)):
    """Close specified window."""
    try:
        dc = get_desktop_controller()
        success = dc.close_window(request.window_id)
        
        if success:
            logging.info(f"WINDOW_CLOSE_SUCCESS: user={user['sub']}, window={request.window_id}")
            return {
                "success": True,
                "window_id": request.window_id,
                "message": f"Closed window {request.window_id}"
            }
        else:
            logging.warning(f"WINDOW_CLOSE_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to close window")
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOW_CLOSE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOW_CLOSE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to close window")

@app.post("/desktop/window/move")
async def move_window(request: WindowMoveRequest, user=Depends(verify_token)):
    """Move window to specified position."""
    try:
        dc = get_desktop_controller()
        success = dc.adapter.move_window(request.window_id, request.x, request.y)
        
        if success:
            logging.info(f"WINDOW_MOVE_SUCCESS: user={user['sub']}, window={request.window_id}, pos=({request.x},{request.y})")
            return {
                "success": True,
                "window_id": request.window_id,
                "x": request.x,
                "y": request.y,
                "message": f"Moved window {request.window_id} to ({request.x}, {request.y})"
            }
        else:
            logging.warning(f"WINDOW_MOVE_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to move window")
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOW_MOVE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOW_MOVE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to move window")

@app.post("/desktop/window/resize")
async def resize_window(request: WindowResizeRequest, user=Depends(verify_token)):
    """Resize window to specified dimensions."""
    try:
        dc = get_desktop_controller()
        success = dc.adapter.resize_window(request.window_id, request.width, request.height)
        
        if success:
            logging.info(f"WINDOW_RESIZE_SUCCESS: user={user['sub']}, window={request.window_id}, size=({request.width}x{request.height})")
            return {
                "success": True,
                "window_id": request.window_id,
                "width": request.width,
                "height": request.height,
                "message": f"Resized window {request.window_id} to {request.width}x{request.height}"
            }
        else:
            logging.warning(f"WINDOW_RESIZE_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to resize window")
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOW_RESIZE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOW_RESIZE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to resize window")

@app.post("/desktop/window/to-workspace")
async def move_window_to_workspace(request: WindowToWorkspaceRequest, user=Depends(verify_token)):
    """Move window to specified workspace."""
    try:
        dc = get_desktop_controller()
        
        # Check if adapter supports this operation
        if hasattr(dc.adapter, 'move_window_to_workspace'):
            success = dc.adapter.move_window_to_workspace(request.window_id, request.workspace_id)
        else:
            logging.warning(f"WINDOW_TO_WORKSPACE_UNSUPPORTED: user={user['sub']}, wm={dc.wm_type.value}")
            raise HTTPException(status_code=400, detail="Window to workspace operation not supported by current window manager")
        
        if success:
            logging.info(f"WINDOW_TO_WORKSPACE_SUCCESS: user={user['sub']}, window={request.window_id}, workspace={request.workspace_id}")
            return {
                "success": True,
                "window_id": request.window_id,
                "workspace_id": request.workspace_id,
                "message": f"Moved window {request.window_id} to workspace {request.workspace_id}"
            }
        else:
            logging.warning(f"WINDOW_TO_WORKSPACE_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to move window to workspace")
    
    except DesktopControllerError as e:
        logging.warning(f"WINDOW_TO_WORKSPACE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WINDOW_TO_WORKSPACE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to move window to workspace")

@app.post("/desktop/fullscreen")
async def toggle_fullscreen(request: FullscreenRequest, user=Depends(verify_token)):
    """Toggle fullscreen for window."""
    try:
        dc = get_desktop_controller()
        
        # Check if adapter supports this operation
        if hasattr(dc.adapter, 'toggle_fullscreen'):
            success = dc.adapter.toggle_fullscreen(request.window_id)
        else:
            logging.warning(f"FULLSCREEN_UNSUPPORTED: user={user['sub']}, wm={dc.wm_type.value}")
            raise HTTPException(status_code=400, detail="Fullscreen toggle not supported by current window manager")
        
        if success:
            logging.info(f"FULLSCREEN_SUCCESS: user={user['sub']}, window={request.window_id or 'active'}")
            return {
                "success": True,
                "window_id": request.window_id,
                "message": f"Toggled fullscreen for window {request.window_id or 'active'}"
            }
        else:
            logging.warning(f"FULLSCREEN_FAILED: user={user['sub']}, window={request.window_id}")
            raise HTTPException(status_code=400, detail="Failed to toggle fullscreen")
    
    except DesktopControllerError as e:
        logging.warning(f"FULLSCREEN_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"FULLSCREEN_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to toggle fullscreen")

@app.post("/desktop/wallpaper")
async def set_wallpaper(request: WallpaperRequest, user=Depends(verify_token)):
    """Set desktop wallpaper."""
    try:
        dc = get_desktop_controller()
        
        # Check if adapter supports this operation
        if hasattr(dc.adapter, 'set_wallpaper'):
            success = dc.adapter.set_wallpaper(request.image_path, request.monitor)
        else:
            logging.warning(f"WALLPAPER_UNSUPPORTED: user={user['sub']}, wm={dc.wm_type.value}")
            raise HTTPException(status_code=400, detail="Wallpaper setting not supported by current window manager")
        
        if success:
            logging.info(f"WALLPAPER_SUCCESS: user={user['sub']}, image='{request.image_path}', monitor={request.monitor}")
            return {
                "success": True,
                "image_path": request.image_path,
                "monitor": request.monitor,
                "message": f"Set wallpaper to {request.image_path}"
            }
        else:
            logging.warning(f"WALLPAPER_FAILED: user={user['sub']}, image='{request.image_path}'")
            raise HTTPException(status_code=400, detail="Failed to set wallpaper")
    
    except DesktopControllerError as e:
        logging.warning(f"WALLPAPER_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WALLPAPER_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set wallpaper")

@app.get("/desktop/monitors")
async def get_monitors(user=Depends(verify_token)):
    """Get list of monitors/displays."""
    try:
        dc = get_desktop_controller()
        monitors = dc.get_monitors()
        
        # Convert to dictionaries
        monitors_dict = [monitor.to_dict() for monitor in monitors]
        
        logging.info(f"MONITORS_SUCCESS: user={user['sub']}, count={len(monitors_dict)}")
        return {
            "success": True,
            "monitors": monitors_dict,
            "count": len(monitors_dict)
        }
    
    except DesktopControllerError as e:
        logging.warning(f"MONITORS_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"MONITORS_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get monitors")

@app.get("/desktop/notifications")
async def get_notifications(user=Depends(verify_token)):
    """Get system notifications (placeholder for future implementation)."""
    try:
        # This is a placeholder - actual implementation would integrate with
        # notification daemons like dunst, mako, or desktop environment notifications
        logging.info(f"NOTIFICATIONS_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "notifications": [],
            "count": 0,
            "message": "Notification integration not yet implemented"
        }
    
    except Exception as e:
        logging.error(f"NOTIFICATIONS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get notifications")

# Media Control Endpoints

@app.get("/media/status")
async def get_media_status(user=Depends(verify_token)):
    """Get current media status and available players."""
    try:
        mc = get_media_controller()
        status = mc.get_comprehensive_status()
        
        logging.info(f"MEDIA_STATUS_SUCCESS: user={user['sub']}, players={len(status['available_players'])}")
        return {
            "success": True,
            "status": status
        }
    
    except Exception as e:
        logging.error(f"MEDIA_STATUS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get media status")

@app.post("/media/control/play-pause")
async def media_play_pause(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Toggle play/pause for media player."""
    try:
        mc = get_media_controller()
        success = mc.play_pause(request.player)
        
        if success:
            logging.info(f"MEDIA_PLAY_PAUSE_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Play/pause toggled"
            }
        else:
            logging.warning(f"MEDIA_PLAY_PAUSE_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to toggle play/pause")
    
    except Exception as e:
        logging.error(f"MEDIA_PLAY_PAUSE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to control media playback")

@app.post("/media/control/play")
async def media_play(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Play media."""
    try:
        mc = get_media_controller()
        success = mc.play(request.player)
        
        if success:
            logging.info(f"MEDIA_PLAY_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Media playing"
            }
        else:
            logging.warning(f"MEDIA_PLAY_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to play media")
    
    except Exception as e:
        logging.error(f"MEDIA_PLAY_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to play media")

@app.post("/media/control/pause")
async def media_pause(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Pause media."""
    try:
        mc = get_media_controller()
        success = mc.pause(request.player)
        
        if success:
            logging.info(f"MEDIA_PAUSE_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Media paused"
            }
        else:
            logging.warning(f"MEDIA_PAUSE_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to pause media")
    
    except Exception as e:
        logging.error(f"MEDIA_PAUSE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to pause media")

@app.post("/media/control/stop")
async def media_stop(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Stop media."""
    try:
        mc = get_media_controller()
        success = mc.stop(request.player)
        
        if success:
            logging.info(f"MEDIA_STOP_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Media stopped"
            }
        else:
            logging.warning(f"MEDIA_STOP_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to stop media")
    
    except Exception as e:
        logging.error(f"MEDIA_STOP_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to stop media")

@app.post("/media/control/next")
async def media_next(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Skip to next track."""
    try:
        mc = get_media_controller()
        success = mc.next_track(request.player)
        
        if success:
            logging.info(f"MEDIA_NEXT_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Skipped to next track"
            }
        else:
            logging.warning(f"MEDIA_NEXT_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to skip to next track")
    
    except Exception as e:
        logging.error(f"MEDIA_NEXT_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to skip track")

@app.post("/media/control/previous")
async def media_previous(request: MediaPlayerRequest, user=Depends(verify_token)):
    """Skip to previous track."""
    try:
        mc = get_media_controller()
        success = mc.previous_track(request.player)
        
        if success:
            logging.info(f"MEDIA_PREVIOUS_SUCCESS: user={user['sub']}, player={request.player}")
            return {
                "success": True,
                "player": request.player or mc.get_active_player(),
                "message": "Skipped to previous track"
            }
        else:
            logging.warning(f"MEDIA_PREVIOUS_FAILED: user={user['sub']}, player={request.player}")
            raise HTTPException(status_code=400, detail="Failed to skip to previous track")
    
    except Exception as e:
        logging.error(f"MEDIA_PREVIOUS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to skip track")

@app.post("/media/volume/player")
async def set_player_volume(request: VolumeRequest, user=Depends(verify_token)):
    """Set volume for media player."""
    try:
        mc = get_media_controller()
        success = mc.set_player_volume(request.volume, request.player)
        
        if success:
            logging.info(f"PLAYER_VOLUME_SUCCESS: user={user['sub']}, volume={request.volume}, player={request.player}")
            return {
                "success": True,
                "volume": request.volume,
                "player": request.player or mc.get_active_player(),
                "message": f"Player volume set to {request.volume}"
            }
        else:
            logging.warning(f"PLAYER_VOLUME_FAILED: user={user['sub']}, volume={request.volume}")
            raise HTTPException(status_code=400, detail="Failed to set player volume")
    
    except Exception as e:
        logging.error(f"PLAYER_VOLUME_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set player volume")

@app.post("/media/volume/system")
async def set_system_volume(request: VolumeRequest, user=Depends(verify_token)):
    """Set system volume."""
    try:
        mc = get_media_controller()
        success = mc.set_system_volume(request.volume)
        
        if success:
            logging.info(f"SYSTEM_VOLUME_SUCCESS: user={user['sub']}, volume={request.volume}")
            return {
                "success": True,
                "volume": request.volume,
                "message": f"System volume set to {request.volume}"
            }
        else:
            logging.warning(f"SYSTEM_VOLUME_FAILED: user={user['sub']}, volume={request.volume}")
            raise HTTPException(status_code=400, detail="Failed to set system volume")
    
    except Exception as e:
        logging.error(f"SYSTEM_VOLUME_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set system volume")

@app.post("/media/volume/mute")
async def toggle_system_mute(user=Depends(verify_token)):
    """Toggle system audio mute."""
    try:
        mc = get_media_controller()
        success = mc.toggle_system_mute()
        
        if success:
            muted = mc.is_system_muted()
            logging.info(f"SYSTEM_MUTE_SUCCESS: user={user['sub']}, muted={muted}")
            return {
                "success": True,
                "muted": muted,
                "message": f"System audio {'muted' if muted else 'unmuted'}"
            }
        else:
            logging.warning(f"SYSTEM_MUTE_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to toggle system mute")
    
    except Exception as e:
        logging.error(f"SYSTEM_MUTE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to toggle system mute")

@app.get("/media/audio/devices")
async def get_audio_devices(user=Depends(verify_token)):
    """Get available audio devices."""
    try:
        mc = get_media_controller()
        devices = mc.get_audio_devices()
        
        logging.info(f"AUDIO_DEVICES_SUCCESS: user={user['sub']}, count={len(devices)}")
        return {
            "success": True,
            "devices": devices,
            "count": len(devices)
        }
    
    except Exception as e:
        logging.error(f"AUDIO_DEVICES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get audio devices")

@app.post("/media/audio/default-device")
async def set_default_audio_device(request: AudioDeviceRequest, user=Depends(verify_token)):
    """Set default audio device."""
    try:
        mc = get_media_controller()
        success = mc.set_default_audio_device(request.device_id, request.device_type)
        
        if success:
            logging.info(f"DEFAULT_DEVICE_SUCCESS: user={user['sub']}, device={request.device_id}, type={request.device_type}")
            return {
                "success": True,
                "device_id": request.device_id,
                "device_type": request.device_type,
                "message": f"Default {request.device_type} device set"
            }
        else:
            logging.warning(f"DEFAULT_DEVICE_FAILED: user={user['sub']}, device={request.device_id}")
            raise HTTPException(status_code=400, detail="Failed to set default audio device")
    
    except Exception as e:
        logging.error(f"DEFAULT_DEVICE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set default audio device")

@app.get("/clipboard")
async def get_clipboard_content(user=Depends(verify_token)):
    """Get clipboard content."""
    try:
        mc = get_media_controller()
        clipboard_data = mc.sync_clipboard_to_mobile()
        
        logging.info(f"CLIPBOARD_GET_SUCCESS: user={user['sub']}, has_text={clipboard_data['has_text']}, has_image={clipboard_data['has_image']}")
        return {
            "success": True,
            "clipboard": clipboard_data
        }
    
    except Exception as e:
        logging.error(f"CLIPBOARD_GET_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get clipboard content")

@app.post("/clipboard/text")
async def set_clipboard_text(request: ClipboardTextRequest, user=Depends(verify_token)):
    """Set text to clipboard."""
    try:
        mc = get_media_controller()
        success = mc.set_clipboard_text(request.text)
        
        if success:
            logging.info(f"CLIPBOARD_TEXT_SUCCESS: user={user['sub']}, length={len(request.text)}")
            return {
                "success": True,
                "text_length": len(request.text),
                "message": "Text set to clipboard"
            }
        else:
            logging.warning(f"CLIPBOARD_TEXT_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to set clipboard text")
    
    except Exception as e:
        logging.error(f"CLIPBOARD_TEXT_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set clipboard text")

@app.post("/clipboard/image")
async def set_clipboard_image(request: ClipboardImageRequest, user=Depends(verify_token)):
    """Set image to clipboard."""
    try:
        mc = get_media_controller()
        
        # Decode base64 image data
        import base64
        image_data = base64.b64decode(request.image_data)
        
        success = mc.set_clipboard_image(image_data, request.image_type)
        
        if success:
            logging.info(f"CLIPBOARD_IMAGE_SUCCESS: user={user['sub']}, size={len(image_data)}, type={request.image_type}")
            return {
                "success": True,
                "image_size": len(image_data),
                "image_type": request.image_type,
                "message": "Image set to clipboard"
            }
        else:
            logging.warning(f"CLIPBOARD_IMAGE_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to set clipboard image")
    
    except Exception as e:
        logging.error(f"CLIPBOARD_IMAGE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to set clipboard image")

@app.post("/clipboard/sync")
async def sync_clipboard_from_mobile(request: ClipboardSyncRequest, user=Depends(verify_token)):
    """Sync clipboard content from mobile device."""
    try:
        mc = get_media_controller()
        
        mobile_data = {
            'text_content': request.text_content,
            'image_content': request.image_content,
            'image_type': request.image_type
        }
        
        success = mc.sync_clipboard_from_mobile(mobile_data)
        
        if success:
            content_type = 'text' if request.text_content else 'image' if request.image_content else 'none'
            logging.info(f"CLIPBOARD_SYNC_SUCCESS: user={user['sub']}, type={content_type}")
            return {
                "success": True,
                "synced_content": content_type,
                "message": f"Clipboard synced from mobile ({content_type})"
            }
        else:
            logging.warning(f"CLIPBOARD_SYNC_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to sync clipboard from mobile")
    
    except Exception as e:
        logging.error(f"CLIPBOARD_SYNC_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to sync clipboard from mobile")

@app.post("/clipboard/clear")
async def clear_clipboard(user=Depends(verify_token)):
    """Clear clipboard contents."""
    try:
        mc = get_media_controller()
        success = mc.clear_clipboard()
        
        if success:
            logging.info(f"CLIPBOARD_CLEAR_SUCCESS: user={user['sub']}")
            return {
                "success": True,
                "message": "Clipboard cleared"
            }
        else:
            logging.warning(f"CLIPBOARD_CLEAR_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to clear clipboard")
    
    except Exception as e:
        logging.error(f"CLIPBOARD_CLEAR_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to clear clipboard")

# Voice Command Endpoints

@app.post("/voice/process")
async def process_voice_command(request: VoiceCommandRequest, user=Depends(verify_token)):
    """Process voice command from text input."""
    try:
        vp = get_voice_processor()
        result = vp.process_command(request.text)
        
        logging.info(f"VOICE_PROCESS_SUCCESS: user={user['sub']}, command='{request.text}', success={result.success}")
        return {
            "success": True,
            "result": result.to_dict()
        }
    
    except Exception as e:
        logging.error(f"VOICE_PROCESS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to process voice command")

@app.get("/voice/commands")
async def get_available_commands(user=Depends(verify_token)):
    """Get list of available voice commands."""
    try:
        vp = get_voice_processor()
        commands = vp.get_available_commands()
        
        logging.info(f"VOICE_COMMANDS_SUCCESS: user={user['sub']}, count={len(commands)}")
        return {
            "success": True,
            "commands": commands,
            "count": len(commands)
        }
    
    except Exception as e:
        logging.error(f"VOICE_COMMANDS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get available commands")

@app.get("/voice/commands/custom")
async def get_custom_commands(user=Depends(verify_token)):
    """Get list of custom voice commands."""
    try:
        vp = get_voice_processor()
        commands = vp.get_custom_commands()
        
        logging.info(f"CUSTOM_COMMANDS_SUCCESS: user={user['sub']}, count={len(commands)}")
        return {
            "success": True,
            "commands": commands,
            "count": len(commands)
        }
    
    except Exception as e:
        logging.error(f"CUSTOM_COMMANDS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get custom commands")

@app.post("/voice/commands/custom")
async def add_custom_command(request: CustomCommandRequest, user=Depends(verify_token)):
    """Add a new custom voice command."""
    try:
        vp = get_voice_processor()
        success = vp.add_custom_command(
            trigger=request.trigger,
            actions=request.actions,
            description=request.description,
            parameters=request.parameters,
            category=request.category
        )
        
        if success:
            logging.info(f"ADD_CUSTOM_COMMAND_SUCCESS: user={user['sub']}, trigger='{request.trigger}'")
            return {
                "success": True,
                "trigger": request.trigger,
                "message": f"Custom command '{request.trigger}' added successfully"
            }
        else:
            logging.warning(f"ADD_CUSTOM_COMMAND_FAILED: user={user['sub']}, trigger='{request.trigger}'")
            raise HTTPException(status_code=400, detail="Failed to add custom command")
    
    except Exception as e:
        logging.error(f"ADD_CUSTOM_COMMAND_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to add custom command")

@app.put("/voice/commands/custom")
async def update_custom_command(request: CustomCommandUpdateRequest, user=Depends(verify_token)):
    """Update an existing custom voice command."""
    try:
        vp = get_voice_processor()
        success = vp.update_custom_command(
            trigger=request.trigger,
            actions=request.actions,
            description=request.description,
            parameters=request.parameters
        )
        
        if success:
            logging.info(f"UPDATE_CUSTOM_COMMAND_SUCCESS: user={user['sub']}, trigger='{request.trigger}'")
            return {
                "success": True,
                "trigger": request.trigger,
                "message": f"Custom command '{request.trigger}' updated successfully"
            }
        else:
            logging.warning(f"UPDATE_CUSTOM_COMMAND_FAILED: user={user['sub']}, trigger='{request.trigger}'")
            raise HTTPException(status_code=404, detail="Custom command not found")
    
    except Exception as e:
        logging.error(f"UPDATE_CUSTOM_COMMAND_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to update custom command")

@app.delete("/voice/commands/custom/{trigger}")
async def remove_custom_command(trigger: str, user=Depends(verify_token)):
    """Remove a custom voice command."""
    try:
        vp = get_voice_processor()
        success = vp.remove_custom_command(trigger)
        
        if success:
            logging.info(f"REMOVE_CUSTOM_COMMAND_SUCCESS: user={user['sub']}, trigger='{trigger}'")
            return {
                "success": True,
                "trigger": trigger,
                "message": f"Custom command '{trigger}' removed successfully"
            }
        else:
            logging.warning(f"REMOVE_CUSTOM_COMMAND_FAILED: user={user['sub']}, trigger='{trigger}'")
            raise HTTPException(status_code=404, detail="Custom command not found")
    
    except Exception as e:
        logging.error(f"REMOVE_CUSTOM_COMMAND_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to remove custom command")

@app.post("/voice/commands/search")
async def search_commands(request: CommandSearchRequest, user=Depends(verify_token)):
    """Search for voice commands matching query."""
    try:
        vp = get_voice_processor()
        results = vp.search_commands(
            query=request.query,
            include_builtin=request.include_builtin,
            include_custom=request.include_custom
        )
        
        logging.info(f"SEARCH_COMMANDS_SUCCESS: user={user['sub']}, query='{request.query}', results={len(results)}")
        return {
            "success": True,
            "query": request.query,
            "results": results,
            "count": len(results)
        }
    
    except Exception as e:
        logging.error(f"SEARCH_COMMANDS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to search commands")

@app.get("/voice/suggestions/{partial_text}")
async def get_command_suggestions(partial_text: str, user=Depends(verify_token)):
    """Get command suggestions for partial text."""
    try:
        vp = get_voice_processor()
        suggestions = vp.get_command_suggestions(partial_text, limit=10)
        
        logging.info(f"COMMAND_SUGGESTIONS_SUCCESS: user={user['sub']}, partial='{partial_text}', count={len(suggestions)}")
        return {
            "success": True,
            "partial_text": partial_text,
            "suggestions": suggestions,
            "count": len(suggestions)
        }
    
    except Exception as e:
        logging.error(f"COMMAND_SUGGESTIONS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get command suggestions")

@app.get("/voice/history")
async def get_command_history(limit: int = 20, user=Depends(verify_token)):
    """Get recent voice command history."""
    try:
        vp = get_voice_processor()
        history = vp.get_command_history(limit=limit)
        
        logging.info(f"COMMAND_HISTORY_SUCCESS: user={user['sub']}, limit={limit}, count={len(history)}")
        return {
            "success": True,
            "history": history,
            "count": len(history),
            "limit": limit
        }
    
    except Exception as e:
        logging.error(f"COMMAND_HISTORY_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get command history")

@app.delete("/voice/history")
async def clear_command_history(user=Depends(verify_token)):
    """Clear voice command history."""
    try:
        vp = get_voice_processor()
        success = vp.clear_command_history()
        
        if success:
            logging.info(f"CLEAR_HISTORY_SUCCESS: user={user['sub']}")
            return {
                "success": True,
                "message": "Command history cleared successfully"
            }
        else:
            logging.warning(f"CLEAR_HISTORY_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to clear command history")
    
    except Exception as e:
        logging.error(f"CLEAR_HISTORY_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to clear command history")

@app.get("/voice/statistics")
async def get_command_statistics(user=Depends(verify_token)):
    """Get voice command usage statistics."""
    try:
        vp = get_voice_processor()
        stats = vp.get_command_statistics()
        
        logging.info(f"COMMAND_STATS_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "statistics": stats
        }
    
    except Exception as e:
        logging.error(f"COMMAND_STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get command statistics")

@app.get("/voice/commands/export")
async def export_custom_commands(user=Depends(verify_token)):
    """Export custom commands to JSON."""
    try:
        vp = get_voice_processor()
        json_data = vp.export_custom_commands()
        
        if json_data:
            logging.info(f"EXPORT_COMMANDS_SUCCESS: user={user['sub']}")
            return {
                "success": True,
                "json_data": json_data,
                "message": "Custom commands exported successfully"
            }
        else:
            logging.warning(f"EXPORT_COMMANDS_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to export custom commands")
    
    except Exception as e:
        logging.error(f"EXPORT_COMMANDS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to export custom commands")

@app.post("/voice/commands/import")
async def import_custom_commands(request: CommandImportRequest, user=Depends(verify_token)):
    """Import custom commands from JSON."""
    try:
        vp = get_voice_processor()
        result = vp.import_custom_commands(request.json_data, overwrite=request.overwrite)
        
        if result['success']:
            logging.info(f"IMPORT_COMMANDS_SUCCESS: user={user['sub']}, imported={result['imported']}, skipped={result['skipped']}")
            return {
                "success": True,
                "imported": result['imported'],
                "skipped": result['skipped'],
                "errors": result['errors'],
                "message": f"Imported {result['imported']} commands successfully"
            }
        else:
            logging.warning(f"IMPORT_COMMANDS_FAILED: user={user['sub']}, error={result.get('error', 'Unknown error')}")
            raise HTTPException(status_code=400, detail=f"Import failed: {result.get('error', 'Unknown error')}")
    
    except Exception as e:
        logging.error(f"IMPORT_COMMANDS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to import custom commands")

# Remote Desktop Endpoints

@app.get("/remote-desktop/capabilities")
async def get_remote_desktop_capabilities(user=Depends(verify_token)):
    """Get remote desktop capabilities and supported features."""
    try:
        rdc = get_remote_desktop_controller()
        capabilities = rdc.get_capabilities()
        
        logging.info(f"REMOTE_DESKTOP_CAPABILITIES_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "capabilities": capabilities
        }
    
    except Exception as e:
        logging.error(f"REMOTE_DESKTOP_CAPABILITIES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get remote desktop capabilities")

@app.get("/remote-desktop/screen-info")
async def get_screen_info(user=Depends(verify_token)):
    """Get current screen information."""
    try:
        rdc = get_remote_desktop_controller()
        screen_info = rdc.get_screen_info()
        
        logging.info(f"SCREEN_INFO_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "screen_info": screen_info.to_dict()
        }
    
    except Exception as e:
        logging.error(f"SCREEN_INFO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get screen information")

@app.post("/remote-desktop/vnc/start")
async def start_vnc_session(request: VNCSessionRequest, user=Depends(verify_token)):
    """Start a new VNC session."""
    try:
        rdc = get_remote_desktop_controller()
        session = rdc.start_vnc_session(
            width=request.width,
            height=request.height,
            depth=request.depth,
            password=request.password
        )
        
        logging.info(f"VNC_START_SUCCESS: user={user['sub']}, session={session.session_id}, port={session.port}")
        return {
            "success": True,
            "session": session.to_dict()
        }
    
    except RemoteDesktopError as e:
        logging.warning(f"VNC_START_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"VNC_START_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to start VNC session")

@app.delete("/remote-desktop/vnc/{session_id}")
async def stop_vnc_session(session_id: str, user=Depends(verify_token)):
    """Stop a VNC session."""
    try:
        rdc = get_remote_desktop_controller()
        success = rdc.stop_vnc_session(session_id)
        
        if success:
            logging.info(f"VNC_STOP_SUCCESS: user={user['sub']}, session={session_id}")
            return {
                "success": True,
                "session_id": session_id,
                "message": "VNC session stopped successfully"
            }
        else:
            logging.warning(f"VNC_STOP_FAILED: user={user['sub']}, session={session_id}")
            raise HTTPException(status_code=404, detail="VNC session not found")
    
    except Exception as e:
        logging.error(f"VNC_STOP_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to stop VNC session")

@app.get("/remote-desktop/vnc/sessions")
async def get_vnc_sessions(user=Depends(verify_token)):
    """Get list of active VNC sessions."""
    try:
        rdc = get_remote_desktop_controller()
        sessions = rdc.get_vnc_sessions()
        
        sessions_dict = [session.to_dict() for session in sessions]
        
        logging.info(f"VNC_SESSIONS_SUCCESS: user={user['sub']}, count={len(sessions_dict)}")
        return {
            "success": True,
            "sessions": sessions_dict,
            "count": len(sessions_dict)
        }
    
    except Exception as e:
        logging.error(f"VNC_SESSIONS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get VNC sessions")

@app.post("/remote-desktop/wayland/start")
async def start_wayland_share(request: WaylandShareRequest, user=Depends(verify_token)):
    """Start Wayland screen sharing."""
    try:
        rdc = get_remote_desktop_controller()
        share_info = rdc.start_wayland_share(
            output_name=request.output_name
        )
        
        logging.info(f"WAYLAND_SHARE_START_SUCCESS: user={user['sub']}, share_id={share_info['share_id']}")
        return {
            "success": True,
            "share_info": share_info
        }
    
    except RemoteDesktopError as e:
        logging.warning(f"WAYLAND_SHARE_START_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"WAYLAND_SHARE_START_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to start Wayland screen sharing")

@app.delete("/remote-desktop/wayland/{share_id}")
async def stop_wayland_share(share_id: str, user=Depends(verify_token)):
    """Stop Wayland screen sharing."""
    try:
        rdc = get_remote_desktop_controller()
        success = rdc.stop_wayland_share(share_id)
        
        if success:
            logging.info(f"WAYLAND_SHARE_STOP_SUCCESS: user={user['sub']}, share_id={share_id}")
            return {
                "success": True,
                "share_id": share_id,
                "message": "Wayland screen sharing stopped successfully"
            }
        else:
            logging.warning(f"WAYLAND_SHARE_STOP_FAILED: user={user['sub']}, share_id={share_id}")
            raise HTTPException(status_code=404, detail="Wayland share not found")
    
    except Exception as e:
        logging.error(f"WAYLAND_SHARE_STOP_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to stop Wayland screen sharing")

@app.post("/remote-desktop/input")
async def simulate_input(request: InputSimulationRequest, user=Depends(verify_token)):
    """Simulate input events (mouse, keyboard, touch)."""
    try:
        rdc = get_remote_desktop_controller()
        success = rdc.simulate_input(
            input_type=request.input_type,
            data=request.data,
            display=request.display
        )
        
        if success:
            logging.info(f"INPUT_SIMULATION_SUCCESS: user={user['sub']}, type={request.input_type}")
            return {
                "success": True,
                "input_type": request.input_type,
                "message": f"Input simulation successful: {request.input_type}"
            }
        else:
            logging.warning(f"INPUT_SIMULATION_FAILED: user={user['sub']}, type={request.input_type}")
            raise HTTPException(status_code=400, detail="Input simulation failed")
    
    except Exception as e:
        logging.error(f"INPUT_SIMULATION_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to simulate input")

@app.get("/remote-desktop/input/capabilities")
async def get_input_capabilities(user=Depends(verify_token)):
    """Get input simulation capabilities."""
    try:
        rdc = get_remote_desktop_controller()
        capabilities = rdc.get_input_capabilities()
        
        logging.info(f"INPUT_CAPABILITIES_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "capabilities": capabilities
        }
    
    except Exception as e:
        logging.error(f"INPUT_CAPABILITIES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get input capabilities")

@app.post("/remote-desktop/launch")
async def launch_application(request: ApplicationLaunchRequest, user=Depends(verify_token)):
    """Launch application on remote desktop."""
    try:
        rdc = get_remote_desktop_controller()
        result = rdc.launch_application(
            application=request.application,
            display=request.display
        )
        
        logging.info(f"APP_LAUNCH_SUCCESS: user={user['sub']}, app={request.application}, pid={result['pid']}")
        return {
            "success": True,
            "launch_info": result
        }
    
    except RemoteDesktopError as e:
        logging.warning(f"APP_LAUNCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"APP_LAUNCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to launch application")

@app.get("/remote-desktop/wayland/outputs")
async def get_wayland_outputs(user=Depends(verify_token)):
    """Get available Wayland outputs."""
    try:
        rdc = get_remote_desktop_controller()
        outputs = rdc.wayland_share.get_wayland_outputs()
        
        logging.info(f"WAYLAND_OUTPUTS_SUCCESS: user={user['sub']}, count={len(outputs)}")
        return {
            "success": True,
            "outputs": outputs,
            "count": len(outputs)
        }
    
    except Exception as e:
        logging.error(f"WAYLAND_OUTPUTS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get Wayland outputs")

# Automation Endpoints

@app.get("/automation/stats")
async def get_automation_stats(user=Depends(verify_token)):
    """Get automation engine statistics."""
    try:
        ae = get_automation_engine()
        stats = ae.get_automation_stats()
        
        logging.info(f"AUTOMATION_STATS_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "stats": stats
        }
    
    except Exception as e:
        logging.error(f"AUTOMATION_STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get automation statistics")

@app.get("/automation/macros")
async def get_macros(user=Depends(verify_token)):
    """Get list of all macros."""
    try:
        ae = get_automation_engine()
        macros = ae.get_macros()
        
        logging.info(f"GET_MACROS_SUCCESS: user={user['sub']}, count={len(macros)}")
        return {
            "success": True,
            "macros": macros,
            "count": len(macros)
        }
    
    except Exception as e:
        logging.error(f"GET_MACROS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get macros")

@app.post("/automation/macros")
async def create_macro(request: MacroCreateRequest, user=Depends(verify_token)):
    """Create a new macro."""
    try:
        ae = get_automation_engine()
        success = ae.create_macro(
            macro_id=request.macro_id,
            name=request.name,
            description=request.description,
            actions=request.actions
        )
        
        if success:
            logging.info(f"CREATE_MACRO_SUCCESS: user={user['sub']}, macro_id={request.macro_id}")
            return {
                "success": True,
                "macro_id": request.macro_id,
                "message": f"Macro '{request.name}' created successfully"
            }
        else:
            logging.warning(f"CREATE_MACRO_FAILED: user={user['sub']}, macro_id={request.macro_id}")
            raise HTTPException(status_code=400, detail="Failed to create macro")
    
    except Exception as e:
        logging.error(f"CREATE_MACRO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to create macro")

@app.delete("/automation/macros/{macro_id}")
async def delete_macro(macro_id: str, user=Depends(verify_token)):
    """Delete a macro."""
    try:
        ae = get_automation_engine()
        success = ae.delete_macro(macro_id)
        
        if success:
            logging.info(f"DELETE_MACRO_SUCCESS: user={user['sub']}, macro_id={macro_id}")
            return {
                "success": True,
                "macro_id": macro_id,
                "message": f"Macro '{macro_id}' deleted successfully"
            }
        else:
            logging.warning(f"DELETE_MACRO_FAILED: user={user['sub']}, macro_id={macro_id}")
            raise HTTPException(status_code=404, detail="Macro not found")
    
    except Exception as e:
        logging.error(f"DELETE_MACRO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to delete macro")

@app.post("/automation/macros/execute")
async def execute_macro(request: MacroExecuteRequest, user=Depends(verify_token)):
    """Execute a macro."""
    try:
        ae = get_automation_engine()
        execution_id = ae.execute_macro(
            macro_id=request.macro_id,
            variables=request.variables
        )
        
        logging.info(f"EXECUTE_MACRO_SUCCESS: user={user['sub']}, macro_id={request.macro_id}, execution_id={execution_id}")
        return {
            "success": True,
            "execution_id": execution_id,
            "macro_id": request.macro_id,
            "message": f"Macro execution started: {execution_id}"
        }
    
    except Exception as e:
        logging.error(f"EXECUTE_MACRO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to execute macro")

@app.get("/automation/executions/{execution_id}")
async def get_macro_status(execution_id: str, user=Depends(verify_token)):
    """Get macro execution status."""
    try:
        ae = get_automation_engine()
        status = ae.get_macro_status(execution_id)
        
        if status:
            logging.info(f"MACRO_STATUS_SUCCESS: user={user['sub']}, execution_id={execution_id}")
            return {
                "success": True,
                "execution": status.to_dict()
            }
        else:
            logging.warning(f"MACRO_STATUS_NOT_FOUND: user={user['sub']}, execution_id={execution_id}")
            raise HTTPException(status_code=404, detail="Execution not found")
    
    except Exception as e:
        logging.error(f"MACRO_STATUS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get macro status")

@app.post("/automation/executions/{execution_id}/stop")
async def stop_macro(execution_id: str, user=Depends(verify_token)):
    """Stop macro execution."""
    try:
        ae = get_automation_engine()
        success = ae.stop_macro(execution_id)
        
        if success:
            logging.info(f"STOP_MACRO_SUCCESS: user={user['sub']}, execution_id={execution_id}")
            return {
                "success": True,
                "execution_id": execution_id,
                "message": "Macro execution stopped"
            }
        else:
            logging.warning(f"STOP_MACRO_FAILED: user={user['sub']}, execution_id={execution_id}")
            raise HTTPException(status_code=404, detail="Execution not found")
    
    except Exception as e:
        logging.error(f"STOP_MACRO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to stop macro")

@app.get("/automation/scheduled-tasks")
async def get_scheduled_tasks(user=Depends(verify_token)):
    """Get list of scheduled tasks."""
    try:
        ae = get_automation_engine()
        tasks = ae.get_scheduled_tasks()
        
        logging.info(f"GET_SCHEDULED_TASKS_SUCCESS: user={user['sub']}, count={len(tasks)}")
        return {
            "success": True,
            "tasks": tasks,
            "count": len(tasks)
        }
    
    except Exception as e:
        logging.error(f"GET_SCHEDULED_TASKS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get scheduled tasks")

@app.post("/automation/scheduled-tasks")
async def schedule_macro(request: TaskScheduleRequest, user=Depends(verify_token)):
    """Schedule a macro to run on a schedule."""
    try:
        ae = get_automation_engine()
        success = ae.schedule_macro(
            task_id=request.task_id,
            macro_id=request.macro_id,
            schedule_expr=request.schedule_expr,
            variables=request.variables
        )
        
        if success:
            logging.info(f"SCHEDULE_MACRO_SUCCESS: user={user['sub']}, task_id={request.task_id}, macro_id={request.macro_id}")
            return {
                "success": True,
                "task_id": request.task_id,
                "macro_id": request.macro_id,
                "schedule": request.schedule_expr,
                "message": f"Macro scheduled successfully: {request.task_id}"
            }
        else:
            logging.warning(f"SCHEDULE_MACRO_FAILED: user={user['sub']}, task_id={request.task_id}")
            raise HTTPException(status_code=400, detail="Failed to schedule macro")
    
    except Exception as e:
        logging.error(f"SCHEDULE_MACRO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to schedule macro")

@app.delete("/automation/scheduled-tasks/{task_id}")
async def delete_scheduled_task(task_id: str, user=Depends(verify_token)):
    """Delete a scheduled task."""
    try:
        ae = get_automation_engine()
        success = ae.delete_scheduled_task(task_id)
        
        if success:
            logging.info(f"DELETE_SCHEDULED_TASK_SUCCESS: user={user['sub']}, task_id={task_id}")
            return {
                "success": True,
                "task_id": task_id,
                "message": f"Scheduled task '{task_id}' deleted successfully"
            }
        else:
            logging.warning(f"DELETE_SCHEDULED_TASK_FAILED: user={user['sub']}, task_id={task_id}")
            raise HTTPException(status_code=404, detail="Scheduled task not found")
    
    except Exception as e:
        logging.error(f"DELETE_SCHEDULED_TASK_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to delete scheduled task")

# Package Management Endpoints

@app.get("/packages/stats")
async def get_package_stats(user=Depends(verify_token)):
    """Get package management statistics."""
    try:
        pm = get_package_manager()
        stats = pm.get_package_stats()
        
        logging.info(f"PACKAGE_STATS_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "stats": stats
        }
    
    except Exception as e:
        logging.error(f"PACKAGE_STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get package statistics")

@app.post("/packages/search")
async def search_packages(request: PackageSearchRequest, user=Depends(verify_token)):
    """Search for packages."""
    try:
        pm = get_package_manager()
        packages = pm.search_packages(
            query=request.query,
            include_aur=request.include_aur,
            search_type=request.search_type,
            limit=request.limit
        )
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"PACKAGE_SEARCH_SUCCESS: user={user['sub']}, query='{request.query}', results={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict),
            "query": request.query
        }
    
    except PackageManagerError as e:
        logging.warning(f"PACKAGE_SEARCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PACKAGE_SEARCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to search packages")

@app.post("/packages/search/advanced")
async def advanced_search_packages(request: AdvancedSearchRequest, user=Depends(verify_token)):
    """Advanced package search with filters."""
    try:
        pm = get_package_manager()
        packages = pm.advanced_search(request.filters)
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"ADVANCED_SEARCH_SUCCESS: user={user['sub']}, results={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict),
            "filters": request.filters
        }
    
    except PackageManagerError as e:
        logging.warning(f"ADVANCED_SEARCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"ADVANCED_SEARCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to perform advanced search")

@app.get("/packages/installed")
async def get_installed_packages(user=Depends(verify_token)):
    """Get list of installed packages."""
    try:
        pm = get_package_manager()
        packages = pm.list_installed_packages()
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"INSTALLED_PACKAGES_SUCCESS: user={user['sub']}, count={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict)
        }
    
    except Exception as e:
        logging.error(f"INSTALLED_PACKAGES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get installed packages")

@app.get("/packages/upgradable")
async def get_upgradable_packages(include_aur: bool = True, user=Depends(verify_token)):
    """Get list of upgradable packages."""
    try:
        pm = get_package_manager()
        packages = pm.list_upgradable_packages(include_aur=include_aur)
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"UPGRADABLE_PACKAGES_SUCCESS: user={user['sub']}, count={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict),
            "include_aur": include_aur
        }
    
    except Exception as e:
        logging.error(f"UPGRADABLE_PACKAGES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get upgradable packages")

@app.get("/packages/info/{package_name}")
async def get_package_info(package_name: str, check_aur: bool = True, user=Depends(verify_token)):
    """Get detailed information about a package."""
    try:
        pm = get_package_manager()
        package = pm.get_package_info(package_name, check_aur=check_aur)
        
        if package:
            logging.info(f"PACKAGE_INFO_SUCCESS: user={user['sub']}, package='{package_name}'")
            return {
                "success": True,
                "package": package.to_dict()
            }
        else:
            logging.warning(f"PACKAGE_INFO_NOT_FOUND: user={user['sub']}, package='{package_name}'")
            raise HTTPException(status_code=404, detail="Package not found")
    
    except PackageManagerError as e:
        logging.warning(f"PACKAGE_INFO_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PACKAGE_INFO_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get package information")

@app.post("/packages/install")
async def install_packages(request: PackageInstallRequest, user=Depends(verify_token)):
    """Install packages."""
    try:
        pm = get_package_manager()
        operation_id = pm.install_packages(
            package_names=request.package_names,
            from_aur=request.from_aur,
            no_confirm=request.no_confirm
        )
        
        logging.info(f"PACKAGE_INSTALL_SUCCESS: user={user['sub']}, packages={request.package_names}, operation_id={operation_id}")
        return {
            "success": True,
            "operation_id": operation_id,
            "packages": request.package_names,
            "from_aur": request.from_aur,
            "message": f"Package installation started: {operation_id}"
        }
    
    except PackageManagerError as e:
        logging.warning(f"PACKAGE_INSTALL_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PACKAGE_INSTALL_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to install packages")

@app.post("/packages/remove")
async def remove_packages(request: PackageRemoveRequest, user=Depends(verify_token)):
    """Remove packages."""
    try:
        pm = get_package_manager()
        operation_id = pm.remove_packages(
            package_names=request.package_names,
            no_confirm=request.no_confirm,
            cascade=request.cascade
        )
        
        logging.info(f"PACKAGE_REMOVE_SUCCESS: user={user['sub']}, packages={request.package_names}, operation_id={operation_id}")
        return {
            "success": True,
            "operation_id": operation_id,
            "packages": request.package_names,
            "cascade": request.cascade,
            "message": f"Package removal started: {operation_id}"
        }
    
    except PackageManagerError as e:
        logging.warning(f"PACKAGE_REMOVE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"PACKAGE_REMOVE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to remove packages")

@app.post("/packages/upgrade")
async def upgrade_system(request: SystemUpgradeRequest, user=Depends(verify_token)):
    """Upgrade system packages."""
    try:
        pm = get_package_manager()
        operations = pm.upgrade_system(
            include_aur=request.include_aur,
            no_confirm=request.no_confirm
        )
        
        logging.info(f"SYSTEM_UPGRADE_SUCCESS: user={user['sub']}, operations={operations}")
        return {
            "success": True,
            "operations": operations,
            "include_aur": request.include_aur,
            "message": "System upgrade started"
        }
    
    except PackageManagerError as e:
        logging.warning(f"SYSTEM_UPGRADE_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"SYSTEM_UPGRADE_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to upgrade system")

@app.post("/packages/refresh")
async def refresh_database(user=Depends(verify_token)):
    """Refresh package database."""
    try:
        pm = get_package_manager()
        success = pm.refresh_database()
        
        if success:
            logging.info(f"DATABASE_REFRESH_SUCCESS: user={user['sub']}")
            return {
                "success": True,
                "message": "Package database refreshed successfully"
            }
        else:
            logging.warning(f"DATABASE_REFRESH_FAILED: user={user['sub']}")
            raise HTTPException(status_code=400, detail="Failed to refresh database")
    
    except Exception as e:
        logging.error(f"DATABASE_REFRESH_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to refresh database")

@app.get("/packages/operations/{operation_id}")
async def get_operation_status(operation_id: str, user=Depends(verify_token)):
    """Get package operation status."""
    try:
        pm = get_package_manager()
        operation = pm.get_operation_status(operation_id)
        
        if operation:
            logging.info(f"OPERATION_STATUS_SUCCESS: user={user['sub']}, operation_id={operation_id}")
            return {
                "success": True,
                "operation": operation.to_dict()
            }
        else:
            logging.warning(f"OPERATION_STATUS_NOT_FOUND: user={user['sub']}, operation_id={operation_id}")
            raise HTTPException(status_code=404, detail="Operation not found")
    
    except Exception as e:
        logging.error(f"OPERATION_STATUS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get operation status")

@app.post("/packages/search/file")
async def search_by_file(request: FileSearchRequest, user=Depends(verify_token)):
    """Search for packages that contain a specific file."""
    try:
        pm = get_package_manager()
        packages = pm.search_by_file(request.file_path)
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"FILE_SEARCH_SUCCESS: user={user['sub']}, file='{request.file_path}', results={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict),
            "file_path": request.file_path
        }
    
    except PackageManagerError as e:
        logging.warning(f"FILE_SEARCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"FILE_SEARCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to search by file")

@app.post("/packages/dependencies")
async def search_dependencies(request: DependencySearchRequest, user=Depends(verify_token)):
    """Search package dependencies."""
    try:
        pm = get_package_manager()
        packages = pm.search_dependencies(
            package_name=request.package_name,
            reverse=request.reverse
        )
        
        # Convert to dictionaries
        packages_dict = [package.to_dict() for package in packages]
        
        logging.info(f"DEPENDENCY_SEARCH_SUCCESS: user={user['sub']}, package='{request.package_name}', reverse={request.reverse}, results={len(packages_dict)}")
        return {
            "success": True,
            "packages": packages_dict,
            "count": len(packages_dict),
            "package_name": request.package_name,
            "reverse": request.reverse
        }
    
    except PackageManagerError as e:
        logging.warning(f"DEPENDENCY_SEARCH_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"DEPENDENCY_SEARCH_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to search dependencies")

# Device Management Endpoints

@app.get("/devices")
async def get_user_devices(user=Depends(verify_token)):
    """Get devices registered to the current user."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        devices = dm.get_user_devices(user['sub'])
        
        # Convert to dictionaries
        devices_dict = [device.to_dict() for device in devices]
        
        logging.info(f"GET_DEVICES_SUCCESS: user={user['sub']}, count={len(devices_dict)}")
        return {
            "success": True,
            "devices": devices_dict,
            "count": len(devices_dict)
        }
    
    except Exception as e:
        logging.error(f"GET_DEVICES_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get devices")

@app.post("/devices/register")
async def register_device(request: DeviceRegistrationRequest, user=Depends(verify_token)):
    """Register a new device."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        
        # Get client IP and user agent from request
        # In a real implementation, you'd extract these from the request headers
        ip_address = "127.0.0.1"  # request.client.host
        user_agent = "Linux-Link-Client"  # request.headers.get("user-agent")
        
        device_id = dm.register_device(
            device_name=request.device_name,
            device_type=request.device_type,
            platform=request.platform,
            app_version=request.app_version,
            username=user['sub'],
            device_info=request.device_info,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        logging.info(f"DEVICE_REGISTER_SUCCESS: user={user['sub']}, device_id={device_id}")
        return {
            "success": True,
            "device_id": device_id,
            "device_name": request.device_name,
            "message": f"Device '{request.device_name}' registered successfully"
        }
    
    except SecurityError as e:
        logging.warning(f"DEVICE_REGISTER_ERROR: user={user['sub']}, error='{e.message}'")
        raise HTTPException(status_code=400, detail={"error": e.message, "code": e.error_code})
    except Exception as e:
        logging.error(f"DEVICE_REGISTER_CRITICAL: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to register device")

@app.get("/devices/{device_id}")
async def get_device_info(device_id: str, user=Depends(verify_token)):
    """Get information about a specific device."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        device = dm.get_device(device_id)
        
        if not device:
            logging.warning(f"DEVICE_INFO_NOT_FOUND: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Check if user owns the device or is admin
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if device.username != user['sub'] and not rbac.has_permission(user_role, "user_management", "view"):
            logging.warning(f"DEVICE_INFO_FORBIDDEN: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        logging.info(f"DEVICE_INFO_SUCCESS: user={user['sub']}, device_id={device_id}")
        return {
            "success": True,
            "device": device.to_dict()
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"DEVICE_INFO_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get device information")

@app.put("/devices/{device_id}")
async def update_device(device_id: str, request: DeviceUpdateRequest, user=Depends(verify_token)):
    """Update device settings."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        device = dm.get_device(device_id)
        
        if not device:
            logging.warning(f"DEVICE_UPDATE_NOT_FOUND: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Check if user owns the device or is admin
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if device.username != user['sub'] and not rbac.has_permission(user_role, "user_management", "modify"):
            logging.warning(f"DEVICE_UPDATE_FORBIDDEN: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        # Prepare update data
        update_data = {}
        if request.device_name is not None:
            update_data['device_name'] = request.device_name
        if request.enabled is not None:
            update_data['enabled'] = request.enabled
        if request.trusted is not None:
            # Only admins can set trusted status
            if rbac.has_permission(user_role, "security", "configure"):
                update_data['trusted'] = request.trusted
        
        success = dm.update_device(device_id, **update_data)
        
        if success:
            logging.info(f"DEVICE_UPDATE_SUCCESS: user={user['sub']}, device_id={device_id}")
            return {
                "success": True,
                "device_id": device_id,
                "message": "Device updated successfully"
            }
        else:
            logging.warning(f"DEVICE_UPDATE_FAILED: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=400, detail="Failed to update device")
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"DEVICE_UPDATE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to update device")

@app.delete("/devices/{device_id}")
async def delete_device(device_id: str, user=Depends(verify_token)):
    """Delete a device."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        device = dm.get_device(device_id)
        
        if not device:
            logging.warning(f"DEVICE_DELETE_NOT_FOUND: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Check if user owns the device or is admin
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if device.username != user['sub'] and not rbac.has_permission(user_role, "user_management", "delete"):
            logging.warning(f"DEVICE_DELETE_FORBIDDEN: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        success = dm.delete_device(device_id)
        
        if success:
            logging.info(f"DEVICE_DELETE_SUCCESS: user={user['sub']}, device_id={device_id}")
            return {
                "success": True,
                "device_id": device_id,
                "message": "Device deleted successfully"
            }
        else:
            logging.warning(f"DEVICE_DELETE_FAILED: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=400, detail="Failed to delete device")
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"DEVICE_DELETE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to delete device")

@app.post("/devices/{device_id}/revoke")
async def revoke_device(device_id: str, user=Depends(verify_token)):
    """Revoke/disable a device."""
    try:
        from security import get_device_manager
        dm = get_device_manager()
        device = dm.get_device(device_id)
        
        if not device:
            logging.warning(f"DEVICE_REVOKE_NOT_FOUND: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Check if user owns the device or is admin
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if device.username != user['sub'] and not rbac.has_permission(user_role, "user_management", "modify"):
            logging.warning(f"DEVICE_REVOKE_FORBIDDEN: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        success = dm.revoke_device(device_id)
        
        if success:
            logging.info(f"DEVICE_REVOKE_SUCCESS: user={user['sub']}, device_id={device_id}")
            return {
                "success": True,
                "device_id": device_id,
                "message": "Device revoked successfully"
            }
        else:
            logging.warning(f"DEVICE_REVOKE_FAILED: user={user['sub']}, device_id={device_id}")
            raise HTTPException(status_code=400, detail="Failed to revoke device")
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"DEVICE_REVOKE_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to revoke device")

@app.get("/devices/stats")
async def get_device_stats(user=Depends(verify_token)):
    """Get device statistics (admin only)."""
    try:
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if not rbac.has_permission(user_role, "user_management", "view"):
            logging.warning(f"DEVICE_STATS_FORBIDDEN: user={user['sub']}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        from security import get_device_manager
        dm = get_device_manager()
        stats = dm.get_device_stats()
        
        logging.info(f"DEVICE_STATS_SUCCESS: user={user['sub']}")
        return {
            "success": True,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"DEVICE_STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get device statistics")

# Activity Logging Endpoints

@app.get("/activity/logs")
async def get_activity_logs(
    username: str = None,
    action: str = None,
    resource: str = None,
    start_time: float = None,
    end_time: float = None,
    success: bool = None,
    limit: int = 100,
    user=Depends(verify_token)
):
    """Get activity logs with optional filters."""
    try:
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        # Check permissions
        if not rbac.has_permission(user_role, "security", "view"):
            # Users can only see their own logs
            if username and username != user['sub']:
                logging.warning(f"ACTIVITY_LOGS_FORBIDDEN: user={user['sub']}, requested_user={username}")
                raise HTTPException(status_code=403, detail="Access denied")
            username = user['sub']  # Force to own logs
        
        activity_logger = get_activity_logger()
        logs = activity_logger.search_logs(
            username=username,
            action=action,
            resource=resource,
            start_time=start_time,
            end_time=end_time,
            success=success,
            limit=limit
        )
        
        # Convert to dictionaries
        logs_dict = [log.to_dict() for log in logs]
        
        logging.info(f"ACTIVITY_LOGS_SUCCESS: user={user['sub']}, results={len(logs_dict)}")
        return {
            "success": True,
            "logs": logs_dict,
            "count": len(logs_dict),
            "filters": {
                "username": username,
                "action": action,
                "resource": resource,
                "start_time": start_time,
                "end_time": end_time,
                "success": success,
                "limit": limit
            }
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"ACTIVITY_LOGS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get activity logs")

@app.get("/activity/summary")
async def get_activity_summary(days: int = 30, user=Depends(verify_token)):
    """Get activity summary for the current user."""
    try:
        activity_logger = get_activity_logger()
        summary = activity_logger.get_user_activity_summary(user['sub'], days)
        
        logging.info(f"ACTIVITY_SUMMARY_SUCCESS: user={user['sub']}, days={days}")
        return {
            "success": True,
            "summary": summary
        }
    
    except Exception as e:
        logging.error(f"ACTIVITY_SUMMARY_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get activity summary")

@app.get("/activity/summary/{target_username}")
async def get_user_activity_summary(target_username: str, days: int = 30, user=Depends(verify_token)):
    """Get activity summary for a specific user (admin only)."""
    try:
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if not rbac.has_permission(user_role, "user_management", "view"):
            logging.warning(f"USER_ACTIVITY_SUMMARY_FORBIDDEN: user={user['sub']}, target={target_username}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        activity_logger = get_activity_logger()
        summary = activity_logger.get_user_activity_summary(target_username, days)
        
        logging.info(f"USER_ACTIVITY_SUMMARY_SUCCESS: user={user['sub']}, target={target_username}, days={days}")
        return {
            "success": True,
            "summary": summary
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"USER_ACTIVITY_SUMMARY_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get user activity summary")

@app.get("/activity/stats")
async def get_system_activity_stats(days: int = 7, user=Depends(verify_token)):
    """Get system-wide activity statistics (admin only)."""
    try:
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if not rbac.has_permission(user_role, "system_monitoring", "view"):
            logging.warning(f"SYSTEM_ACTIVITY_STATS_FORBIDDEN: user={user['sub']}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        activity_logger = get_activity_logger()
        stats = activity_logger.get_system_activity_stats(days)
        
        logging.info(f"SYSTEM_ACTIVITY_STATS_SUCCESS: user={user['sub']}, days={days}")
        return {
            "success": True,
            "stats": stats
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"SYSTEM_ACTIVITY_STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to get system activity statistics")

@app.post("/activity/cleanup")
async def cleanup_old_logs(days: int = 90, user=Depends(verify_token)):
    """Clean up old activity logs (admin only)."""
    try:
        rbac = get_rbac()
        user_role = UserRole(user.get('role', 'user'))
        
        if not rbac.has_permission(user_role, "security", "configure"):
            logging.warning(f"LOG_CLEANUP_FORBIDDEN: user={user['sub']}")
            raise HTTPException(status_code=403, detail="Access denied")
        
        activity_logger = get_activity_logger()
        removed_files = activity_logger.cleanup_old_logs(days)
        
        # Log the cleanup activity
        activity_logger.log_activity(
            username=user['sub'],
            action="log_cleanup",
            resource="activity_logs",
            success=True,
            details={"days": days, "removed_files": removed_files}
        )
        
        logging.info(f"LOG_CLEANUP_SUCCESS: user={user['sub']}, days={days}, removed={removed_files}")
        return {
            "success": True,
            "removed_files": removed_files,
            "days": days,
            "message": f"Cleaned up {removed_files} old log files"
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"LOG_CLEANUP_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to cleanup old logs")

# Authentication Endpoints

@app.post("/auth/login")
async def login(request: LoginRequest):
    # MVP: Hardcoded credentials (make configurable later)
    if request.username == "admin" and request.password == "linuxlink123":
        token = jwt.encode({
            "sub": request.username,
            "exp": datetime.utcnow() + timedelta(hours=24)
        }, SECRET_KEY, algorithm="HS256")
        logging.info(f"Login successful for user: {request.username}")
        return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/auth/verify-token")
async def verify_token_endpoint(user=Depends(verify_token)):
    return {"valid": True, "user": user["sub"]}

@app.post("/exec")
async def execute_command(request: CommandRequest, user=Depends(verify_token)):
    start_time = datetime.utcnow()
    logging.info(f"EXEC_ATTEMPT: user={user['sub']}, cmd='{request.cmd}', timeout={request.timeout}")
    try:
        result = await executor.execute_safe(request.cmd, request.timeout)
        logging.info(f"EXEC_SUCCESS: user={user['sub']}, cmd='{request.cmd}', rc={result['returncode']}")
        return result
    except ValueError as e:
        logging.warning(f"EXEC_BLOCKED: user={user['sub']}, cmd='{request.cmd}', reason='{str(e)}'")
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        logging.error(f"EXEC_TIMEOUT: user={user['sub']}, cmd='{request.cmd}', timeout={request.timeout}")
        raise HTTPException(status_code=408, detail=str(e))
    except Exception as e:
        logging.critical(f"EXEC_ERROR: user={user['sub']}, cmd='{request.cmd}', error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Command execution failed")

@app.get("/sys/stats")
async def system_stats(user=Depends(verify_token)):
    try:
        stats = await monitor.get_stats()
        return stats
    except Exception as e:
        logging.error(f"STATS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to retrieve system stats")

@app.get("/sys/quick-status")
async def quick_status(user=Depends(verify_token)):
    try:
        stats = await monitor.get_stats()
        critical_info = await get_critical_system_info()
        return {
            "system_stats": {
                "cpu_percent": stats["cpu"]["percent"][0] if stats["cpu"]["percent"] else 0,
                "memory_percent": stats["memory"]["percent"],
                "disk_percent": stats["disk"]["percent"],
                "uptime": stats["uptime"]
            },
            "critical_info": critical_info,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logging.error(f"QUICK_STATUS_ERROR: user={user['sub']}, error='{str(e)}'")
        raise HTTPException(status_code=500, detail="Failed to retrieve quick status")

async def get_critical_system_info():
    try:
        services_result = await executor.execute_safe("systemctl list-units --type=service --state=running --no-pager --no-legend")
        logs_result = await executor.execute_safe("journalctl -p err -n 3 --no-pager")
        running_services = len(services_result["stdout"].strip().split('\n')) if services_result["stdout"].strip() else 0
        return {
            "running_services": running_services,
            "recent_errors": logs_result["stdout"].strip().split('\n')[-3:] if logs_result["stdout"].strip() else []
        }
    except Exception as e:
        logging.warning(f"Failed to get critical system info: {e}")
        return {
            "running_services": 0,
            "recent_errors": ["Unable to fetch system information"]
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 