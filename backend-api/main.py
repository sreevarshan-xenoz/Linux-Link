from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Union
import logging
from datetime import datetime, timedelta
import os
import jwt
from security import SecureCommandExecutor
from monitoring import monitor
from file_manager import get_file_manager, FileManagerError, PermissionError as FilePermissionError
from desktop_controller import get_desktop_controller, DesktopControllerError

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