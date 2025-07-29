from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime, timedelta
import os
import jwt
from security import SecureCommandExecutor
from monitoring import monitor
from file_manager import get_file_manager, FileManagerError, PermissionError as FilePermissionError

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