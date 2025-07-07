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

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

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