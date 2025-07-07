import asyncio
import psutil
import time
import logging
from typing import Dict, Any
from datetime import datetime
import os

class AsyncSystemMonitor:
    """High-performance async system monitoring with intelligent caching"""
    
    def __init__(self, cache_duration: int = 2):
        self._stats_cache = {}
        self._last_update = 0
        self._cache_duration = cache_duration
        self._update_lock = asyncio.Lock()
        
    async def get_stats(self) -> Dict[str, Any]:
        """Get system stats with async caching"""
        current_time = time.time()
        
        # Return cached stats if fresh
        if (current_time - self._last_update) < self._cache_duration and self._stats_cache:
            return {**self._stats_cache, "cached": True}
        
        async with self._update_lock:
            # Double-check after acquiring lock
            if (current_time - self._last_update) < self._cache_duration and self._stats_cache:
                return {**self._stats_cache, "cached": True}
            
            # Collect stats asynchronously
            stats = await self._collect_stats()
            
            self._stats_cache = stats
            self._last_update = current_time
            
            return {**stats, "cached": False}
    
    async def _collect_stats(self) -> Dict[str, Any]:
        """Collect system statistics without blocking"""
        loop = asyncio.get_event_loop()
        
        # Run CPU-intensive operations in thread pool
        cpu_task = loop.run_in_executor(None, self._get_cpu_stats)
        memory_task = loop.run_in_executor(None, self._get_memory_stats)
        disk_task = loop.run_in_executor(None, self._get_disk_stats)
        network_task = loop.run_in_executor(None, self._get_network_stats)
        
        cpu_stats, memory_stats, disk_stats, network_stats = await asyncio.gather(
            cpu_task, memory_task, disk_task, network_task
        )
        
        return {
            "cpu": cpu_stats,
            "memory": memory_stats,
            "disk": disk_stats,
            "network": network_stats,
            "timestamp": datetime.utcnow().isoformat(),
            "uptime": self._get_uptime()
        }
    
    def _get_cpu_stats(self) -> Dict[str, Any]:
        """Get CPU statistics"""
        return {
            "percent": psutil.cpu_percent(percpu=True),
            "count": psutil.cpu_count(),
            "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
        }
    
    def _get_memory_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        mem = psutil.virtual_memory()
        return {
            "total": mem.total,
            "available": mem.available,
            "percent": mem.percent,
            "used": mem.used,
            "free": mem.free
        }
    
    def _get_disk_stats(self) -> Dict[str, Any]:
        """Get disk statistics"""
        disk = psutil.disk_usage('/')
        return {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": (disk.used / disk.total) * 100
        }
    
    def _get_network_stats(self) -> Dict[str, Any]:
        """Get network statistics"""
        net = psutil.net_io_counters()
        return {
            "bytes_sent": net.bytes_sent,
            "bytes_recv": net.bytes_recv,
            "packets_sent": net.packets_sent,
            "packets_recv": net.packets_recv
        }
    
    def _get_uptime(self) -> str:
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
                uptime_days = int(uptime_seconds // 86400)
                uptime_hours = int((uptime_seconds % 86400) // 3600)
                uptime_minutes = int((uptime_seconds % 3600) // 60)
                return f"{uptime_days}d {uptime_hours}h {uptime_minutes}m"
        except:
            return "Unknown"

# Global monitor instance
monitor = AsyncSystemMonitor() 