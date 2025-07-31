"""
Linux-Link System Monitoring

Provides comprehensive system monitoring with real-time metrics collection,
alert management, and historical data storage capabilities.
"""

import os
import json
import time
import psutil
import logging
import threading
import sqlite3
from typing import Dict, List, Optional, Union, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timedelta
import subprocess

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class MetricType(Enum):
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESS = "process"
    TEMPERATURE = "temperature"
    CUSTOM = "custom"


@dataclass
class SystemMetric:
    """Represents a system metric data point"""
    metric_type: MetricType
    name: str
    value: Union[float, int, str]
    unit: str
    timestamp: float
    hostname: str
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['metric_type'] = self.metric_type.value
        data['timestamp_iso'] = datetime.fromtimestamp(self.timestamp).isoformat()
        return data


@dataclass
class Alert:
    """Represents a system alert"""
    alert_id: str
    level: AlertLevel
    title: str
    message: str
    metric_type: MetricType
    metric_name: str
    threshold_value: Union[float, int]
    current_value: Union[float, int]
    created_at: float
    acknowledged: bool = False
    resolved: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[float] = None
    resolved_at: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['level'] = self.level.value
        data['metric_type'] = self.metric_type.value
        data['created_at_iso'] = datetime.fromtimestamp(self.created_at).isoformat()
        if self.acknowledged_at:
            data['acknowledged_at_iso'] = datetime.fromtimestamp(self.acknowledged_at).isoformat()
        if self.resolved_at:
            data['resolved_at_iso'] = datetime.fromtimestamp(self.resolved_at).isoformat()
        return data


@dataclass
class AlertThreshold:
    """Represents an alert threshold configuration"""
    threshold_id: str
    metric_type: MetricType
    metric_name: str
    operator: str  # >, <, >=, <=, ==, !=
    warning_value: Optional[Union[float, int]]
    critical_value: Optional[Union[float, int]]
    enabled: bool = True
    created_at: float = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['metric_type'] = self.metric_type.value
        return data


class MonitoringError(Exception):
    """Base exception for monitoring operations"""
    def __init__(self, message: str, error_code: str, details: Dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)


class MetricsCollector:
    """Collects system metrics using psutil and system commands"""
    
    def __init__(self):
        self.hostname = self._get_hostname()
        self.collection_interval = 30  # seconds
        self.running = False
        self.collection_thread = None
        logger.info("Metrics collector initialized")
    
    def _get_hostname(self) -> str:
        """Get system hostname"""
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "localhost"
    
    def start_collection(self):
        """Start metrics collection"""
        if not self.running:
            self.running = True
            self.collection_thread = threading.Thread(target=self._collection_loop)
            self.collection_thread.daemon = True
            self.collection_thread.start()
            logger.info("Metrics collection started")
    
    def stop_collection(self):
        """Stop metrics collection"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5)
        logger.info("Metrics collection stopped")
    
    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                metrics = self.collect_all_metrics()
                
                # Store metrics in database
                monitor = get_system_monitor()
                monitor.store_metrics(metrics)
                
                # Check for alerts
                monitor.check_alert_thresholds(metrics)
                
                time.sleep(self.collection_interval)
            
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                time.sleep(self.collection_interval)
    
    def collect_all_metrics(self) -> List[SystemMetric]:
        """Collect all available system metrics"""
        metrics = []
        timestamp = time.time()
        
        try:
            # CPU metrics
            metrics.extend(self._collect_cpu_metrics(timestamp))
            
            # Memory metrics
            metrics.extend(self._collect_memory_metrics(timestamp))
            
            # Disk metrics
            metrics.extend(self._collect_disk_metrics(timestamp))
            
            # Network metrics
            metrics.extend(self._collect_network_metrics(timestamp))
            
            # Process metrics
            metrics.extend(self._collect_process_metrics(timestamp))
            
            # Temperature metrics (if available)
            metrics.extend(self._collect_temperature_metrics(timestamp))
            
            return metrics
        
        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
            return []
    
    def _collect_cpu_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect CPU-related metrics"""
        metrics = []
        
        try:
            # CPU usage percentage
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics.append(SystemMetric(
                metric_type=MetricType.CPU,
                name="cpu_usage_percent",
                value=cpu_percent,
                unit="percent",
                timestamp=timestamp,
                hostname=self.hostname
            ))
            
            # Per-core CPU usage
            cpu_per_core = psutil.cpu_percent(interval=1, percpu=True)
            for i, core_usage in enumerate(cpu_per_core):
                metrics.append(SystemMetric(
                    metric_type=MetricType.CPU,
                    name=f"cpu_core_{i}_usage",
                    value=core_usage,
                    unit="percent",
                    timestamp=timestamp,
                    hostname=self.hostname
                ))
            
            # CPU frequency
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                metrics.append(SystemMetric(
                    metric_type=MetricType.CPU,
                    name="cpu_frequency",
                    value=cpu_freq.current,
                    unit="MHz",
                    timestamp=timestamp,
                    hostname=self.hostname,
                    metadata={"min": cpu_freq.min, "max": cpu_freq.max}
                ))
            
            # Load average (Unix only)
            if hasattr(os, 'getloadavg'):
                load_avg = os.getloadavg()
                for i, load in enumerate(load_avg):
                    metrics.append(SystemMetric(
                        metric_type=MetricType.CPU,
                        name=f"load_avg_{[1, 5, 15][i]}min",
                        value=load,
                        unit="load",
                        timestamp=timestamp,
                        hostname=self.hostname
                    ))
        
        except Exception as e:
            logger.debug(f"Failed to collect CPU metrics: {e}")
        
        return metrics
    
    def _collect_memory_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect memory-related metrics"""
        metrics = []
        
        try:
            # Virtual memory
            vm = psutil.virtual_memory()
            metrics.extend([
                SystemMetric(MetricType.MEMORY, "memory_total", vm.total, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "memory_available", vm.available, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "memory_used", vm.used, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "memory_percent", vm.percent, "percent", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "memory_free", vm.free, "bytes", timestamp, self.hostname)
            ])
            
            # Swap memory
            swap = psutil.swap_memory()
            metrics.extend([
                SystemMetric(MetricType.MEMORY, "swap_total", swap.total, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "swap_used", swap.used, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "swap_free", swap.free, "bytes", timestamp, self.hostname),
                SystemMetric(MetricType.MEMORY, "swap_percent", swap.percent, "percent", timestamp, self.hostname)
            ])
        
        except Exception as e:
            logger.debug(f"Failed to collect memory metrics: {e}")
        
        return metrics
    
    def _collect_disk_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect disk-related metrics"""
        metrics = []
        
        try:
            # Disk usage for all mounted filesystems
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    mount_name = partition.mountpoint.replace('/', '_').replace('\\\\', '_').strip('_') or 'root'
                    
                    metrics.extend([
                        SystemMetric(MetricType.DISK, f"disk_{mount_name}_total", usage.total, "bytes", timestamp, self.hostname),
                        SystemMetric(MetricType.DISK, f"disk_{mount_name}_used", usage.used, "bytes", timestamp, self.hostname),
                        SystemMetric(MetricType.DISK, f"disk_{mount_name}_free", usage.free, "bytes", timestamp, self.hostname),
                        SystemMetric(MetricType.DISK, f"disk_{mount_name}_percent", 
                                   (usage.used / usage.total) * 100, "percent", timestamp, self.hostname)
                    ])
                except (PermissionError, OSError):
                    continue
            
            # Disk I/O statistics
            disk_io = psutil.disk_io_counters()
            if disk_io:
                metrics.extend([
                    SystemMetric(MetricType.DISK, "disk_read_bytes", disk_io.read_bytes, "bytes", timestamp, self.hostname),
                    SystemMetric(MetricType.DISK, "disk_write_bytes", disk_io.write_bytes, "bytes", timestamp, self.hostname),
                    SystemMetric(MetricType.DISK, "disk_read_count", disk_io.read_count, "count", timestamp, self.hostname),
                    SystemMetric(MetricType.DISK, "disk_write_count", disk_io.write_count, "count", timestamp, self.hostname)
                ])
        
        except Exception as e:
            logger.debug(f"Failed to collect disk metrics: {e}")
        
        return metrics
    
    def _collect_network_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect network-related metrics"""
        metrics = []
        
        try:
            # Network I/O statistics
            net_io = psutil.net_io_counters()
            if net_io:
                metrics.extend([
                    SystemMetric(MetricType.NETWORK, "network_bytes_sent", net_io.bytes_sent, "bytes", timestamp, self.hostname),
                    SystemMetric(MetricType.NETWORK, "network_bytes_recv", net_io.bytes_recv, "bytes", timestamp, self.hostname),
                    SystemMetric(MetricType.NETWORK, "network_packets_sent", net_io.packets_sent, "count", timestamp, self.hostname),
                    SystemMetric(MetricType.NETWORK, "network_packets_recv", net_io.packets_recv, "count", timestamp, self.hostname)
                ])
            
            # Per-interface statistics
            net_per_nic = psutil.net_io_counters(pernic=True)
            for interface, stats in net_per_nic.items():
                if interface.startswith('lo'):  # Skip loopback
                    continue
                
                metrics.extend([
                    SystemMetric(MetricType.NETWORK, f"network_{interface}_bytes_sent", 
                               stats.bytes_sent, "bytes", timestamp, self.hostname),
                    SystemMetric(MetricType.NETWORK, f"network_{interface}_bytes_recv", 
                               stats.bytes_recv, "bytes", timestamp, self.hostname)
                ])
        
        except Exception as e:
            logger.debug(f"Failed to collect network metrics: {e}")
        
        return metrics
    
    def _collect_process_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect process-related metrics"""
        metrics = []
        
        try:
            # Process count
            process_count = len(psutil.pids())
            metrics.append(SystemMetric(
                MetricType.PROCESS, "process_count", process_count, "count", timestamp, self.hostname
            ))
            
            # Top processes by CPU and memory
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            top_cpu_processes = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:5]
            for i, proc in enumerate(top_cpu_processes):
                metrics.append(SystemMetric(
                    MetricType.PROCESS, f"top_cpu_process_{i+1}", 
                    proc['cpu_percent'] or 0, "percent", timestamp, self.hostname,
                    metadata={"name": proc['name'], "pid": proc['pid']}
                ))
            
            # Sort by memory usage
            top_mem_processes = sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:5]
            for i, proc in enumerate(top_mem_processes):
                metrics.append(SystemMetric(
                    MetricType.PROCESS, f"top_mem_process_{i+1}", 
                    proc['memory_percent'] or 0, "percent", timestamp, self.hostname,
                    metadata={"name": proc['name'], "pid": proc['pid']}
                ))
        
        except Exception as e:
            logger.debug(f"Failed to collect process metrics: {e}")
        
        return metrics
    
    def _collect_temperature_metrics(self, timestamp: float) -> List[SystemMetric]:
        """Collect temperature metrics (if available)"""
        metrics = []
        
        try:
            # Try to get temperature sensors
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                for sensor_name, sensor_list in temps.items():
                    for i, sensor in enumerate(sensor_list):
                        if sensor.current:
                            metrics.append(SystemMetric(
                                MetricType.TEMPERATURE, 
                                f"temp_{sensor_name}_{i}",
                                sensor.current, 
                                "celsius", 
                                timestamp, 
                                self.hostname,
                                metadata={
                                    "label": sensor.label or f"{sensor_name}_{i}",
                                    "high": sensor.high,
                                    "critical": sensor.critical
                                }
                            ))
        
        except Exception as e:
            logger.debug(f"Failed to collect temperature metrics: {e}")
        
        return metrics


class SystemMonitor:
    """Main system monitoring class"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.expanduser('~/.linux_link_monitoring.db')
        self.metrics_collector = MetricsCollector()
        self.alerts = {}
        self.alert_thresholds = {}
        self._init_database()
        self._load_alert_thresholds()
        logger.info("System monitor initialized")
    
    def _init_database(self):
        """Initialize SQLite database for metrics storage"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    hostname TEXT NOT NULL,
                    metadata TEXT
                )
            ''')
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    level TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    threshold_value REAL NOT NULL,
                    current_value REAL NOT NULL,
                    created_at REAL NOT NULL,
                    acknowledged INTEGER DEFAULT 0,
                    resolved INTEGER DEFAULT 0,
                    acknowledged_by TEXT,
                    acknowledged_at REAL,
                    resolved_at REAL
                )
            ''')
            
            # Create alert thresholds table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alert_thresholds (
                    threshold_id TEXT PRIMARY KEY,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    operator TEXT NOT NULL,
                    warning_value REAL,
                    critical_value REAL,
                    enabled INTEGER DEFAULT 1,
                    created_at REAL NOT NULL
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at)')
            
            conn.commit()
            conn.close()
            
            logger.info("Database initialized successfully")
        
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def _load_alert_thresholds(self):
        """Load alert thresholds from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM alert_thresholds WHERE enabled = 1')
            rows = cursor.fetchall()
            
            for row in rows:
                threshold = AlertThreshold(
                    threshold_id=row[0],
                    metric_type=MetricType(row[1]),
                    metric_name=row[2],
                    operator=row[3],
                    warning_value=row[4],
                    critical_value=row[5],
                    enabled=bool(row[6]),
                    created_at=row[7]
                )
                self.alert_thresholds[threshold.threshold_id] = threshold
            
            conn.close()
            logger.info(f"Loaded {len(self.alert_thresholds)} alert thresholds")
        
        except Exception as e:
            logger.error(f"Failed to load alert thresholds: {e}")
    
    def start_monitoring(self):
        """Start system monitoring"""
        self.metrics_collector.start_collection()
        logger.info("System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.metrics_collector.stop_collection()
        logger.info("System monitoring stopped")
    
    def store_metrics(self, metrics: List[SystemMetric]):
        """Store metrics in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for metric in metrics:
                metadata_json = json.dumps(metric.metadata) if metric.metadata else None
                
                cursor.execute('''
                    INSERT INTO metrics (metric_type, name, value, unit, timestamp, hostname, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metric.metric_type.value,
                    metric.name,
                    metric.value,
                    metric.unit,
                    metric.timestamp,
                    metric.hostname,
                    metadata_json
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store metrics: {e}")
    
    def get_metrics(self, metric_type: MetricType = None, metric_name: str = None,
                   start_time: float = None, end_time: float = None,
                   limit: int = 1000) -> List[SystemMetric]:
        """Retrieve metrics from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM metrics WHERE 1=1'
            params = []
            
            if metric_type:
                query += ' AND metric_type = ?'
                params.append(metric_type.value)
            
            if metric_name:
                query += ' AND name = ?'
                params.append(metric_name)
            
            if start_time:
                query += ' AND timestamp >= ?'
                params.append(start_time)
            
            if end_time:
                query += ' AND timestamp <= ?'
                params.append(end_time)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            metrics = []
            for row in rows:
                metadata = json.loads(row[7]) if row[7] else None
                
                metric = SystemMetric(
                    metric_type=MetricType(row[1]),
                    name=row[2],
                    value=row[3],
                    unit=row[4],
                    timestamp=row[5],
                    hostname=row[6],
                    metadata=metadata
                )
                metrics.append(metric)
            
            conn.close()
            return metrics
        
        except Exception as e:
            logger.error(f"Failed to retrieve metrics: {e}")
            return []


# Global system monitor instance
_system_monitor = None


def get_system_monitor() -> SystemMonitor:
    """Get global system monitor instance"""
    global _system_monitor
    if _system_monitor is None:
        _system_monitor = SystemMonitor()
    return _system_monitor


# Decorator for monitoring function calls
def monitor(func_name: str = None):
    """Decorator to monitor function execution"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            error = None
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                error = str(e)
                raise
            finally:
                execution_time = time.time() - start_time
                
                # Log execution metrics
                monitor_name = func_name or f"{func.__module__}.{func.__name__}"
                
                try:
                    system_monitor = get_system_monitor()
                    
                    # Create custom metric for function execution
                    metric = SystemMetric(
                        metric_type=MetricType.CUSTOM,
                        name=f"function_{monitor_name}_execution_time",
                        value=execution_time,
                        unit="seconds",
                        timestamp=time.time(),
                        hostname=system_monitor.metrics_collector.hostname,
                        metadata={
                            "function": monitor_name,
                            "success": success,
                            "error": error
                        }
                    )
                    
                    system_monitor.store_metrics([metric])
                
                except Exception as monitor_error:
                    logger.debug(f"Failed to monitor function {monitor_name}: {monitor_error}")
        
        return wrapper
    return decorator