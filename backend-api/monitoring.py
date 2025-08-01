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
    
    def create_alert_threshold(self, metric_type: MetricType, metric_name: str,
                              operator: str, warning_value: float = None,
                              critical_value: float = None) -> str:
        """Create a new alert threshold"""
        try:
            import secrets
            threshold_id = secrets.token_urlsafe(16)
            
            threshold = AlertThreshold(
                threshold_id=threshold_id,
                metric_type=metric_type,
                metric_name=metric_name,
                operator=operator,
                warning_value=warning_value,
                critical_value=critical_value,
                enabled=True
            )
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alert_thresholds 
                (threshold_id, metric_type, metric_name, operator, warning_value, critical_value, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threshold.threshold_id,
                threshold.metric_type.value,
                threshold.metric_name,
                threshold.operator,
                threshold.warning_value,
                threshold.critical_value,
                1 if threshold.enabled else 0,
                threshold.created_at
            ))
            
            conn.commit()
            conn.close()
            
            # Add to memory
            self.alert_thresholds[threshold_id] = threshold
            
            logger.info(f"Created alert threshold: {threshold_id} for {metric_name}")
            return threshold_id
        
        except Exception as e:
            logger.error(f"Failed to create alert threshold: {e}")
            raise MonitoringError("Failed to create alert threshold", "THRESHOLD_CREATE_FAILED")
    
    def update_alert_threshold(self, threshold_id: str, **kwargs) -> bool:
        """Update an alert threshold"""
        try:
            threshold = self.alert_thresholds.get(threshold_id)
            if not threshold:
                return False
            
            # Update allowed fields
            allowed_fields = ['operator', 'warning_value', 'critical_value', 'enabled']
            for field, value in kwargs.items():
                if field in allowed_fields and hasattr(threshold, field):
                    setattr(threshold, field, value)
            
            # Update in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE alert_thresholds 
                SET operator = ?, warning_value = ?, critical_value = ?, enabled = ?
                WHERE threshold_id = ?
            ''', (
                threshold.operator,
                threshold.warning_value,
                threshold.critical_value,
                1 if threshold.enabled else 0,
                threshold_id
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated alert threshold: {threshold_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to update alert threshold {threshold_id}: {e}")
            return False
    
    def delete_alert_threshold(self, threshold_id: str) -> bool:
        """Delete an alert threshold"""
        try:
            if threshold_id not in self.alert_thresholds:
                return False
            
            # Remove from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM alert_thresholds WHERE threshold_id = ?', (threshold_id,))
            
            conn.commit()
            conn.close()
            
            # Remove from memory
            del self.alert_thresholds[threshold_id]
            
            logger.info(f"Deleted alert threshold: {threshold_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete alert threshold {threshold_id}: {e}")
            return False
    
    def get_alert_thresholds(self) -> List[AlertThreshold]:
        """Get all alert thresholds"""
        return list(self.alert_thresholds.values())
    
    def check_alert_thresholds(self, metrics: List[SystemMetric]):
        """Check metrics against alert thresholds"""
        try:
            for metric in metrics:
                # Find matching thresholds
                matching_thresholds = [
                    threshold for threshold in self.alert_thresholds.values()
                    if (threshold.enabled and 
                        threshold.metric_type == metric.metric_type and
                        threshold.metric_name == metric.name)
                ]
                
                for threshold in matching_thresholds:
                    self._evaluate_threshold(metric, threshold)
        
        except Exception as e:
            logger.error(f"Failed to check alert thresholds: {e}")
    
    def _evaluate_threshold(self, metric: SystemMetric, threshold: AlertThreshold):
        """Evaluate a metric against a threshold"""
        try:
            current_value = float(metric.value)
            alert_level = None
            threshold_value = None
            
            # Check critical threshold first
            if threshold.critical_value is not None:
                if self._compare_values(current_value, threshold.critical_value, threshold.operator):
                    alert_level = AlertLevel.CRITICAL
                    threshold_value = threshold.critical_value
            
            # Check warning threshold if no critical alert
            if alert_level is None and threshold.warning_value is not None:
                if self._compare_values(current_value, threshold.warning_value, threshold.operator):
                    alert_level = AlertLevel.WARNING
                    threshold_value = threshold.warning_value
            
            # Create alert if threshold exceeded
            if alert_level is not None:
                self._create_alert(metric, threshold, alert_level, threshold_value, current_value)
        
        except Exception as e:
            logger.error(f"Failed to evaluate threshold: {e}")
    
    def _compare_values(self, current: float, threshold: float, operator: str) -> bool:
        """Compare values based on operator"""
        if operator == '>':
            return current > threshold
        elif operator == '<':
            return current < threshold
        elif operator == '>=':
            return current >= threshold
        elif operator == '<=':
            return current <= threshold
        elif operator == '==':
            return current == threshold
        elif operator == '!=':
            return current != threshold
        else:
            return False
    
    def _create_alert(self, metric: SystemMetric, threshold: AlertThreshold,
                     level: AlertLevel, threshold_value: float, current_value: float):
        """Create a new alert"""
        try:
            import secrets
            alert_id = secrets.token_urlsafe(16)
            
            # Check if similar alert already exists and is not resolved
            existing_alerts = [
                alert for alert in self.alerts.values()
                if (alert.metric_type == metric.metric_type and
                    alert.metric_name == metric.name and
                    alert.level == level and
                    not alert.resolved and
                    time.time() - alert.created_at < 3600)  # Within last hour
            ]
            
            if existing_alerts:
                # Don't create duplicate alerts
                return
            
            alert = Alert(
                alert_id=alert_id,
                level=level,
                title=f"{level.value.title()} Alert: {metric.name}",
                message=f"{metric.name} is {current_value} {metric.unit}, exceeding {level.value} threshold of {threshold_value} {metric.unit}",
                metric_type=metric.metric_type,
                metric_name=metric.name,
                threshold_value=threshold_value,
                current_value=current_value,
                created_at=time.time()
            )
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts 
                (alert_id, level, title, message, metric_type, metric_name, threshold_value, current_value, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_id,
                alert.level.value,
                alert.title,
                alert.message,
                alert.metric_type.value,
                alert.metric_name,
                alert.threshold_value,
                alert.current_value,
                alert.created_at
            ))
            
            conn.commit()
            conn.close()
            
            # Add to memory
            self.alerts[alert_id] = alert
            
            logger.warning(f"Created {level.value} alert: {alert.title}")
        
        except Exception as e:
            logger.error(f"Failed to create alert: {e}")
    
    def get_alerts(self, level: AlertLevel = None, resolved: bool = None,
                  acknowledged: bool = None, limit: int = 100) -> List[Alert]:
        """Get alerts with optional filters"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = 'SELECT * FROM alerts WHERE 1=1'
            params = []
            
            if level:
                query += ' AND level = ?'
                params.append(level.value)
            
            if resolved is not None:
                query += ' AND resolved = ?'
                params.append(1 if resolved else 0)
            
            if acknowledged is not None:
                query += ' AND acknowledged = ?'
                params.append(1 if acknowledged else 0)
            
            query += ' ORDER BY created_at DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            alerts = []
            for row in rows:
                alert = Alert(
                    alert_id=row[0],
                    level=AlertLevel(row[1]),
                    title=row[2],
                    message=row[3],
                    metric_type=MetricType(row[4]),
                    metric_name=row[5],
                    threshold_value=row[6],
                    current_value=row[7],
                    created_at=row[8],
                    acknowledged=bool(row[9]),
                    resolved=bool(row[10]),
                    acknowledged_by=row[11],
                    acknowledged_at=row[12],
                    resolved_at=row[13]
                )
                alerts.append(alert)
            
            conn.close()
            return alerts
        
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
    
    def acknowledge_alert(self, alert_id: str, username: str) -> bool:
        """Acknowledge an alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            acknowledged_at = time.time()
            
            cursor.execute('''
                UPDATE alerts 
                SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
                WHERE alert_id = ?
            ''', (username, acknowledged_at, alert_id))
            
            conn.commit()
            conn.close()
            
            # Update in memory if exists
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.acknowledged = True
                alert.acknowledged_by = username
                alert.acknowledged_at = acknowledged_at
            
            logger.info(f"Alert acknowledged: {alert_id} by {username}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            resolved_at = time.time()
            
            cursor.execute('''
                UPDATE alerts 
                SET resolved = 1, resolved_at = ?
                WHERE alert_id = ?
            ''', (resolved_at, alert_id))
            
            conn.commit()
            conn.close()
            
            # Update in memory if exists
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.resolved = True
                alert.resolved_at = resolved_at
            
            logger.info(f"Alert resolved: {alert_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to resolve alert {alert_id}: {e}")
            return False
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get metrics count
            cursor.execute('SELECT COUNT(*) FROM metrics')
            total_metrics = cursor.fetchone()[0]
            
            # Get recent metrics (last hour)
            recent_cutoff = time.time() - 3600
            cursor.execute('SELECT COUNT(*) FROM metrics WHERE timestamp > ?', (recent_cutoff,))
            recent_metrics = cursor.fetchone()[0]
            
            # Get alerts count
            cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = 0')
            active_alerts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE acknowledged = 0 AND resolved = 0')
            unacknowledged_alerts = cursor.fetchone()[0]
            
            # Get alert counts by level
            cursor.execute('SELECT level, COUNT(*) FROM alerts WHERE resolved = 0 GROUP BY level')
            alert_levels = dict(cursor.fetchall())
            
            # Get threshold count
            cursor.execute('SELECT COUNT(*) FROM alert_thresholds WHERE enabled = 1')
            active_thresholds = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_metrics': total_metrics,
                'recent_metrics': recent_metrics,
                'total_alerts': total_alerts,
                'active_alerts': active_alerts,
                'unacknowledged_alerts': unacknowledged_alerts,
                'alert_levels': alert_levels,
                'active_thresholds': active_thresholds,
                'monitoring_active': self.metrics_collector.running
            }
        
        except Exception as e:
            logger.error(f"Failed to get monitoring stats: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 30) -> Dict[str, int]:
        """Clean up old metrics and alerts data"""
        try:
            cutoff_time = time.time() - (days * 86400)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Clean up old metrics
            cursor.execute('SELECT COUNT(*) FROM metrics WHERE timestamp < ?', (cutoff_time,))
            old_metrics_count = cursor.fetchone()[0]
            
            cursor.execute('DELETE FROM metrics WHERE timestamp < ?', (cutoff_time,))
            
            # Clean up old resolved alerts
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE resolved = 1 AND created_at < ?', (cutoff_time,))
            old_alerts_count = cursor.fetchone()[0]
            
            cursor.execute('DELETE FROM alerts WHERE resolved = 1 AND created_at < ?', (cutoff_time,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cleaned up {old_metrics_count} old metrics and {old_alerts_count} old alerts")
            
            return {
                'metrics_removed': old_metrics_count,
                'alerts_removed': old_alerts_count,
                'cutoff_days': days
            }
        
        except Exception as e:
            logger.error(f"Failed to cleanup old data: {e}")
            return {}
    
    def aggregate_metrics(self, metric_type: MetricType, metric_name: str,
                         start_time: float, end_time: float, 
                         interval_minutes: int = 60) -> List[Dict[str, Any]]:
        """Aggregate metrics over time intervals"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate interval in seconds
            interval_seconds = interval_minutes * 60
            
            # Query for aggregated data
            cursor.execute('''
                SELECT 
                    CAST(timestamp / ? AS INTEGER) * ? as time_bucket,
                    AVG(value) as avg_value,
                    MIN(value) as min_value,
                    MAX(value) as max_value,
                    COUNT(*) as count
                FROM metrics 
                WHERE metric_type = ? AND name = ? AND timestamp >= ? AND timestamp <= ?
                GROUP BY time_bucket
                ORDER BY time_bucket
            ''', (interval_seconds, interval_seconds, metric_type.value, metric_name, start_time, end_time))
            
            rows = cursor.fetchall()
            conn.close()
            
            aggregated_data = []
            for row in rows:
                aggregated_data.append({
                    'timestamp': row[0],
                    'timestamp_iso': datetime.fromtimestamp(row[0]).isoformat(),
                    'avg_value': row[1],
                    'min_value': row[2],
                    'max_value': row[3],
                    'count': row[4],
                    'interval_minutes': interval_minutes
                })
            
            return aggregated_data
        
        except Exception as e:
            logger.error(f"Failed to aggregate metrics: {e}")
            return []
    
    def get_metric_summary(self, metric_type: MetricType, metric_name: str,
                          hours: int = 24) -> Dict[str, Any]:
        """Get summary statistics for a metric over time period"""
        try:
            end_time = time.time()
            start_time = end_time - (hours * 3600)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    COUNT(*) as count,
                    AVG(value) as avg_value,
                    MIN(value) as min_value,
                    MAX(value) as max_value,
                    MIN(timestamp) as first_timestamp,
                    MAX(timestamp) as last_timestamp
                FROM metrics 
                WHERE metric_type = ? AND name = ? AND timestamp >= ? AND timestamp <= ?
            ''', (metric_type.value, metric_name, start_time, end_time))
            
            row = cursor.fetchone()
            conn.close()
            
            if row and row[0] > 0:
                return {
                    'metric_type': metric_type.value,
                    'metric_name': metric_name,
                    'period_hours': hours,
                    'data_points': row[0],
                    'avg_value': row[1],
                    'min_value': row[2],
                    'max_value': row[3],
                    'first_timestamp': row[4],
                    'last_timestamp': row[5],
                    'first_timestamp_iso': datetime.fromtimestamp(row[4]).isoformat() if row[4] else None,
                    'last_timestamp_iso': datetime.fromtimestamp(row[5]).isoformat() if row[5] else None
                }
            else:
                return {
                    'metric_type': metric_type.value,
                    'metric_name': metric_name,
                    'period_hours': hours,
                    'data_points': 0,
                    'message': 'No data available for the specified period'
                }
        
        except Exception as e:
            logger.error(f"Failed to get metric summary: {e}")
            return {}
    
    def export_metrics(self, metric_type: MetricType = None, 
                      start_time: float = None, end_time: float = None,
                      format: str = 'json') -> str:
        """Export metrics data in specified format"""
        try:
            metrics = self.get_metrics(
                metric_type=metric_type,
                start_time=start_time,
                end_time=end_time,
                limit=10000
            )
            
            if format.lower() == 'json':
                return json.dumps([metric.to_dict() for metric in metrics], indent=2)
            
            elif format.lower() == 'csv':
                import csv
                import io
                
                output = io.StringIO()
                writer = csv.writer(output)
                
                # Write header
                writer.writerow(['timestamp', 'timestamp_iso', 'metric_type', 'name', 'value', 'unit', 'hostname'])
                
                # Write data
                for metric in metrics:
                    writer.writerow([
                        metric.timestamp,
                        datetime.fromtimestamp(metric.timestamp).isoformat(),
                        metric.metric_type.value,
                        metric.name,
                        metric.value,
                        metric.unit,
                        metric.hostname
                    ])
                
                return output.getvalue()
            
            else:
                raise MonitoringError(f"Unsupported export format: {format}", "UNSUPPORTED_FORMAT")
        
        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
            raise MonitoringError(f"Export failed: {str(e)}", "EXPORT_FAILED")
    
    def create_data_retention_policy(self, metric_type: MetricType = None,
                                   retention_days: int = 30) -> bool:
        """Create or update data retention policy"""
        try:
            # This would typically be stored in a configuration table
            # For now, we'll implement it as a scheduled cleanup
            
            def cleanup_job():
                while True:
                    try:
                        self.cleanup_old_data(retention_days)
                        time.sleep(86400)  # Run daily
                    except Exception as e:
                        logger.error(f"Retention cleanup failed: {e}")
                        time.sleep(3600)  # Retry in 1 hour
            
            # Start cleanup thread
            cleanup_thread = threading.Thread(target=cleanup_job)
            cleanup_thread.daemon = True
            cleanup_thread.start()
            
            logger.info(f"Data retention policy created: {retention_days} days")
            return True
        
        except Exception as e:
            logger.error(f"Failed to create retention policy: {e}")
            return False


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