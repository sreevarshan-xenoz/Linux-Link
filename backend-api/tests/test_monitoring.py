"""
Tests for monitoring functionality
"""

import pytest
import time
from unittest.mock import patch, Mock
from monitoring import (
    get_system_monitor, MetricsCollector, SystemMetric, Alert,
    AlertThreshold, MetricType, AlertLevel, MonitoringError
)


class TestMetricsCollector:
    """Test metrics collection functionality"""
    
    def test_collect_cpu_metrics(self):
        """Test CPU metrics collection"""
        collector = MetricsCollector()
        timestamp = time.time()
        
        with patch('monitoring.psutil.cpu_percent', return_value=75.5):
            metrics = collector._collect_cpu_metrics(timestamp)
            
            assert len(metrics) > 0
            cpu_metric = next((m for m in metrics if m.name == "cpu_usage_percent"), None)
            assert cpu_metric is not None
            assert cpu_metric.value == 75.5
            assert cpu_metric.unit == "percent"
            assert cpu_metric.metric_type == MetricType.CPU
    
    def test_collect_memory_metrics(self):
        """Test memory metrics collection"""
        collector = MetricsCollector()
        timestamp = time.time()
        
        mock_vm = Mock()
        mock_vm.total = 8589934592  # 8GB
        mock_vm.available = 4294967296  # 4GB
        mock_vm.used = 4294967296  # 4GB
        mock_vm.percent = 50.0
        mock_vm.free = 4294967296  # 4GB
        
        with patch('monitoring.psutil.virtual_memory', return_value=mock_vm):
            metrics = collector._collect_memory_metrics(timestamp)
            
            assert len(metrics) >= 5
            memory_percent_metric = next((m for m in metrics if m.name == "memory_percent"), None)
            assert memory_percent_metric is not None
            assert memory_percent_metric.value == 50.0
    
    def test_collect_disk_metrics(self):
        """Test disk metrics collection"""
        collector = MetricsCollector()
        timestamp = time.time()
        
        mock_partition = Mock()
        mock_partition.mountpoint = "/"
        
        mock_usage = Mock()
        mock_usage.total = 1000000000000  # 1TB
        mock_usage.used = 500000000000   # 500GB
        mock_usage.free = 500000000000   # 500GB
        
        with patch('monitoring.psutil.disk_partitions', return_value=[mock_partition]), \\
             patch('monitoring.psutil.disk_usage', return_value=mock_usage):
            
            metrics = collector._collect_disk_metrics(timestamp)
            
            assert len(metrics) >= 4
            disk_total_metric = next((m for m in metrics if "disk_root_total" in m.name), None)
            assert disk_total_metric is not None
            assert disk_total_metric.value == 1000000000000
    
    def test_collect_network_metrics(self):
        """Test network metrics collection"""
        collector = MetricsCollector()
        timestamp = time.time()
        
        mock_net_io = Mock()
        mock_net_io.bytes_sent = 1000000
        mock_net_io.bytes_recv = 2000000
        mock_net_io.packets_sent = 1000
        mock_net_io.packets_recv = 2000
        
        with patch('monitoring.psutil.net_io_counters', return_value=mock_net_io):
            metrics = collector._collect_network_metrics(timestamp)
            
            assert len(metrics) >= 4
            bytes_sent_metric = next((m for m in metrics if m.name == "network_bytes_sent"), None)
            assert bytes_sent_metric is not None
            assert bytes_sent_metric.value == 1000000
    
    def test_collect_process_metrics(self):
        """Test process metrics collection"""
        collector = MetricsCollector()
        timestamp = time.time()
        
        mock_processes = [
            {'pid': 1, 'name': 'systemd', 'cpu_percent': 0.1, 'memory_percent': 0.5},
            {'pid': 2, 'name': 'kthreadd', 'cpu_percent': 0.0, 'memory_percent': 0.0}
        ]
        
        with patch('monitoring.psutil.pids', return_value=[1, 2]), \\
             patch('monitoring.psutil.process_iter') as mock_iter:
            
            mock_iter.return_value = [Mock(info=proc) for proc in mock_processes]
            
            metrics = collector._collect_process_metrics(timestamp)
            
            assert len(metrics) >= 1
            process_count_metric = next((m for m in metrics if m.name == "process_count"), None)
            assert process_count_metric is not None
            assert process_count_metric.value == 2


class TestSystemMonitor:
    """Test system monitoring functionality"""
    
    def test_create_alert_threshold(self, temp_dir):
        """Test alert threshold creation"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        threshold_id = monitor.create_alert_threshold(
            metric_type=MetricType.CPU,
            metric_name="cpu_usage_percent",
            operator=">",
            warning_value=80.0,
            critical_value=95.0
        )
        
        assert threshold_id is not None
        assert threshold_id in monitor.alert_thresholds
        
        threshold = monitor.alert_thresholds[threshold_id]
        assert threshold.metric_type == MetricType.CPU
        assert threshold.warning_value == 80.0
        assert threshold.critical_value == 95.0
    
    def test_update_alert_threshold(self, temp_dir):
        """Test alert threshold updating"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create threshold first
        threshold_id = monitor.create_alert_threshold(
            metric_type=MetricType.MEMORY,
            metric_name="memory_percent",
            operator=">",
            warning_value=70.0,
            critical_value=90.0
        )
        
        # Update threshold
        success = monitor.update_alert_threshold(
            threshold_id,
            warning_value=75.0,
            critical_value=95.0
        )
        
        assert success is True
        
        threshold = monitor.alert_thresholds[threshold_id]
        assert threshold.warning_value == 75.0
        assert threshold.critical_value == 95.0
    
    def test_delete_alert_threshold(self, temp_dir):
        """Test alert threshold deletion"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create threshold first
        threshold_id = monitor.create_alert_threshold(
            metric_type=MetricType.DISK,
            metric_name="disk_root_percent",
            operator=">",
            warning_value=80.0,
            critical_value=95.0
        )
        
        # Delete threshold
        success = monitor.delete_alert_threshold(threshold_id)
        
        assert success is True
        assert threshold_id not in monitor.alert_thresholds
    
    def test_store_and_retrieve_metrics(self, temp_dir):
        """Test metrics storage and retrieval"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create test metrics
        timestamp = time.time()
        metrics = [
            SystemMetric(
                metric_type=MetricType.CPU,
                name="cpu_usage_percent",
                value=75.5,
                unit="percent",
                timestamp=timestamp,
                hostname="test_host"
            ),
            SystemMetric(
                metric_type=MetricType.MEMORY,
                name="memory_percent",
                value=60.0,
                unit="percent",
                timestamp=timestamp,
                hostname="test_host"
            )
        ]
        
        # Store metrics
        monitor.store_metrics(metrics)
        
        # Retrieve metrics
        retrieved_metrics = monitor.get_metrics(limit=10)
        
        assert len(retrieved_metrics) == 2
        assert retrieved_metrics[0].name in ["cpu_usage_percent", "memory_percent"]
        assert retrieved_metrics[1].name in ["cpu_usage_percent", "memory_percent"]
    
    def test_threshold_evaluation(self, temp_dir):
        """Test alert threshold evaluation"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create threshold
        threshold_id = monitor.create_alert_threshold(
            metric_type=MetricType.CPU,
            metric_name="cpu_usage_percent",
            operator=">",
            warning_value=70.0,
            critical_value=90.0
        )
        
        # Create metric that exceeds critical threshold
        timestamp = time.time()
        metrics = [
            SystemMetric(
                metric_type=MetricType.CPU,
                name="cpu_usage_percent",
                value=95.0,  # Exceeds critical threshold
                unit="percent",
                timestamp=timestamp,
                hostname="test_host"
            )
        ]
        
        # Check thresholds
        monitor.check_alert_thresholds(metrics)
        
        # Verify alert was created
        alerts = monitor.get_alerts(limit=10)
        assert len(alerts) > 0
        
        critical_alert = next((a for a in alerts if a.level == AlertLevel.CRITICAL), None)
        assert critical_alert is not None
        assert critical_alert.current_value == 95.0
        assert critical_alert.threshold_value == 90.0
    
    def test_alert_acknowledgment(self, temp_dir):
        """Test alert acknowledgment"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create a mock alert directly in database
        import sqlite3
        conn = sqlite3.connect(monitor.db_path)
        cursor = conn.cursor()
        
        alert_id = "test_alert_123"
        cursor.execute('''
            INSERT INTO alerts 
            (alert_id, level, title, message, metric_type, metric_name, threshold_value, current_value, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_id, "critical", "Test Alert", "Test message", "cpu", "cpu_usage_percent",
            90.0, 95.0, time.time()
        ))
        conn.commit()
        conn.close()
        
        # Acknowledge alert
        success = monitor.acknowledge_alert(alert_id, "test_user")
        assert success is True
        
        # Verify acknowledgment
        alerts = monitor.get_alerts(limit=10)
        alert = next((a for a in alerts if a.alert_id == alert_id), None)
        assert alert is not None
        assert alert.acknowledged is True
        assert alert.acknowledged_by == "test_user"
    
    def test_alert_resolution(self, temp_dir):
        """Test alert resolution"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Create a mock alert directly in database
        import sqlite3
        conn = sqlite3.connect(monitor.db_path)
        cursor = conn.cursor()
        
        alert_id = "test_alert_456"
        cursor.execute('''
            INSERT INTO alerts 
            (alert_id, level, title, message, metric_type, metric_name, threshold_value, current_value, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_id, "warning", "Test Alert", "Test message", "memory", "memory_percent",
            80.0, 85.0, time.time()
        ))
        conn.commit()
        conn.close()
        
        # Resolve alert
        success = monitor.resolve_alert(alert_id)
        assert success is True
        
        # Verify resolution
        alerts = monitor.get_alerts(limit=10)
        alert = next((a for a in alerts if a.alert_id == alert_id), None)
        assert alert is not None
        assert alert.resolved is True
        assert alert.resolved_at is not None
    
    def test_monitoring_statistics(self, temp_dir):
        """Test monitoring statistics"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Add some test data
        timestamp = time.time()
        metrics = [
            SystemMetric(MetricType.CPU, "cpu_usage_percent", 50.0, "percent", timestamp, "test_host"),
            SystemMetric(MetricType.MEMORY, "memory_percent", 60.0, "percent", timestamp, "test_host")
        ]
        monitor.store_metrics(metrics)
        
        # Create threshold
        monitor.create_alert_threshold(
            MetricType.CPU, "cpu_usage_percent", ">", 70.0, 90.0
        )
        
        # Get statistics
        stats = monitor.get_monitoring_stats()
        
        assert "total_metrics" in stats
        assert "active_thresholds" in stats
        assert stats["total_metrics"] >= 2
        assert stats["active_thresholds"] >= 1
    
    def test_data_cleanup(self, temp_dir):
        """Test old data cleanup"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Add old metrics
        old_timestamp = time.time() - (40 * 86400)  # 40 days ago
        old_metrics = [
            SystemMetric(MetricType.CPU, "cpu_usage_percent", 50.0, "percent", old_timestamp, "test_host")
        ]
        monitor.store_metrics(old_metrics)
        
        # Add recent metrics
        recent_timestamp = time.time()
        recent_metrics = [
            SystemMetric(MetricType.MEMORY, "memory_percent", 60.0, "percent", recent_timestamp, "test_host")
        ]
        monitor.store_metrics(recent_metrics)
        
        # Cleanup old data (30 days)
        cleanup_result = monitor.cleanup_old_data(30)
        
        assert "metrics_removed" in cleanup_result
        assert cleanup_result["metrics_removed"] >= 1
        
        # Verify recent data still exists
        remaining_metrics = monitor.get_metrics(limit=10)
        assert len(remaining_metrics) >= 1
        assert all(m.timestamp > old_timestamp + 86400 for m in remaining_metrics)
    
    def test_metric_aggregation(self, temp_dir):
        """Test metric aggregation"""
        monitor = get_system_monitor()
        monitor.db_path = f"{temp_dir}/test_monitoring.db"
        monitor._init_database()
        
        # Add test metrics over time
        base_time = time.time() - 7200  # 2 hours ago
        for i in range(10):
            timestamp = base_time + (i * 600)  # Every 10 minutes
            metrics = [
                SystemMetric(MetricType.CPU, "cpu_usage_percent", 50.0 + i, "percent", timestamp, "test_host")
            ]
            monitor.store_metrics(metrics)
        
        # Aggregate data
        aggregated = monitor.aggregate_metrics(
            MetricType.CPU,
            "cpu_usage_percent",
            base_time,
            time.time(),
            interval_minutes=60  # 1 hour intervals
        )
        
        assert len(aggregated) >= 1
        assert "avg_value" in aggregated[0]
        assert "min_value" in aggregated[0]
        assert "max_value" in aggregated[0]
        assert "count" in aggregated[0]