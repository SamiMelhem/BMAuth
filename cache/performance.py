"""
Performance monitoring and optimization for the authentication system.

This module provides comprehensive performance monitoring, bottleneck detection,
and automatic optimization for the biometric authentication system.
"""

import asyncio
import logging
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
from contextlib import asynccontextmanager
import statistics

from app.config.scaling import get_scaling_config

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Represents a performance metric measurement."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceAlert:
    """Represents a performance alert."""
    level: str  # "warning", "error", "critical"
    message: str
    metric_name: str
    threshold: float
    actual_value: float
    timestamp: datetime
    resolved: bool = False


class PerformanceCollector:
    """Collects and stores performance metrics."""

    def __init__(self, max_metrics: int = 10000):
        """
        Initialize performance collector.

        Args:
            max_metrics: Maximum number of metrics to store
        """
        self.max_metrics = max_metrics
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_metrics))
        self.alerts: List[PerformanceAlert] = []
        self.thresholds: Dict[str, Dict[str, float]] = {}

    def add_metric(self, metric: PerformanceMetric):
        """Add a performance metric."""
        self.metrics[metric.name].append(metric)

        # Check thresholds
        self._check_thresholds(metric)

    def _check_thresholds(self, metric: PerformanceMetric):
        """Check if metric exceeds configured thresholds."""
        if metric.name not in self.thresholds:
            return

        thresholds = self.thresholds[metric.name]

        for level, threshold in thresholds.items():
            if metric.value > threshold:
                alert = PerformanceAlert(
                    level=level,
                    message=f"{metric.name} exceeded {level} threshold: {metric.value:.2f} > {threshold}",
                    metric_name=metric.name,
                    threshold=threshold,
                    actual_value=metric.value,
                    timestamp=metric.timestamp
                )
                self.alerts.append(alert)

                # Log alert
                if level == "critical":
                    logger.critical(alert.message)
                elif level == "error":
                    logger.error(alert.message)
                else:
                    logger.warning(alert.message)

    def set_threshold(self, metric_name: str, level: str, threshold: float):
        """Set a threshold for a metric."""
        if metric_name not in self.thresholds:
            self.thresholds[metric_name] = {}
        self.thresholds[metric_name][level] = threshold

    def get_metrics(self, metric_name: str, since: Optional[datetime] = None) -> List[PerformanceMetric]:
        """Get metrics for a specific name since a certain time."""
        metrics = list(self.metrics[metric_name])

        if since:
            metrics = [m for m in metrics if m.timestamp >= since]

        return metrics

    def get_metric_summary(self, metric_name: str, period_minutes: int = 60) -> Dict[str, float]:
        """Get summary statistics for a metric over a time period."""
        since = datetime.now() - timedelta(minutes=period_minutes)
        metrics = self.get_metrics(metric_name, since)

        if not metrics:
            return {}

        values = [m.value for m in metrics]

        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "p95": self._percentile(values, 95),
            "p99": self._percentile(values, 99)
        }

    def _percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values."""
        if not values:
            return 0.0

        sorted_values = sorted(values)
        index = int((percentile / 100) * len(sorted_values))
        return sorted_values[min(index, len(sorted_values) - 1)]

    def get_active_alerts(self) -> List[PerformanceAlert]:
        """Get unresolved alerts."""
        return [alert for alert in self.alerts if not alert.resolved]

    def resolve_alert(self, alert: PerformanceAlert):
        """Mark an alert as resolved."""
        alert.resolved = True


class PerformanceMonitor:
    """Comprehensive performance monitoring system."""

    def __init__(self):
        """Initialize performance monitor."""
        self.config = get_scaling_config()
        self.collector = PerformanceCollector()
        self.running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._setup_default_thresholds()

    def _setup_default_thresholds(self):
        """Set up default performance thresholds."""
        # Response time thresholds (milliseconds)
        self.collector.set_threshold("auth_response_time", "warning", 100)
        self.collector.set_threshold("auth_response_time", "error", 250)
        self.collector.set_threshold("auth_response_time", "critical", 500)

        # Database query thresholds (milliseconds)
        self.collector.set_threshold("db_query_time", "warning", 50)
        self.collector.set_threshold("db_query_time", "error", 150)
        self.collector.set_threshold("db_query_time", "critical", 300)

        # Cache hit rate thresholds (percentage)
        self.collector.set_threshold("cache_miss_rate", "warning", 20)
        self.collector.set_threshold("cache_miss_rate", "error", 40)
        self.collector.set_threshold("cache_miss_rate", "critical", 60)

        # Memory usage thresholds (percentage)
        self.collector.set_threshold("memory_usage", "warning", 80)
        self.collector.set_threshold("memory_usage", "error", 90)
        self.collector.set_threshold("memory_usage", "critical", 95)

        # CPU usage thresholds (percentage)
        self.collector.set_threshold("cpu_usage", "warning", 70)
        self.collector.set_threshold("cpu_usage", "error", 85)
        self.collector.set_threshold("cpu_usage", "critical", 95)

    async def start(self):
        """Start performance monitoring."""
        if self.running:
            return

        self.running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Performance monitoring started")

    async def stop(self):
        """Stop performance monitoring."""
        self.running = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        logger.info("Performance monitoring stopped")

    async def _monitoring_loop(self):
        """Background monitoring loop."""
        while self.running:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(10)  # Collect metrics every 10 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in performance monitoring loop: {e}")
                await asyncio.sleep(30)

    async def _collect_system_metrics(self):
        """Collect system performance metrics."""
        now = datetime.now()

        # Memory usage
        memory = psutil.virtual_memory()
        self.collector.add_metric(PerformanceMetric(
            name="memory_usage",
            value=memory.percent,
            unit="percent",
            timestamp=now,
            metadata={"available_gb": memory.available / (1024**3)}
        ))

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        self.collector.add_metric(PerformanceMetric(
            name="cpu_usage",
            value=cpu_percent,
            unit="percent",
            timestamp=now,
            metadata={"cpu_count": psutil.cpu_count()}
        ))

        # Disk usage
        disk = psutil.disk_usage('/')
        self.collector.add_metric(PerformanceMetric(
            name="disk_usage",
            value=disk.percent,
            unit="percent",
            timestamp=now,
            metadata={"free_gb": disk.free / (1024**3)}
        ))

    @asynccontextmanager
    async def measure_time(self, operation_name: str, metadata: Optional[Dict[str, Any]] = None):
        """Context manager to measure operation time."""
        start_time = time.time()
        try:
            yield
        finally:
            duration = (time.time() - start_time) * 1000  # Convert to milliseconds
            self.collector.add_metric(PerformanceMetric(
                name=operation_name,
                value=duration,
                unit="milliseconds",
                timestamp=datetime.now(),
                metadata=metadata or {}
            ))

    def measure_function(self, metric_name: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None):
        """Decorator to measure function execution time."""
        def decorator(func: Callable) -> Callable:
            name = metric_name or f"{func.__module__}.{func.__name__}"

            if asyncio.iscoroutinefunction(func):
                async def async_wrapper(*args, **kwargs):
                    async with self.measure_time(name, metadata):
                        return await func(*args, **kwargs)
                return async_wrapper
            else:
                def sync_wrapper(*args, **kwargs):
                    start_time = time.time()
                    try:
                        return func(*args, **kwargs)
                    finally:
                        duration = (time.time() - start_time) * 1000
                        self.collector.add_metric(PerformanceMetric(
                            name=name,
                            value=duration,
                            unit="milliseconds",
                            timestamp=datetime.now(),
                            metadata=metadata or {}
                        ))
                return sync_wrapper

        return decorator

    def record_auth_event(self, event_type: str, duration_ms: float, success: bool, metadata: Optional[Dict[str, Any]] = None):
        """Record an authentication event."""
        self.collector.add_metric(PerformanceMetric(
            name="auth_response_time",
            value=duration_ms,
            unit="milliseconds",
            timestamp=datetime.now(),
            metadata={
                "event_type": event_type,
                "success": success,
                **(metadata or {})
            }
        ))

        # Record success/failure rate
        self.collector.add_metric(PerformanceMetric(
            name="auth_success_rate",
            value=100.0 if success else 0.0,
            unit="percent",
            timestamp=datetime.now(),
            metadata={"event_type": event_type}
        ))

    def record_db_query(self, query_type: str, duration_ms: float, metadata: Optional[Dict[str, Any]] = None):
        """Record a database query."""
        self.collector.add_metric(PerformanceMetric(
            name="db_query_time",
            value=duration_ms,
            unit="milliseconds",
            timestamp=datetime.now(),
            metadata={
                "query_type": query_type,
                **(metadata or {})
            }
        ))

    def record_cache_operation(self, operation: str, hit: bool, duration_ms: Optional[float] = None, metadata: Optional[Dict[str, Any]] = None):
        """Record a cache operation."""
        # Record hit/miss rate
        self.collector.add_metric(PerformanceMetric(
            name="cache_hit_rate" if hit else "cache_miss_rate",
            value=100.0,
            unit="percent",
            timestamp=datetime.now(),
            metadata={
                "operation": operation,
                **(metadata or {})
            }
        ))

        # Record operation time if provided
        if duration_ms is not None:
            self.collector.add_metric(PerformanceMetric(
                name="cache_operation_time",
                value=duration_ms,
                unit="milliseconds",
                timestamp=datetime.now(),
                metadata={
                    "operation": operation,
                    "hit": hit,
                    **(metadata or {})
                }
            ))

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get metrics for dashboard display."""
        return {
            "auth_response_time": self.collector.get_metric_summary("auth_response_time", 60),
            "db_query_time": self.collector.get_metric_summary("db_query_time", 60),
            "memory_usage": self.collector.get_metric_summary("memory_usage", 10),
            "cpu_usage": self.collector.get_metric_summary("cpu_usage", 10),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "active_alerts": len(self.collector.get_active_alerts()),
            "system_health": self._calculate_system_health()
        }

    def _calculate_cache_hit_rate(self) -> float:
        """Calculate overall cache hit rate."""
        since = datetime.now() - timedelta(minutes=60)
        hits = self.collector.get_metrics("cache_hit_rate", since)
        misses = self.collector.get_metrics("cache_miss_rate", since)

        total_operations = len(hits) + len(misses)
        if total_operations == 0:
            return 100.0

        hit_rate = (len(hits) / total_operations) * 100
        return round(hit_rate, 2)

    def _calculate_system_health(self) -> str:
        """Calculate overall system health status."""
        active_alerts = self.collector.get_active_alerts()

        critical_alerts = [a for a in active_alerts if a.level == "critical"]
        error_alerts = [a for a in active_alerts if a.level == "error"]

        if critical_alerts:
            return "critical"
        elif error_alerts:
            return "degraded"
        elif active_alerts:
            return "warning"
        else:
            return "healthy"

    def get_performance_report(self, period_hours: int = 24) -> Dict[str, Any]:
        """Generate a comprehensive performance report."""
        since = datetime.now() - timedelta(hours=period_hours)

        report = {
            "period_hours": period_hours,
            "generated_at": datetime.now().isoformat(),
            "system_health": self._calculate_system_health(),
            "metrics": {},
            "alerts": {
                "active": len(self.collector.get_active_alerts()),
                "by_level": defaultdict(int)
            },
            "recommendations": []
        }

        # Collect metric summaries
        metric_names = ["auth_response_time", "db_query_time", "memory_usage", "cpu_usage", "cache_hit_rate"]
        for metric_name in metric_names:
            summary = self.collector.get_metric_summary(metric_name, period_hours * 60)
            if summary:
                report["metrics"][metric_name] = summary

        # Count alerts by level
        for alert in self.collector.alerts:
            if alert.timestamp >= since:
                report["alerts"]["by_level"][alert.level] += 1

        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(report["metrics"])

        return report

    def _generate_recommendations(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations based on metrics."""
        recommendations = []

        # Check response times
        if "auth_response_time" in metrics:
            auth_metrics = metrics["auth_response_time"]
            if auth_metrics.get("p95", 0) > 100:
                recommendations.append("Consider enabling caching for authentication operations")
            if auth_metrics.get("p99", 0) > 250:
                recommendations.append("Investigate database query optimization")

        # Check memory usage
        if "memory_usage" in metrics:
            memory_metrics = metrics["memory_usage"]
            if memory_metrics.get("max", 0) > 85:
                recommendations.append("Consider increasing memory allocation or optimizing memory usage")

        # Check cache performance
        cache_hit_rate = self._calculate_cache_hit_rate()
        if cache_hit_rate < 80:
            recommendations.append("Optimize cache configuration to improve hit rate")

        return recommendations


# Global performance monitor instance
_performance_monitor: Optional[PerformanceMonitor] = None


async def start_performance_monitor():
    """Start the global performance monitor."""
    global _performance_monitor

    if _performance_monitor is not None and _performance_monitor.running:
        logger.warning("Performance monitor is already running")
        return

    _performance_monitor = PerformanceMonitor()
    await _performance_monitor.start()


async def stop_performance_monitor():
    """Stop the global performance monitor."""
    global _performance_monitor

    if _performance_monitor is not None:
        await _performance_monitor.stop()
        _performance_monitor = None


def get_performance_monitor() -> Optional[PerformanceMonitor]:
    """Get the global performance monitor instance."""
    return _performance_monitor