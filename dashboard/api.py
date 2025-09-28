"""
Dashboard API endpoints for authentication monitoring and analytics.

This module provides RESTful API endpoints for the authentication dashboard,
including user analytics, security metrics, and system status.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy import text, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.config.scaling import get_scaling_config
from app.models.user import User
from app.models.webauthn_credential import WebAuthnCredential
from app.security.auth import get_current_user
from app.tasks.scheduler import get_task_scheduler
from app.dashboard.analytics import AnalyticsEngine
from app.dashboard.websocket import get_connection_manager

logger = logging.getLogger(__name__)

dashboard_router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home():
    """Serve the main dashboard HTML page."""
    # In a real implementation, this would serve the dashboard HTML
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; }
            .card { background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            .metric { text-align: center; }
            .metric-value { font-size: 2em; font-weight: bold; color: #2196F3; }
            .metric-label { color: #666; margin-top: 5px; }
            #events { height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; }
            .event { padding: 10px; border-bottom: 1px solid #eee; }
            .event.success { border-left: 4px solid #4CAF50; }
            .event.failure { border-left: 4px solid #f44336; }
            .loading { text-align: center; color: #666; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Authentication Dashboard</h1>

            <div class="grid">
                <div class="card">
                    <div class="metric">
                        <div class="metric-value" id="total-users">-</div>
                        <div class="metric-label">Total Users</div>
                    </div>
                </div>
                <div class="card">
                    <div class="metric">
                        <div class="metric-value" id="active-sessions">-</div>
                        <div class="metric-label">Active Sessions</div>
                    </div>
                </div>
                <div class="card">
                    <div class="metric">
                        <div class="metric-value" id="success-rate">-</div>
                        <div class="metric-label">Success Rate (24h)</div>
                    </div>
                </div>
                <div class="card">
                    <div class="metric">
                        <div class="metric-value" id="threat-level">Low</div>
                        <div class="metric-label">Threat Level</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>📊 Live Authentication Events</h2>
                <div id="events">
                    <div class="loading">Connecting to live feed...</div>
                </div>
            </div>

            <div class="grid">
                <div class="card">
                    <h3>🌍 Geographic Distribution</h3>
                    <div id="geo-chart">
                        <div class="loading">Loading geographic data...</div>
                    </div>
                </div>
                <div class="card">
                    <h3>📈 Authentication Trends</h3>
                    <div id="trend-chart">
                        <div class="loading">Loading trend data...</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>⚙️ System Status</h2>
                <div id="system-status">
                    <div class="loading">Loading system status...</div>
                </div>
            </div>
        </div>

        <script>
            // WebSocket connection for real-time updates
            let ws = null;
            let reconnectAttempts = 0;
            const maxReconnectAttempts = 5;

            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                const wsUrl = protocol + '//' + window.location.host + '/dashboard/ws';

                ws = new WebSocket(wsUrl);

                ws.onopen = function() {
                    console.log('Dashboard WebSocket connected');
                    reconnectAttempts = 0;
                    loadDashboardData();
                };

                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    handleRealtimeUpdate(data);
                };

                ws.onclose = function() {
                    console.log('Dashboard WebSocket disconnected');
                    if (reconnectAttempts < maxReconnectAttempts) {
                        setTimeout(() => {
                            reconnectAttempts++;
                            connectWebSocket();
                        }, 1000 * Math.pow(2, reconnectAttempts));
                    }
                };

                ws.onerror = function(error) {
                    console.error('WebSocket error:', error);
                };
            }

            function handleRealtimeUpdate(data) {
                if (data.type === 'metrics') {
                    updateMetrics(data.data);
                } else if (data.type === 'auth_event') {
                    addAuthEvent(data.data);
                } else if (data.type === 'system_status') {
                    updateSystemStatus(data.data);
                }
            }

            function updateMetrics(metrics) {
                document.getElementById('total-users').textContent = metrics.total_users || '-';
                document.getElementById('active-sessions').textContent = metrics.active_sessions || '-';
                document.getElementById('success-rate').textContent =
                    metrics.success_rate ? metrics.success_rate + '%' : '-';
                document.getElementById('threat-level').textContent = metrics.threat_level || 'Low';
            }

            function addAuthEvent(event) {
                const eventsContainer = document.getElementById('events');
                const eventDiv = document.createElement('div');
                eventDiv.className = 'event ' + (event.success ? 'success' : 'failure');
                eventDiv.innerHTML =
                    '<strong>' + event.event_type + '</strong> - ' +
                    event.user_id + ' from ' + (event.location || 'Unknown') +
                    '<br><small>' + new Date(event.created_at).toLocaleString() + '</small>';

                eventsContainer.insertBefore(eventDiv, eventsContainer.firstChild);

                // Keep only last 50 events
                while (eventsContainer.children.length > 50) {
                    eventsContainer.removeChild(eventsContainer.lastChild);
                }
            }

            function updateSystemStatus(status) {
                const container = document.getElementById('system-status');
                container.innerHTML =
                    '<p><strong>Scale Level:</strong> ' + status.scale_level + '</p>' +
                    '<p><strong>Database Status:</strong> ' + status.database_status + '</p>' +
                    '<p><strong>Background Tasks:</strong> ' + status.background_tasks + '</p>' +
                    '<p><strong>Memory Usage:</strong> ' + status.memory_usage + '</p>';
            }

            async function loadDashboardData() {
                try {
                    // Load initial metrics
                    const metricsResponse = await fetch('/dashboard/api/metrics');
                    const metrics = await metricsResponse.json();
                    updateMetrics(metrics);

                    // Load system status
                    const statusResponse = await fetch('/dashboard/api/status');
                    const status = await statusResponse.json();
                    updateSystemStatus(status);

                    // Load recent events
                    const eventsResponse = await fetch('/dashboard/api/events?limit=20');
                    const events = await eventsResponse.json();
                    const eventsContainer = document.getElementById('events');
                    eventsContainer.innerHTML = '';

                    events.forEach(event => addAuthEvent(event));

                } catch (error) {
                    console.error('Failed to load dashboard data:', error);
                }
            }

            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', function() {
                connectWebSocket();
                // Fallback polling if WebSocket fails
                setInterval(loadDashboardData, 30000); // Every 30 seconds
            });
        </script>
    </body>
    </html>
    """


@dashboard_router.get("/api/metrics")
async def get_dashboard_metrics(
    period_hours: int = Query(24, description="Time period in hours"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get dashboard metrics for the specified time period."""
    try:
        analytics = AnalyticsEngine(db)
        metrics = await analytics.get_dashboard_metrics(period_hours)
        return metrics
    except Exception as e:
        logger.error(f"Failed to get dashboard metrics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve metrics")


@dashboard_router.get("/api/events")
async def get_recent_events(
    limit: int = Query(50, description="Number of events to retrieve"),
    offset: int = Query(0, description="Offset for pagination"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    db: AsyncSession = Depends(get_db)
) -> List[Dict[str, Any]]:
    """Get recent authentication events."""
    try:
        # Try partitioned table first, fall back to regular table
        table_name = "auth_events_partitioned"
        where_conditions = []
        params = {}

        if event_type:
            where_conditions.append("event_type = :event_type")
            params["event_type"] = event_type

        if user_id:
            where_conditions.append("user_id = :user_id")
            params["user_id"] = user_id

        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""

        query = f"""
        SELECT
            user_id,
            event_type,
            ip_address,
            success,
            failure_reason,
            location_country,
            location_city,
            created_at,
            metadata
        FROM {table_name}
        {where_clause}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
        """

        params.update({"limit": limit, "offset": offset})

        try:
            result = await db.execute(text(query), params)
        except Exception:
            # Fallback to non-partitioned table or create dummy data
            logger.warning("Could not query partitioned events table, using fallback")
            return []

        events = []
        for row in result.fetchall():
            events.append({
                "user_id": row[0],
                "event_type": row[1],
                "ip_address": str(row[2]) if row[2] else None,
                "success": row[3],
                "failure_reason": row[4],
                "location": f"{row[6]}, {row[5]}" if row[5] and row[6] else row[5] or "Unknown",
                "created_at": row[7].isoformat() if row[7] else None,
                "metadata": row[8]
            })

        return events

    except Exception as e:
        logger.error(f"Failed to get recent events: {e}")
        return []


@dashboard_router.get("/api/analytics/geographic")
async def get_geographic_analytics(
    period_hours: int = Query(24, description="Time period in hours"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get geographic distribution of authentication events."""
    try:
        analytics = AnalyticsEngine(db)
        return await analytics.get_geographic_analytics(period_hours)
    except Exception as e:
        logger.error(f"Failed to get geographic analytics: {e}")
        return {"countries": [], "cities": []}


@dashboard_router.get("/api/analytics/trends")
async def get_authentication_trends(
    period_hours: int = Query(24, description="Time period in hours"),
    interval: str = Query("hourly", description="Aggregation interval"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get authentication trend data."""
    try:
        analytics = AnalyticsEngine(db)
        return await analytics.get_authentication_trends(period_hours, interval)
    except Exception as e:
        logger.error(f"Failed to get authentication trends: {e}")
        return {"timeline": [], "summary": {}}


@dashboard_router.get("/api/users")
async def get_user_analytics(
    limit: int = Query(100, description="Number of users to retrieve"),
    sort_by: str = Query("last_login", description="Sort field"),
    order: str = Query("desc", description="Sort order"),
    search: Optional[str] = Query(None, description="Search term"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get user analytics and management data."""
    try:
        query = db.query(User)

        if search:
            query = query.filter(
                User.username.ilike(f"%{search}%") |
                User.email.ilike(f"%{search}%")
            )

        # Apply sorting
        if sort_by == "last_login":
            if order == "desc":
                query = query.order_by(desc(User.last_login_at))
            else:
                query = query.order_by(User.last_login_at)
        elif sort_by == "created":
            if order == "desc":
                query = query.order_by(desc(User.created_at))
            else:
                query = query.order_by(User.created_at)
        elif sort_by == "username":
            if order == "desc":
                query = query.order_by(desc(User.username))
            else:
                query = query.order_by(User.username)

        users = query.limit(limit).all()

        user_data = []
        for user in users:
            # Get credential count
            cred_count = len([c for c in user.credentials if c.is_active])

            user_data.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "display_name": user.display_name,
                "is_active": user.is_active,
                "is_verified": user.is_verified,
                "credential_count": cred_count,
                "failed_login_attempts": user.failed_login_attempts,
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "is_locked": user.is_locked
            })

        return {
            "users": user_data,
            "total": len(user_data),
            "has_more": len(user_data) == limit
        }

    except Exception as e:
        logger.error(f"Failed to get user analytics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user data")


@dashboard_router.get("/api/security/threats")
async def get_security_threats(
    period_hours: int = Query(24, description="Time period in hours"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get security threat analysis."""
    try:
        analytics = AnalyticsEngine(db)
        return await analytics.get_security_threats(period_hours, severity)
    except Exception as e:
        logger.error(f"Failed to get security threats: {e}")
        return {"threats": [], "summary": {"total": 0, "high_risk": 0}}


@dashboard_router.get("/api/status")
async def get_system_status() -> Dict[str, Any]:
    """Get comprehensive system status."""
    try:
        config = get_scaling_config()
        task_scheduler = get_task_scheduler()
        connection_manager = get_connection_manager()

        status = {
            "scale_level": config._detected_scale.value if config._detected_scale else "unknown",
            "database_status": "Connected",
            "partitioning_enabled": config.enable_partitioning,
            "background_tasks": "Running" if task_scheduler and task_scheduler.running else "Stopped",
            "websocket_connections": connection_manager.get_connection_count() if connection_manager else 0,
            "memory_usage": f"{config._system_resources.available_memory_gb:.1f}GB available" if config._system_resources else "Unknown",
            "configuration": {
                "max_concurrent_sessions": config.max_concurrent_sessions,
                "event_retention_days": config.event_retention_days,
                "dashboard_page_size": config.dashboard_page_size,
                "real_time_update_interval": config.real_time_update_interval
            }
        }

        if task_scheduler:
            status["task_status"] = task_scheduler.get_task_status()

        return status

    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {
            "scale_level": "unknown",
            "database_status": "Error",
            "error": str(e)
        }


@dashboard_router.post("/api/maintenance/run")
async def run_manual_maintenance(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Manually trigger database maintenance (admin only)."""
    try:
        from app.tasks.scheduler import run_maintenance_now
        results = await run_maintenance_now()
        return {"status": "success", "results": results}
    except Exception as e:
        logger.error(f"Manual maintenance failed: {e}")
        raise HTTPException(status_code=500, detail=f"Maintenance failed: {e}")


@dashboard_router.post("/api/cleanup/run")
async def run_manual_cleanup(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """Manually trigger cleanup tasks (admin only)."""
    try:
        from app.tasks.scheduler import run_cleanup_now
        results = await run_cleanup_now()
        return {"status": "success", "results": results}
    except Exception as e:
        logger.error(f"Manual cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Cleanup failed: {e}")


@dashboard_router.get("/api/database/partitions")
async def get_partition_info(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get database partition information (admin only)."""
    try:
        from app.database.partitioning import DatabasePartitionManager

        manager = DatabasePartitionManager(db)
        return await manager.get_partition_info()
    except Exception as e:
        logger.error(f"Failed to get partition info: {e}")
        return {"error": str(e), "partitions": []}


@dashboard_router.get("/api/database/stats")
async def get_database_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
) -> Dict[str, Any]:
    """Get database statistics (admin only)."""
    try:
        from app.database.partitioning import DatabaseOptimizer

        optimizer = DatabaseOptimizer(db)
        return await optimizer.get_database_stats()
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return {"error": str(e)}