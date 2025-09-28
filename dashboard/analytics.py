"""
Analytics engine for the authentication dashboard.

This module provides comprehensive analytics and data processing
for authentication events, user behavior, and system performance.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy import text, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from collections import defaultdict

from app.config.scaling import get_scaling_config
from app.cache.decorators import cached

logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """Comprehensive analytics engine for authentication data."""

    def __init__(self, db_session: AsyncSession):
        """Initialize analytics engine."""
        self.db = db_session
        self.config = get_scaling_config()

    @cached(ttl=300, key_prefix="dashboard_metrics")  # Cache for 5 minutes
    async def get_dashboard_metrics(self, period_hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive dashboard metrics."""
        try:
            since = datetime.now() - timedelta(hours=period_hours)

            # Get total users
            total_users_result = await self.db.execute(
                text("SELECT COUNT(*) FROM users WHERE is_active = true")
            )
            total_users = total_users_result.scalar() or 0

            # Get active sessions (approximation - would need session tracking)
            active_sessions = min(total_users, self.config.max_concurrent_sessions // 10)

            # Get authentication success rate
            success_rate = await self._get_success_rate(since)

            # Get threat level
            threat_level = await self._calculate_threat_level(since)

            # Get recent activity count
            activity_count = await self._get_recent_activity_count(since)

            return {
                "total_users": total_users,
                "active_sessions": active_sessions,
                "success_rate": round(success_rate, 1),
                "threat_level": threat_level,
                "recent_activity": activity_count,
                "period_hours": period_hours,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get dashboard metrics: {e}")
            return {
                "total_users": 0,
                "active_sessions": 0,
                "success_rate": 0.0,
                "threat_level": "Unknown",
                "recent_activity": 0,
                "error": str(e)
            }

    async def _get_success_rate(self, since: datetime) -> float:
        """Calculate authentication success rate."""
        try:
            # Try partitioned table first
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            total_query = f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE created_at >= :since
            AND event_type IN ('login', 'authentication')
            """

            success_query = f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE created_at >= :since
            AND event_type IN ('login', 'authentication')
            AND (success = true OR description LIKE '%success%')
            """

            total_result = await self.db.execute(text(total_query), {"since": since})
            success_result = await self.db.execute(text(success_query), {"since": since})

            total = total_result.scalar() or 0
            successful = success_result.scalar() or 0

            if total == 0:
                return 100.0  # No failed attempts

            return (successful / total) * 100

        except Exception as e:
            logger.warning(f"Could not calculate success rate: {e}")
            return 95.0  # Default optimistic value

    async def _calculate_threat_level(self, since: datetime) -> str:
        """Calculate current threat level."""
        try:
            # Count high-risk events in the last period
            risk_query = """
            SELECT COUNT(*) FROM security_logs
            WHERE created_at >= :since
            AND risk_level IN ('high', 'critical')
            """

            result = await self.db.execute(text(risk_query), {"since": since})
            high_risk_count = result.scalar() or 0

            # Calculate threat level based on activity
            if high_risk_count > 10:
                return "High"
            elif high_risk_count > 3:
                return "Medium"
            else:
                return "Low"

        except Exception as e:
            logger.warning(f"Could not calculate threat level: {e}")
            return "Low"

    async def _get_recent_activity_count(self, since: datetime) -> int:
        """Get count of recent authentication activity."""
        try:
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            query = f"""
            SELECT COUNT(*) FROM {table_name}
            WHERE created_at >= :since
            """

            result = await self.db.execute(text(query), {"since": since})
            return result.scalar() or 0

        except Exception as e:
            logger.warning(f"Could not get activity count: {e}")
            return 0

    @cached(ttl=900, key_prefix="geographic_analytics")  # Cache for 15 minutes
    async def get_geographic_analytics(self, period_hours: int = 24) -> Dict[str, Any]:
        """Get geographic distribution of authentication events."""
        try:
            since = datetime.now() - timedelta(hours=period_hours)
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            # Get country distribution
            country_query = f"""
            SELECT
                location_country,
                COUNT(*) as event_count,
                COUNT(CASE WHEN success = true THEN 1 END) as successful_count
            FROM {table_name}
            WHERE created_at >= :since
            AND location_country IS NOT NULL
            GROUP BY location_country
            ORDER BY event_count DESC
            LIMIT 20
            """

            # Get city distribution
            city_query = f"""
            SELECT
                location_city,
                location_country,
                COUNT(*) as event_count
            FROM {table_name}
            WHERE created_at >= :since
            AND location_city IS NOT NULL
            GROUP BY location_city, location_country
            ORDER BY event_count DESC
            LIMIT 50
            """

            country_result = await self.db.execute(text(country_query), {"since": since})
            city_result = await self.db.execute(text(city_query), {"since": since})

            countries = []
            for row in country_result.fetchall():
                countries.append({
                    "country": row[0],
                    "event_count": row[1],
                    "successful_count": row[2],
                    "success_rate": round((row[2] / row[1]) * 100, 1) if row[1] > 0 else 0
                })

            cities = []
            for row in city_result.fetchall():
                cities.append({
                    "city": row[0],
                    "country": row[1],
                    "event_count": row[2]
                })

            return {
                "countries": countries,
                "cities": cities,
                "period_hours": period_hours,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get geographic analytics: {e}")
            return {"countries": [], "cities": [], "error": str(e)}

    @cached(ttl=600, key_prefix="auth_trends")  # Cache for 10 minutes
    async def get_authentication_trends(self, period_hours: int = 24, interval: str = "hourly") -> Dict[str, Any]:
        """Get authentication trend data over time."""
        try:
            since = datetime.now() - timedelta(hours=period_hours)
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            # Determine time grouping based on interval
            if interval == "hourly":
                time_format = "YYYY-MM-DD HH24:00:00"
                time_group = "date_trunc('hour', created_at)"
            elif interval == "daily":
                time_format = "YYYY-MM-DD"
                time_group = "date_trunc('day', created_at)"
            else:
                time_format = "YYYY-MM-DD HH24:00:00"
                time_group = "date_trunc('hour', created_at)"

            trends_query = f"""
            SELECT
                {time_group} as time_bucket,
                COUNT(*) as total_events,
                COUNT(CASE WHEN success = true THEN 1 END) as successful_events,
                COUNT(CASE WHEN success = false THEN 1 END) as failed_events,
                COUNT(DISTINCT user_id) as unique_users
            FROM {table_name}
            WHERE created_at >= :since
            GROUP BY {time_group}
            ORDER BY time_bucket
            """

            result = await self.db.execute(text(trends_query), {"since": since})

            timeline = []
            total_events = 0
            total_successful = 0
            total_failed = 0
            unique_users = set()

            for row in result.fetchall():
                time_bucket = row[0]
                events = row[1]
                successful = row[2]
                failed = row[3]
                users = row[4]

                timeline.append({
                    "timestamp": time_bucket.isoformat() if time_bucket else None,
                    "total_events": events,
                    "successful_events": successful,
                    "failed_events": failed,
                    "unique_users": users,
                    "success_rate": round((successful / events) * 100, 1) if events > 0 else 0
                })

                total_events += events
                total_successful += successful
                total_failed += failed

            summary = {
                "total_events": total_events,
                "successful_events": total_successful,
                "failed_events": total_failed,
                "overall_success_rate": round((total_successful / total_events) * 100, 1) if total_events > 0 else 0,
                "average_events_per_period": round(total_events / max(len(timeline), 1), 1)
            }

            return {
                "timeline": timeline,
                "summary": summary,
                "interval": interval,
                "period_hours": period_hours,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get authentication trends: {e}")
            return {"timeline": [], "summary": {}, "error": str(e)}

    @cached(ttl=1800, key_prefix="security_threats")  # Cache for 30 minutes
    async def get_security_threats(self, period_hours: int = 24, severity: Optional[str] = None) -> Dict[str, Any]:
        """Get security threat analysis."""
        try:
            since = datetime.now() - timedelta(hours=period_hours)

            # Build query with optional severity filter
            where_clause = "WHERE created_at >= :since"
            params = {"since": since}

            if severity:
                where_clause += " AND risk_level = :severity"
                params["severity"] = severity

            threats_query = f"""
            SELECT
                event_type,
                risk_level,
                COUNT(*) as threat_count,
                COUNT(DISTINCT user_id) as affected_users,
                MAX(created_at) as latest_occurrence
            FROM security_logs
            {where_clause}
            AND risk_level IN ('medium', 'high', 'critical')
            GROUP BY event_type, risk_level
            ORDER BY
                CASE risk_level
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    ELSE 4
                END,
                threat_count DESC
            """

            # Get IP address patterns
            ip_patterns_query = f"""
            SELECT
                ip_address,
                COUNT(*) as attempt_count,
                COUNT(DISTINCT user_id) as targeted_users,
                MAX(created_at) as latest_attempt
            FROM security_logs
            {where_clause}
            AND risk_level IN ('high', 'critical')
            GROUP BY ip_address
            HAVING COUNT(*) >= 3
            ORDER BY attempt_count DESC
            LIMIT 20
            """

            threats_result = await self.db.execute(text(threats_query), params)
            ip_result = await self.db.execute(text(ip_patterns_query), params)

            threats = []
            for row in threats_result.fetchall():
                threats.append({
                    "event_type": row[0],
                    "risk_level": row[1],
                    "threat_count": row[2],
                    "affected_users": row[3],
                    "latest_occurrence": row[4].isoformat() if row[4] else None
                })

            suspicious_ips = []
            for row in ip_result.fetchall():
                suspicious_ips.append({
                    "ip_address": str(row[0]) if row[0] else "Unknown",
                    "attempt_count": row[1],
                    "targeted_users": row[2],
                    "latest_attempt": row[3].isoformat() if row[3] else None
                })

            # Calculate summary
            total_threats = sum(t["threat_count"] for t in threats)
            high_risk_threats = sum(t["threat_count"] for t in threats if t["risk_level"] in ["high", "critical"])

            summary = {
                "total_threats": total_threats,
                "high_risk_threats": high_risk_threats,
                "unique_threat_types": len(set(t["event_type"] for t in threats)),
                "suspicious_ip_count": len(suspicious_ips)
            }

            return {
                "threats": threats,
                "suspicious_ips": suspicious_ips,
                "summary": summary,
                "period_hours": period_hours,
                "severity_filter": severity,
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to get security threats: {e}")
            return {"threats": [], "suspicious_ips": [], "summary": {"total_threats": 0, "high_risk_threats": 0}, "error": str(e)}

    async def get_user_behavior_analysis(self, user_id: str, period_days: int = 30) -> Dict[str, Any]:
        """Analyze user behavior patterns."""
        try:
            since = datetime.now() - timedelta(days=period_days)
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            # Get user activity patterns
            activity_query = f"""
            SELECT
                EXTRACT(hour FROM created_at) as hour_of_day,
                EXTRACT(dow FROM created_at) as day_of_week,
                COUNT(*) as activity_count,
                COUNT(CASE WHEN success = true THEN 1 END) as successful_count
            FROM {table_name}
            WHERE user_id = :user_id
            AND created_at >= :since
            GROUP BY EXTRACT(hour FROM created_at), EXTRACT(dow FROM created_at)
            ORDER BY activity_count DESC
            """

            # Get device patterns
            device_query = f"""
            SELECT
                device_fingerprint,
                COUNT(*) as usage_count,
                MAX(created_at) as last_used,
                COUNT(CASE WHEN success = true THEN 1 END) as successful_count
            FROM {table_name}
            WHERE user_id = :user_id
            AND created_at >= :since
            AND device_fingerprint IS NOT NULL
            GROUP BY device_fingerprint
            ORDER BY usage_count DESC
            """

            params = {"user_id": user_id, "since": since}

            activity_result = await self.db.execute(text(activity_query), params)
            device_result = await self.db.execute(text(device_query), params)

            # Process activity patterns
            hourly_activity = defaultdict(int)
            daily_activity = defaultdict(int)

            for row in activity_result.fetchall():
                hour = int(row[0])
                day = int(row[1])
                count = row[2]

                hourly_activity[hour] += count
                daily_activity[day] += count

            # Process device patterns
            devices = []
            for row in device_result.fetchall():
                devices.append({
                    "device_fingerprint": row[0][:20] + "..." if len(row[0]) > 20 else row[0],
                    "usage_count": row[1],
                    "last_used": row[2].isoformat() if row[2] else None,
                    "successful_count": row[3],
                    "success_rate": round((row[3] / row[1]) * 100, 1) if row[1] > 0 else 0
                })

            return {
                "user_id": user_id,
                "period_days": period_days,
                "hourly_activity": dict(hourly_activity),
                "daily_activity": dict(daily_activity),
                "devices": devices,
                "most_active_hour": max(hourly_activity.items(), key=lambda x: x[1])[0] if hourly_activity else None,
                "most_active_day": max(daily_activity.items(), key=lambda x: x[1])[0] if daily_activity else None,
                "device_count": len(devices),
                "generated_at": datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to analyze user behavior for {user_id}: {e}")
            return {"user_id": user_id, "error": str(e)}


class AuthenticationAnalytics:
    """Specialized analytics for authentication events."""

    def __init__(self, db_session: AsyncSession):
        """Initialize authentication analytics."""
        self.db = db_session
        self.config = get_scaling_config()

    async def get_authentication_summary(self, period_hours: int = 24) -> Dict[str, Any]:
        """Get authentication summary statistics."""
        since = datetime.now() - timedelta(hours=period_hours)

        try:
            # Use appropriate table based on configuration
            table_name = "auth_events_partitioned" if self.config.enable_partitioning else "security_logs"

            summary_query = f"""
            SELECT
                COUNT(*) as total_attempts,
                COUNT(CASE WHEN success = true THEN 1 END) as successful_attempts,
                COUNT(CASE WHEN success = false THEN 1 END) as failed_attempts,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT ip_address) as unique_ips,
                AVG(CASE WHEN success = true THEN 1.0 ELSE 0.0 END) * 100 as success_rate
            FROM {table_name}
            WHERE created_at >= :since
            """

            result = await self.db.execute(text(summary_query), {"since": since})
            row = result.fetchone()

            if row:
                return {
                    "total_attempts": row[0] or 0,
                    "successful_attempts": row[1] or 0,
                    "failed_attempts": row[2] or 0,
                    "unique_users": row[3] or 0,
                    "unique_ips": row[4] or 0,
                    "success_rate": round(float(row[5] or 0), 2),
                    "period_hours": period_hours,
                    "generated_at": datetime.now().isoformat()
                }

        except Exception as e:
            logger.error(f"Failed to get authentication summary: {e}")

        return {
            "total_attempts": 0,
            "successful_attempts": 0,
            "failed_attempts": 0,
            "unique_users": 0,
            "unique_ips": 0,
            "success_rate": 0.0,
            "error": "Could not retrieve data"
        }