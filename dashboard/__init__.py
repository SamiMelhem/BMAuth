"""
Real-time authentication dashboard module.

This module provides a comprehensive dashboard for monitoring authentication
events, user activity, and system performance with unlimited scalability.
"""

from .api import dashboard_router
from .websocket import WebSocketManager, ConnectionManager
from .analytics import AnalyticsEngine, AuthenticationAnalytics
from .events import EventProcessor, RealTimeEventStream

__all__ = [
    "dashboard_router",
    "WebSocketManager",
    "ConnectionManager",
    "AnalyticsEngine",
    "AuthenticationAnalytics",
    "EventProcessor",
    "RealTimeEventStream",
]