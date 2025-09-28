"""
WebSocket manager for real-time dashboard updates.

This module provides WebSocket connection management and real-time event
broadcasting for the authentication dashboard.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Set, Any, Optional, List
from fastapi import WebSocket, WebSocketDisconnect
from collections import defaultdict

from app.config.scaling import get_scaling_config

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time dashboard updates."""

    def __init__(self):
        """Initialize connection manager."""
        self.active_connections: Set[WebSocket] = set()
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        self.topic_subscriptions: Dict[str, Set[WebSocket]] = defaultdict(set)
        self.config = get_scaling_config()
        self.max_connections = self.config.max_websocket_connections

    async def connect(self, websocket: WebSocket, user_id: Optional[str] = None) -> bool:
        """
        Accept a new WebSocket connection.

        Args:
            websocket: WebSocket connection
            user_id: Optional user ID for the connection

        Returns:
            bool: True if connection accepted, False if rejected
        """
        if len(self.active_connections) >= self.max_connections:
            logger.warning(f"WebSocket connection rejected: max connections ({self.max_connections}) reached")
            await websocket.close(code=1013, reason="Server overloaded")
            return False

        try:
            await websocket.accept()
            self.active_connections.add(websocket)

            # Store connection metadata
            self.connection_metadata[websocket] = {
                "user_id": user_id,
                "connected_at": datetime.now(),
                "subscriptions": set(),
                "message_count": 0
            }

            # Subscribe to default topics
            await self.subscribe(websocket, "dashboard_metrics")
            await self.subscribe(websocket, "auth_events")
            await self.subscribe(websocket, "system_status")

            logger.info(f"WebSocket connected: {len(self.active_connections)} total connections")
            return True

        except Exception as e:
            logger.error(f"Failed to accept WebSocket connection: {e}")
            return False

    async def disconnect(self, websocket: WebSocket):
        """
        Disconnect a WebSocket connection.

        Args:
            websocket: WebSocket connection to disconnect
        """
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

            # Remove from topic subscriptions
            if websocket in self.connection_metadata:
                subscriptions = self.connection_metadata[websocket]["subscriptions"]
                for topic in subscriptions:
                    if topic in self.topic_subscriptions:
                        self.topic_subscriptions[topic].discard(websocket)

                del self.connection_metadata[websocket]

            logger.info(f"WebSocket disconnected: {len(self.active_connections)} total connections")

    async def subscribe(self, websocket: WebSocket, topic: str):
        """
        Subscribe a connection to a topic.

        Args:
            websocket: WebSocket connection
            topic: Topic to subscribe to
        """
        if websocket in self.active_connections:
            self.topic_subscriptions[topic].add(websocket)
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]["subscriptions"].add(topic)
            logger.debug(f"WebSocket subscribed to topic: {topic}")

    async def unsubscribe(self, websocket: WebSocket, topic: str):
        """
        Unsubscribe a connection from a topic.

        Args:
            websocket: WebSocket connection
            topic: Topic to unsubscribe from
        """
        if topic in self.topic_subscriptions:
            self.topic_subscriptions[topic].discard(websocket)

        if websocket in self.connection_metadata:
            self.connection_metadata[websocket]["subscriptions"].discard(topic)

        logger.debug(f"WebSocket unsubscribed from topic: {topic}")

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """
        Send a message to a specific connection.

        Args:
            message: Message to send
            websocket: Target WebSocket connection
        """
        if websocket not in self.active_connections:
            return

        try:
            await websocket.send_text(json.dumps(message))

            # Update message count
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]["message_count"] += 1

        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")
            await self.disconnect(websocket)

    async def broadcast_to_topic(self, topic: str, message: dict):
        """
        Broadcast a message to all connections subscribed to a topic.

        Args:
            topic: Topic to broadcast to
            message: Message to broadcast
        """
        if topic not in self.topic_subscriptions:
            return

        connections_to_remove = []
        message_text = json.dumps(message)

        for websocket in self.topic_subscriptions[topic].copy():
            try:
                await websocket.send_text(message_text)

                # Update message count
                if websocket in self.connection_metadata:
                    self.connection_metadata[websocket]["message_count"] += 1

            except Exception as e:
                logger.warning(f"Failed to send broadcast message: {e}")
                connections_to_remove.append(websocket)

        # Clean up failed connections
        for websocket in connections_to_remove:
            await self.disconnect(websocket)

        if connections_to_remove:
            logger.info(f"Removed {len(connections_to_remove)} failed WebSocket connections")

    async def broadcast_to_all(self, message: dict):
        """
        Broadcast a message to all active connections.

        Args:
            message: Message to broadcast
        """
        if not self.active_connections:
            return

        connections_to_remove = []
        message_text = json.dumps(message)

        for websocket in self.active_connections.copy():
            try:
                await websocket.send_text(message_text)

                # Update message count
                if websocket in self.connection_metadata:
                    self.connection_metadata[websocket]["message_count"] += 1

            except Exception as e:
                logger.warning(f"Failed to send broadcast message: {e}")
                connections_to_remove.append(websocket)

        # Clean up failed connections
        for websocket in connections_to_remove:
            await self.disconnect(websocket)

    def get_connection_count(self) -> int:
        """Get the current number of active connections."""
        return len(self.active_connections)

    def get_topic_subscription_count(self, topic: str) -> int:
        """Get the number of connections subscribed to a topic."""
        return len(self.topic_subscriptions.get(topic, set()))

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get comprehensive connection statistics."""
        now = datetime.now()
        total_messages = sum(
            metadata["message_count"]
            for metadata in self.connection_metadata.values()
        )

        # Calculate connection durations
        durations = []
        for metadata in self.connection_metadata.values():
            duration = (now - metadata["connected_at"]).total_seconds()
            durations.append(duration)

        avg_duration = sum(durations) / len(durations) if durations else 0

        return {
            "total_connections": len(self.active_connections),
            "max_connections": self.max_connections,
            "total_messages_sent": total_messages,
            "average_connection_duration": avg_duration,
            "topic_subscriptions": {
                topic: len(connections)
                for topic, connections in self.topic_subscriptions.items()
            },
            "connection_utilization": len(self.active_connections) / self.max_connections
        }


class WebSocketManager:
    """High-level WebSocket manager with event processing."""

    def __init__(self):
        """Initialize WebSocket manager."""
        self.connection_manager = ConnectionManager()
        self.event_queue = asyncio.Queue()
        self.processing_task: Optional[asyncio.Task] = None
        self.running = False

    async def start(self):
        """Start the WebSocket manager and event processing."""
        if self.running:
            return

        self.running = True
        self.processing_task = asyncio.create_task(self._process_events())
        logger.info("WebSocket manager started")

    async def stop(self):
        """Stop the WebSocket manager."""
        self.running = False

        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass

        # Disconnect all connections
        for websocket in list(self.connection_manager.active_connections):
            await self.connection_manager.disconnect(websocket)

        logger.info("WebSocket manager stopped")

    async def handle_websocket(self, websocket: WebSocket, user_id: Optional[str] = None):
        """
        Handle a WebSocket connection lifecycle.

        Args:
            websocket: WebSocket connection
            user_id: Optional user ID
        """
        connected = await self.connection_manager.connect(websocket, user_id)
        if not connected:
            return

        try:
            while True:
                # Listen for client messages
                message = await websocket.receive_text()
                await self._handle_client_message(websocket, message)

        except WebSocketDisconnect:
            await self.connection_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            await self.connection_manager.disconnect(websocket)

    async def _handle_client_message(self, websocket: WebSocket, message: str):
        """
        Handle a message from a client.

        Args:
            websocket: WebSocket connection
            message: Message from client
        """
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "subscribe":
                topic = data.get("topic")
                if topic:
                    await self.connection_manager.subscribe(websocket, topic)

            elif msg_type == "unsubscribe":
                topic = data.get("topic")
                if topic:
                    await self.connection_manager.unsubscribe(websocket, topic)

            elif msg_type == "ping":
                await self.connection_manager.send_personal_message(
                    {"type": "pong", "timestamp": datetime.now().isoformat()},
                    websocket
                )

        except json.JSONDecodeError:
            logger.warning("Received invalid JSON from WebSocket client")
        except Exception as e:
            logger.error(f"Error handling client message: {e}")

    async def _process_events(self):
        """Process events from the event queue."""
        while self.running:
            try:
                # Wait for events with timeout
                event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                await self._broadcast_event(event)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing WebSocket event: {e}")

    async def _broadcast_event(self, event: Dict[str, Any]):
        """
        Broadcast an event to appropriate subscribers.

        Args:
            event: Event to broadcast
        """
        event_type = event.get("type")

        if event_type == "auth_event":
            await self.connection_manager.broadcast_to_topic("auth_events", event)
        elif event_type == "metrics":
            await self.connection_manager.broadcast_to_topic("dashboard_metrics", event)
        elif event_type == "system_status":
            await self.connection_manager.broadcast_to_topic("system_status", event)
        elif event_type == "security_alert":
            await self.connection_manager.broadcast_to_topic("security_alerts", event)
        else:
            # Broadcast to all for unknown event types
            await self.connection_manager.broadcast_to_all(event)

    async def send_auth_event(self, event_data: Dict[str, Any]):
        """
        Send an authentication event to subscribers.

        Args:
            event_data: Authentication event data
        """
        event = {
            "type": "auth_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat()
        }
        await self.event_queue.put(event)

    async def send_metrics_update(self, metrics: Dict[str, Any]):
        """
        Send a metrics update to subscribers.

        Args:
            metrics: Metrics data
        """
        event = {
            "type": "metrics",
            "data": metrics,
            "timestamp": datetime.now().isoformat()
        }
        await self.event_queue.put(event)

    async def send_system_status(self, status: Dict[str, Any]):
        """
        Send a system status update to subscribers.

        Args:
            status: System status data
        """
        event = {
            "type": "system_status",
            "data": status,
            "timestamp": datetime.now().isoformat()
        }
        await self.event_queue.put(event)

    async def send_security_alert(self, alert: Dict[str, Any]):
        """
        Send a security alert to subscribers.

        Args:
            alert: Security alert data
        """
        event = {
            "type": "security_alert",
            "data": alert,
            "timestamp": datetime.now().isoformat()
        }
        await self.event_queue.put(event)

    def get_stats(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics."""
        return {
            "running": self.running,
            "queue_size": self.event_queue.qsize(),
            **self.connection_manager.get_connection_stats()
        }


# Global WebSocket manager instance
_websocket_manager: Optional[WebSocketManager] = None


async def start_websocket_manager():
    """Start the global WebSocket manager."""
    global _websocket_manager

    if _websocket_manager is not None and _websocket_manager.running:
        logger.warning("WebSocket manager is already running")
        return

    _websocket_manager = WebSocketManager()
    await _websocket_manager.start()


async def stop_websocket_manager():
    """Stop the global WebSocket manager."""
    global _websocket_manager

    if _websocket_manager is not None:
        await _websocket_manager.stop()
        _websocket_manager = None


def get_websocket_manager() -> Optional[WebSocketManager]:
    """Get the global WebSocket manager instance."""
    return _websocket_manager


def get_connection_manager() -> Optional[ConnectionManager]:
    """Get the global connection manager instance."""
    if _websocket_manager:
        return _websocket_manager.connection_manager
    return None


# Convenience functions for sending events
async def send_auth_event(event_data: Dict[str, Any]):
    """Send an authentication event (convenience function)."""
    if _websocket_manager:
        await _websocket_manager.send_auth_event(event_data)


async def send_metrics_update(metrics: Dict[str, Any]):
    """Send a metrics update (convenience function)."""
    if _websocket_manager:
        await _websocket_manager.send_metrics_update(metrics)


async def send_system_status(status: Dict[str, Any]):
    """Send a system status update (convenience function)."""
    if _websocket_manager:
        await _websocket_manager.send_system_status(status)


async def send_security_alert(alert: Dict[str, Any]):
    """Send a security alert (convenience function)."""
    if _websocket_manager:
        await _websocket_manager.send_security_alert(alert)