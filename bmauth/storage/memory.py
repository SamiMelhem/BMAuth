"""
In-memory storage backend used by default for BMAuth.
"""
from __future__ import annotations

from threading import RLock
from typing import Any, Dict, Optional

from .base import StorageBackend


class InMemoryStorage(StorageBackend):
    """
    Non-persistent storage suitable for demos and tests.
    """

    def __init__(self) -> None:
        self._users: Dict[str, Dict[str, Any]] = {}
        self._challenges: Dict[str, str] = {}
        self._pins: Dict[str, Dict[str, Any]] = {}
        self._device_sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            user = self._users.get(email)
            return None if user is None else user.copy()

    def save_user(self, email: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._users[email] = payload.copy()

    def delete_user(self, email: str) -> None:
        with self._lock:
            self._users.pop(email, None)

    def get_challenge(self, email: str) -> Optional[str]:
        with self._lock:
            return self._challenges.get(email)

    def set_challenge(self, email: str, challenge: str) -> None:
        with self._lock:
            self._challenges[email] = challenge

    def delete_challenge(self, email: str) -> None:
        with self._lock:
            self._challenges.pop(email, None)

    def get_verification_pin(self, email: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            data = self._pins.get(email)
            return None if data is None else data.copy()

    def set_verification_pin(self, email: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._pins[email] = payload.copy()

    def delete_verification_pin(self, email: str) -> None:
        with self._lock:
            self._pins.pop(email, None)

    def get_device_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._device_sessions.get(session_id)
            return None if session is None else session.copy()

    def set_device_session(self, session_id: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            self._device_sessions[session_id] = payload.copy()

    def delete_device_session(self, session_id: str) -> None:
        with self._lock:
            self._device_sessions.pop(session_id, None)

    def debug_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "backend": "in-memory",
                "users": {k: v.copy() for k, v in self._users.items()},
                "challenges": self._challenges.copy(),
                "verification_pins": {
                    k: v.copy() for k, v in self._pins.items()
                },
                "device_sessions": {
                    k: v.copy() for k, v in self._device_sessions.items()
                },
            }


