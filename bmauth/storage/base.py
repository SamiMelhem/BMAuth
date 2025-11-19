"""
Base interfaces for BMAuth storage backends.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class StorageError(RuntimeError):
    """Generic storage-related error."""


class StorageBackend(ABC):
    """
    Abstract base class for BMAuth persistence.

    Implementations must provide durable storage for:
    - user records (including device metadata)
    - WebAuthn challenges
    - pending email verification PINs
    - cross-device session state
    """

    # region User helpers
    @abstractmethod
    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        """Return the stored user payload or None."""

    @abstractmethod
    def save_user(self, email: str, payload: Dict[str, Any]) -> None:
        """Persist the complete user payload (overwrites existing)."""

    @abstractmethod
    def delete_user(self, email: str) -> None:
        """Remove the user record if it exists."""

    # endregion

    # region WebAuthn challenges
    @abstractmethod
    def get_challenge(self, email: str) -> Optional[str]:
        """Return the pending challenge for the email or None."""

    @abstractmethod
    def set_challenge(self, email: str, challenge: str) -> None:
        """Persist a challenge for the email."""

    @abstractmethod
    def delete_challenge(self, email: str) -> None:
        """Delete the pending challenge for the email."""

    # endregion

    # region Verification PINs
    @abstractmethod
    def get_verification_pin(self, email: str) -> Optional[Dict[str, Any]]:
        """Return the verification PIN payload or None."""

    @abstractmethod
    def set_verification_pin(self, email: str, payload: Dict[str, Any]) -> None:
        """Persist the verification PIN payload."""

    @abstractmethod
    def delete_verification_pin(self, email: str) -> None:
        """Delete the verification PIN payload."""

    # endregion

    # region Device sessions
    @abstractmethod
    def get_device_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return the device session payload or None."""

    @abstractmethod
    def set_device_session(self, session_id: str, payload: Dict[str, Any]) -> None:
        """Persist the device session payload."""

    @abstractmethod
    def delete_device_session(self, session_id: str) -> None:
        """Delete a stored device session."""

    # endregion

    # region Introspection
    @abstractmethod
    def debug_snapshot(self) -> Dict[str, Any]:
        """
        Return a JSON-serialisable snapshot of the storage backend.

        Intended for diagnostics only; implementations should avoid exposing
        sensitive credentials.
        """

    # endregion

