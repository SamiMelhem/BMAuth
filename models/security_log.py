"""Security log model for audit trails and security monitoring."""

import uuid
from enum import Enum
from typing import Dict, Optional

from sqlalchemy import Column, DateTime, ForeignKey, String, Text, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class SecurityEventType(str, Enum):
    """Types of security events to log."""

    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"

    # Registration events
    REGISTRATION_START = "registration_start"
    REGISTRATION_SUCCESS = "registration_success"
    REGISTRATION_FAILED = "registration_failed"

    # Credential management
    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_UPDATED = "credential_updated"
    CREDENTIAL_DELETED = "credential_deleted"
    CREDENTIAL_DISABLED = "credential_disabled"

    # Security events
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFIED = "email_verified"

    # Suspicious activity
    MULTIPLE_FAILED_ATTEMPTS = "multiple_failed_attempts"
    UNUSUAL_LOCATION = "unusual_location"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    POTENTIAL_ATTACK = "potential_attack"

    # System events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"


class SecurityLog(Base):
    """
    Security log model for storing audit trails and security events.

    This model tracks all security-related events for compliance,
    monitoring, and incident response purposes.
    """

    __tablename__ = "security_logs"

    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique log entry identifier"
    )

    # User reference (nullable for system events)
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        doc="Reference to the user (if applicable)"
    )

    # Event information
    event_type = Column(
        String(50),
        nullable=False,
        index=True,
        doc="Type of security event"
    )

    event_description = Column(
        Text,
        nullable=False,
        doc="Detailed description of the event"
    )

    # Request context
    ip_address = Column(
        String(45),  # IPv6 compatible
        nullable=True,
        index=True,
        doc="IP address of the request"
    )

    user_agent = Column(
        Text,
        nullable=True,
        doc="User agent string from the request"
    )

    session_id = Column(
        String(255),
        nullable=True,
        index=True,
        doc="Session identifier"
    )

    request_id = Column(
        String(255),
        nullable=True,
        index=True,
        doc="Request trace identifier"
    )

    # Additional metadata
    event_metadata = Column(
        JSON,
        nullable=True,
        doc="Additional event metadata (JSON)"
    )

    # Risk assessment
    risk_level = Column(
        String(20),
        nullable=False,
        default="low",
        doc="Risk level: low, medium, high, critical"
    )

    # Timestamp
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
        doc="Event timestamp"
    )

    # Relationships
    user = relationship(
        "User",
        back_populates="security_logs",
        doc="User associated with this event"
    )

    def __repr__(self) -> str:
        """String representation of security log."""
        return f"<SecurityLog(id={self.id}, event_type='{self.event_type}')>"

    @classmethod
    def create_log(
        cls,
        event_type: SecurityEventType,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict] = None,
        risk_level: str = "low",
    ) -> "SecurityLog":
        """
        Create a new security log entry.

        Args:
            event_type: Type of security event
            description: Detailed description
            user_id: User ID (if applicable)
            ip_address: Request IP address
            user_agent: Request user agent
            session_id: Session identifier
            request_id: Request trace ID
            metadata: Additional metadata
            risk_level: Risk level assessment

        Returns:
            SecurityLog: New log entry instance
        """
        return cls(
            event_type=event_type.value,
            event_description=description,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            request_id=request_id,
            event_metadata=metadata or {},
            risk_level=risk_level,
        )

    def is_high_risk(self) -> bool:
        """Check if this is a high-risk event."""
        return self.risk_level in ["high", "critical"]

    def is_authentication_event(self) -> bool:
        """Check if this is an authentication-related event."""
        auth_events = {
            SecurityEventType.LOGIN_SUCCESS.value,
            SecurityEventType.LOGIN_FAILED.value,
            SecurityEventType.LOGOUT.value,
            SecurityEventType.REGISTRATION_START.value,
            SecurityEventType.REGISTRATION_SUCCESS.value,
            SecurityEventType.REGISTRATION_FAILED.value,
        }
        return self.event_type in auth_events

    def is_suspicious_activity(self) -> bool:
        """Check if this represents suspicious activity."""
        suspicious_events = {
            SecurityEventType.MULTIPLE_FAILED_ATTEMPTS.value,
            SecurityEventType.UNUSUAL_LOCATION.value,
            SecurityEventType.RATE_LIMIT_EXCEEDED.value,
            SecurityEventType.POTENTIAL_ATTACK.value,
        }
        return self.event_type in suspicious_events