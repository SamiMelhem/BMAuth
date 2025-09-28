"""User model for the biometric authentication system."""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class User(Base):
    """
    User model for storing user account information.

    This model stores core user information and maintains relationships
    with WebAuthn credentials and security logs.
    """

    __tablename__ = "users"

    # Primary key using UUID for better security
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique user identifier"
    )

    # Core user information
    username = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True,
        doc="Unique username for the user"
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        doc="User's email address"
    )

    display_name = Column(
        String(255),
        nullable=False,
        doc="Display name for WebAuthn"
    )

    # Account status
    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        doc="Whether the user account is active"
    )

    is_verified = Column(
        Boolean,
        default=True,
        nullable=False,
        doc="Whether the user's email is verified"
    )

    # Optional backup authentication (for fallback)
    backup_codes_hash = Column(
        Text,
        nullable=True,
        doc="Hashed backup recovery codes"
    )

    totp_secret = Column(
        String(255),
        nullable=True,
        doc="TOTP secret for backup authentication"
    )

    # Security tracking
    failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False,
        doc="Number of failed login attempts"
    )

    last_login_at = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp of last successful login"
    )

    locked_until = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="Account lock expiration time"
    )

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Account creation timestamp"
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="Last account update timestamp"
    )

    # Relationships
    credentials = relationship(
        "WebAuthnCredential",
        back_populates="user",
        cascade="all, delete-orphan",
        doc="User's WebAuthn credentials"
    )

    security_logs = relationship(
        "SecurityLog",
        back_populates="user",
        cascade="all, delete-orphan",
        doc="User's security event logs"
    )

    def __repr__(self) -> str:
        """String representation of user."""
        return f"<User(id={self.id}, username='{self.username}')>"

    @property
    def is_locked(self) -> bool:
        """Check if user account is currently locked."""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def can_authenticate(self) -> bool:
        """Check if user can attempt authentication."""
        return self.is_active and not self.is_locked

    def has_webauthn_credentials(self) -> bool:
        """Check if user has any active WebAuthn credentials."""
        return any(cred.is_active for cred in self.credentials)

    def get_webauthn_user_handle(self) -> str:
        """Get WebAuthn user handle (user ID as string)."""
        return self.id