"""WebAuthn challenge model for storing registration and authentication challenges."""

import uuid
from datetime import datetime, timedelta

from sqlalchemy import Column, DateTime, String, Text
from sqlalchemy.sql import func

from app.database import Base


class WebAuthnChallenge(Base):
    """
    WebAuthn challenge model for storing registration and authentication challenges.
    
    This model stores challenges temporarily to prevent replay attacks
    and ensure proper challenge-response flow.
    """

    __tablename__ = "webauthn_challenges"

    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique challenge identifier"
    )

    # Challenge data
    challenge = Column(
        Text,
        nullable=False,
        index=True,
        doc="Base64 encoded challenge string"
    )

    # User information
    user_id = Column(
        String(36),
        nullable=True,
        index=True,
        doc="User ID (for registration challenges)"
    )

    username = Column(
        String(100),
        nullable=False,
        index=True,
        doc="Username associated with challenge"
    )

    # Challenge metadata
    challenge_type = Column(
        String(20),
        nullable=False,
        index=True,
        doc="Type of challenge (registration or authentication)"
    )

    # Expiration
    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        doc="Challenge expiration time"
    )

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Challenge creation timestamp"
    )

    def __repr__(self) -> str:
        """String representation of challenge."""
        return f"<WebAuthnChallenge(id={self.id}, username='{self.username}', type='{self.challenge_type}')>"

    def is_expired(self) -> bool:
        """Check if challenge has expired."""
        return datetime.utcnow() > self.expires_at.replace(tzinfo=None)

    @classmethod
    def create_challenge(
        cls,
        challenge: str,
        username: str,
        challenge_type: str,
        user_id: str = None,
        expires_in_minutes: int = 5
    ) -> "WebAuthnChallenge":
        """
        Create a new WebAuthn challenge.

        Args:
            challenge: Base64 encoded challenge string
            username: Username associated with challenge
            challenge_type: Type of challenge (registration or authentication)
            user_id: User ID (for registration challenges)
            expires_in_minutes: Challenge expiration time in minutes

        Returns:
            WebAuthnChallenge: New challenge instance
        """
        expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        
        return cls(
            challenge=challenge,
            username=username,
            challenge_type=challenge_type,
            user_id=user_id,
            expires_at=expires_at
        )
