"""WebAuthn credential model for storing user authenticator credentials."""

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class WebAuthnCredential(Base):
    """
    WebAuthn credential model for storing authenticator credentials.

    This model stores the public key credentials generated during WebAuthn
    registration and the metadata required for authentication verification.
    """

    __tablename__ = "webauthn_credentials"

    # Primary key
    id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
        doc="Unique credential record identifier"
    )

    # Foreign key to user
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        doc="Reference to the user who owns this credential"
    )

    # WebAuthn credential data
    credential_id = Column(
        LargeBinary,
        unique=True,
        nullable=False,
        index=True,
        doc="WebAuthn credential ID (binary)"
    )

    public_key = Column(
        LargeBinary,
        nullable=False,
        doc="Public key for verifying assertions (CBOR encoded)"
    )

    sign_count = Column(
        Integer,
        default=0,
        nullable=False,
        doc="Signature counter for replay attack prevention"
    )

    # Authenticator metadata
    aaguid = Column(
        LargeBinary,
        nullable=True,
        doc="Authenticator AAGUID"
    )

    attestation_type = Column(
        String(50),
        nullable=True,
        doc="Type of attestation (basic, self, attca, ecdaa)"
    )

    attestation_trust_path = Column(
        Text,
        nullable=True,
        doc="Attestation certificate chain (JSON)"
    )

    # Transport methods
    transports = Column(
        String(255),
        nullable=True,
        doc="Supported transport methods (comma-separated)"
    )

    # Credential metadata
    name = Column(
        String(255),
        nullable=True,
        doc="User-friendly name for this credential"
    )

    device_type = Column(
        String(50),
        nullable=True,
        doc="Type of device (platform, cross-platform)"
    )

    backup_eligible = Column(
        Boolean,
        default=False,
        nullable=False,
        doc="Whether credential is backup eligible"
    )

    backup_state = Column(
        Boolean,
        default=False,
        nullable=False,
        doc="Whether credential is currently backed up"
    )

    # Security and lifecycle
    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
        doc="Whether this credential is active and can be used"
    )

    last_used_at = Column(
        DateTime(timezone=True),
        nullable=True,
        doc="Timestamp of last successful authentication"
    )

    usage_count = Column(
        Integer,
        default=0,
        nullable=False,
        doc="Number of times this credential has been used"
    )

    # Risk assessment
    risk_score = Column(
        Integer,
        default=0,
        nullable=False,
        doc="Risk score based on usage patterns (0-100)"
    )

    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        doc="Credential registration timestamp"
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        doc="Last credential update timestamp"
    )

    # Relationships
    user = relationship(
        "User",
        back_populates="credentials",
        doc="User who owns this credential"
    )

    def __repr__(self) -> str:
        """String representation of credential."""
        return f"<WebAuthnCredential(id={self.id}, user_id={self.user_id})>"

    @property
    def credential_id_b64(self) -> str:
        """Get credential ID as base64 string."""
        import base64
        return base64.b64encode(self.credential_id).decode('utf-8')
    
    @property
    def credential_id_str(self) -> str:
        """Get credential ID as base64 string for API responses."""
        return self.credential_id_b64

    @property
    def transports_list(self) -> List[str]:
        """Get transports as a list."""
        if not self.transports:
            return []
        return [t.strip() for t in self.transports.split(",") if t.strip()]

    @transports_list.setter
    def transports_list(self, transports: List[str]) -> None:
        """Set transports from a list."""
        self.transports = ",".join(transports) if transports else None

    def is_recent_registration(self, days: int = 7) -> bool:
        """Check if credential was registered recently."""
        if not self.created_at:
            return False
        delta = datetime.utcnow() - self.created_at.replace(tzinfo=None)
        return delta.days <= days

    def update_usage(self) -> None:
        """Update usage statistics after successful authentication."""
        self.last_used_at = datetime.utcnow()
        self.usage_count += 1

    def can_authenticate(self) -> bool:
        """Check if credential can be used for authentication."""
        return self.is_active and self.user and self.user.can_authenticate()

    def calculate_risk_score(self) -> int:
        """Calculate risk score based on various factors."""
        score = 0

        # Age factor (newer credentials are riskier)
        if self.is_recent_registration(1):
            score += 20
        elif self.is_recent_registration(7):
            score += 10

        # Usage pattern factor
        if self.usage_count == 0:
            score += 15
        elif self.usage_count < 5:
            score += 5

        # Transport factor (some transports are riskier)
        if "usb" in self.transports_list:
            score -= 5  # USB is generally more secure
        if "nfc" in self.transports_list:
            score += 5  # NFC has some risks

        # Backup state factor
        if not self.backup_eligible:
            score += 10

        return min(max(score, 0), 100)  # Clamp between 0-100