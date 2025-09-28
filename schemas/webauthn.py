"""WebAuthn-related Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class WebAuthnRegistrationStart(BaseModel):
    """Schema for starting WebAuthn registration."""

    username: str = Field(..., description="Username for registration")
    display_name: str = Field(..., description="Display name for WebAuthn")
    email: str = Field(..., description="User's email address")
    credential_name: Optional[str] = Field(
        None, description="Optional name for this credential"
    )


class WebAuthnRegistrationOptions(BaseModel):
    """Schema for WebAuthn registration options response."""

    challenge: str = Field(..., description="Challenge string (base64)")
    rp: Dict[str, Any] = Field(..., description="Relying Party information")
    user: Dict[str, Any] = Field(..., description="User information")
    pubKeyCredParams: List[Dict[str, Any]] = Field(
        ..., description="Supported public key algorithms"
    )
    authenticatorSelection: Dict[str, Any] = Field(
        ..., description="Authenticator selection criteria"
    )
    attestation: str = Field(..., description="Attestation conveyance preference")
    timeout: int = Field(..., description="Timeout in milliseconds")


class WebAuthnRegistrationComplete(BaseModel):
    """Schema for completing WebAuthn registration."""

    username: str = Field(..., description="Username")
    credential: Dict[str, Any] = Field(
        ..., description="WebAuthn credential creation response"
    )
    credential_name: Optional[str] = Field(
        None, description="Optional name for this credential"
    )


class WebAuthnAuthenticationStart(BaseModel):
    """Schema for starting WebAuthn authentication."""

    username: str = Field(..., description="Username for authentication")


class WebAuthnAuthenticationOptions(BaseModel):
    """Schema for WebAuthn authentication options response."""

    challenge: str = Field(..., description="Challenge string (base64)")
    allowCredentials: List[Dict[str, Any]] = Field(
        ..., description="Allowed credentials for authentication"
    )
    userVerification: str = Field(..., description="User verification requirement")
    timeout: int = Field(..., description="Timeout in milliseconds")


class WebAuthnAuthenticationComplete(BaseModel):
    """Schema for completing WebAuthn authentication."""

    username: str = Field(..., description="Username")
    credential: Dict[str, Any] = Field(
        ..., description="WebAuthn authentication assertion response"
    )


class CredentialResponse(BaseModel):
    """Schema for credential information in responses."""

    id: str = Field(..., description="Credential record ID")
    credential_id: str = Field(..., description="WebAuthn credential ID (base64)", alias="credential_id_str")
    name: Optional[str] = Field(None, description="User-assigned credential name")
    device_type: Optional[str] = Field(None, description="Device type")
    transports: List[str] = Field(default_factory=list, description="Supported transport methods", alias="transports_list")
    backup_eligible: bool = Field(..., description="Whether credential is backup eligible")
    backup_state: bool = Field(..., description="Current backup state")
    is_active: bool = Field(..., description="Whether credential is active")
    last_used_at: Optional[datetime] = Field(
        None, description="Last authentication time"
    )
    usage_count: int = Field(..., description="Number of times used")
    risk_score: int = Field(..., description="Risk score (0-100)")
    created_at: datetime = Field(..., description="Registration timestamp")

    class Config:
        from_attributes = True


class CredentialUpdate(BaseModel):
    """Schema for updating credential information."""

    name: Optional[str] = Field(
        None,
        max_length=255,
        description="User-assigned credential name"
    )
    is_active: Optional[bool] = Field(
        None, description="Whether credential should be active"
    )


class CredentialList(BaseModel):
    """Schema for user's credential list."""

    credentials: List[CredentialResponse] = Field(..., description="User's credentials")
    total: int = Field(..., description="Total number of credentials")
    active_count: int = Field(..., description="Number of active credentials")


class WebAuthnChallenge(BaseModel):
    """Schema for WebAuthn challenge storage."""

    challenge: str = Field(..., description="Challenge string")
    user_id: Optional[str] = Field(None, description="User ID")
    username: str = Field(..., description="Username")
    expires_at: datetime = Field(..., description="Challenge expiration time")
    challenge_type: str = Field(
        ..., description="Type of challenge (registration or authentication)"
    )


class AttestationResult(BaseModel):
    """Schema for attestation verification result."""

    verified: bool = Field(..., description="Whether attestation is verified")
    credential_id: str = Field(..., description="Credential ID")
    public_key: str = Field(..., description="Public key (base64)")
    sign_count: int = Field(..., description="Signature counter")
    aaguid: Optional[str] = Field(None, description="Authenticator AAGUID")
    attestation_type: Optional[str] = Field(None, description="Attestation type")


class AssertionResult(BaseModel):
    """Schema for assertion verification result."""

    verified: bool = Field(..., description="Whether assertion is verified")
    new_sign_count: int = Field(..., description="New signature counter")
    user_id: str = Field(..., description="Authenticated user ID")
    credential_id: str = Field(..., description="Used credential ID")


class WebAuthnStats(BaseModel):
    """Schema for WebAuthn usage statistics."""

    total_credentials: int = Field(..., description="Total registered credentials")
    active_credentials: int = Field(..., description="Active credentials")
    platform_credentials: int = Field(..., description="Platform authenticators")
    cross_platform_credentials: int = Field(..., description="Cross-platform authenticators")
    recent_registrations: int = Field(
        ..., description="Credentials registered in last 7 days"
    )
    recent_authentications: int = Field(
        ..., description="Authentications in last 7 days"
    )