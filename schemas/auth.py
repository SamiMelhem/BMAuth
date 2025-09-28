"""Authentication-related Pydantic schemas."""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Token(BaseModel):
    """JWT token response schema."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")


class TokenData(BaseModel):
    """JWT token payload data."""

    sub: str = Field(..., description="Subject (user ID)")
    username: Optional[str] = Field(None, description="Username")
    exp: datetime = Field(..., description="Token expiration time")
    iat: datetime = Field(..., description="Token issued at time")
    jti: str = Field(..., description="JWT ID")


class LoginResponse(BaseModel):
    """Response schema for successful login."""

    user: dict = Field(..., description="User information")
    token: Token = Field(..., description="Authentication token")
    session_id: str = Field(..., description="Session identifier")


class LogoutRequest(BaseModel):
    """Request schema for logout."""

    session_id: Optional[str] = Field(None, description="Session identifier")


class RefreshTokenRequest(BaseModel):
    """Request schema for token refresh."""

    refresh_token: str = Field(..., description="Refresh token")


class SessionInfo(BaseModel):
    """Session information schema."""

    session_id: str = Field(..., description="Session identifier")
    user_id: str = Field(..., description="User identifier")
    created_at: datetime = Field(..., description="Session creation time")
    last_activity: datetime = Field(..., description="Last activity time")
    ip_address: Optional[str] = Field(None, description="Client IP address")
    user_agent: Optional[str] = Field(None, description="Client user agent")
    is_active: bool = Field(..., description="Whether session is active")


class PasswordResetRequest(BaseModel):
    """Request schema for password reset."""

    email: str = Field(..., description="User's email address")


class PasswordResetConfirm(BaseModel):
    """Schema for password reset confirmation."""

    token: str = Field(..., description="Reset token")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password"
    )


class EmailVerificationRequest(BaseModel):
    """Request schema for email verification."""

    email: str = Field(..., description="Email address to verify")


class EmailVerificationConfirm(BaseModel):
    """Schema for email verification confirmation."""

    token: str = Field(..., description="Verification token")


class ChangePasswordRequest(BaseModel):
    """Request schema for password change."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password"
    )