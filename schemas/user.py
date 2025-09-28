"""User-related Pydantic schemas."""

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, validator


class UserBase(BaseModel):
    """Base user schema with common fields."""

    username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        pattern=r"^[a-zA-Z0-9_-]+$",
        description="Unique username (alphanumeric, underscore, hyphen only)"
    )
    email: EmailStr = Field(..., description="User's email address")
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Display name for WebAuthn"
    )


class UserCreate(UserBase):
    """Schema for user registration."""

    @validator("username")
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if v.lower() in ["admin", "root", "user", "test", "api"]:
            raise ValueError("Username not allowed")
        return v.lower()

    @validator("display_name")
    def validate_display_name(cls, v: str) -> str:
        """Validate display name."""
        if not v.strip():
            raise ValueError("Display name cannot be empty")
        return v.strip()


class UserUpdate(BaseModel):
    """Schema for user profile updates."""

    display_name: Optional[str] = Field(
        None,
        min_length=1,
        max_length=255,
        description="Display name for WebAuthn"
    )
    email: Optional[EmailStr] = Field(None, description="User's email address")

    @validator("display_name")
    def validate_display_name(cls, v: Optional[str]) -> Optional[str]:
        """Validate display name."""
        if v is not None:
            if not v.strip():
                raise ValueError("Display name cannot be empty")
            return v.strip()
        return v


class UserResponse(UserBase):
    """Schema for user data in API responses."""

    id: str = Field(..., description="User's unique identifier")
    is_active: bool = Field(..., description="Whether the account is active")
    is_verified: bool = Field(..., description="Whether the email is verified")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last account update timestamp")
    last_login_at: Optional[datetime] = Field(
        None, description="Last successful login timestamp"
    )

    class Config:
        from_attributes = True


class UserProfile(UserResponse):
    """Extended user profile with additional information."""

    has_webauthn_credentials: bool = Field(
        ..., description="Whether user has WebAuthn credentials"
    )
    credential_count: int = Field(..., description="Number of registered credentials")
    failed_login_attempts: int = Field(
        ..., description="Number of recent failed login attempts"
    )
    is_locked: bool = Field(..., description="Whether the account is locked")

    class Config:
        from_attributes = True


class UserList(BaseModel):
    """Schema for paginated user list."""

    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_prev: bool = Field(..., description="Whether there are previous pages")


class UserStats(BaseModel):
    """Schema for user statistics."""

    total_users: int = Field(..., description="Total number of users")
    active_users: int = Field(..., description="Number of active users")
    verified_users: int = Field(..., description="Number of verified users")
    users_with_credentials: int = Field(
        ..., description="Number of users with WebAuthn credentials"
    )
    recent_registrations: int = Field(
        ..., description="Number of users registered in the last 7 days"
    )