"""Authentication utilities and JWT token management."""

import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.auth import TokenData
from app.services.user_service import UserService

# Bearer token scheme
security = HTTPBearer(auto_error=False)


def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        data: Token payload data
        expires_delta: Custom expiration time

    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    # Add standard JWT claims
    now = datetime.utcnow()
    to_encode.update({
        "exp": expire,
        "iat": now,
        "jti": str(uuid.uuid4()),  # JWT ID for token tracking
    })
    

    encoded_jwt = jwt.encode(
        to_encode,
        settings.secret_key,
        algorithm=settings.algorithm
    )

    return encoded_jwt


def verify_token(token: str) -> Optional[TokenData]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token string

    Returns:
        TokenData: Decoded token data or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.algorithm]
        )

        # Extract required fields
        sub = payload.get("sub")
        if sub is None:
            return None

        # Convert timestamps to UTC datetime objects
        exp = datetime.utcfromtimestamp(payload.get("exp", 0))
        iat = datetime.utcfromtimestamp(payload.get("iat", 0))
        

        return TokenData(
            sub=sub,
            username=payload.get("username"),
            exp=exp,
            iat=iat,
            jti=payload.get("jti", ""),
        )

    except JWTError:
        return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get the current authenticated user from JWT token.

    Args:
        credentials: HTTP authorization credentials
        db: Database session

    Returns:
        User: Current authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    # Verify token
    token_data = verify_token(credentials.credentials)
    if token_data is None:
        raise credentials_exception

    # Check token expiration
    if datetime.utcnow() > token_data.exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user from database
    user_service = UserService(db)
    try:
        user_id = token_data.sub
        user = await user_service.get_user_by_id(user_id)
    except (ValueError, TypeError):
        raise credentials_exception

    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get the current authenticated and active user.

    Args:
        current_user: Current authenticated user

    Returns:
        User: Current active user

    Raises:
        HTTPException: If user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )

    return current_user


def create_session_token(user: User) -> dict:
    """
    Create session token data for a user.

    Args:
        user: User object

    Returns:
        dict: Token data including access token and metadata
    """
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)

    token_data = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
    }

    access_token = create_access_token(
        data=token_data,
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": int(access_token_expires.total_seconds()),
        "user_id": str(user.id),
        "username": user.username,
    }


async def authenticate_user(
    username: str,
    db: AsyncSession
) -> Optional[User]:
    """
    Authenticate a user by username (for WebAuthn).

    Args:
        username: Username to authenticate
        db: Database session

    Returns:
        User: Authenticated user or None
    """
    user_service = UserService(db)
    user = await user_service.get_user_by_username(username)

    if not user or not user.can_authenticate():
        return None

    return user


def generate_session_id() -> str:
    """Generate a unique session identifier."""
    return str(uuid.uuid4())


class TokenBlacklist:
    """Simple in-memory token blacklist (use Redis in production)."""

    _blacklisted_tokens: set = set()

    @classmethod
    def add_token(cls, jti: str) -> None:
        """Add token to blacklist."""
        cls._blacklisted_tokens.add(jti)

    @classmethod
    def is_blacklisted(cls, jti: str) -> bool:
        """Check if token is blacklisted."""
        return jti in cls._blacklisted_tokens

    @classmethod
    def clear_expired(cls) -> None:
        """Clear expired tokens (implement with proper storage)."""
        # In a real implementation, this would remove expired tokens
        # from Redis or database storage
        pass