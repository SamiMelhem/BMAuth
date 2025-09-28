"""Authentication endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginResponse, Token
from app.schemas.user import UserCreate, UserResponse
from app.security.auth import create_session_token, get_current_active_user
from app.services.user_service import UserService
from app.services.webauthn_service import WebAuthnService

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Register a new user account.

    Creates a new user account that can be used for WebAuthn registration.
    This endpoint only creates the user - WebAuthn credentials must be
    registered separately using the /webauthn/register endpoints.
    """
    user_service = UserService(db)

    try:
        user = await user_service.create_user(user_data)
        return UserResponse.from_orm(user)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get current user information.

    Returns the profile information for the currently authenticated user.
    """
    return UserResponse.from_orm(current_user)


@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Logout the current user.

    In a production system, this would invalidate the JWT token
    by adding it to a blacklist stored in Redis or database.
    """
    # TODO: Add token to blacklist
    return {"message": "Successfully logged out"}


@router.post("/refresh", response_model=Token)
async def refresh_token(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Refresh the current access token.

    Returns a new access token for the authenticated user.
    """
    token_data = create_session_token(current_user)
    return Token(
        access_token=token_data["access_token"],
        token_type=token_data["token_type"],
        expires_in=token_data["expires_in"],
    )