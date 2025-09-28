"""User management endpoints."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.user import UserProfile, UserResponse, UserUpdate
from app.security.auth import get_current_active_user
from app.services.user_service import UserService

router = APIRouter()


@router.get("/profile", response_model=UserProfile)
async def get_user_profile(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Get user profile with additional information.

    Returns extended user profile information including credential count,
    account status, and security information.
    """
    webauthn_credentials = [
        cred for cred in current_user.credentials if cred.is_active
    ]

    profile_data = UserProfile(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        display_name=current_user.display_name,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
        last_login_at=current_user.last_login_at,
        has_webauthn_credentials=len(webauthn_credentials) > 0,
        credential_count=len(webauthn_credentials),
        failed_login_attempts=current_user.failed_login_attempts,
        is_locked=current_user.is_locked,
    )

    return profile_data


@router.put("/profile", response_model=UserResponse)
async def update_user_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Update user profile information.

    Allows updating display name and email address. Email address
    changes will reset the verification status.
    """
    user_service = UserService(db)

    try:
        updated_user = await user_service.update_user(
            user_id=current_user.id,
            user_data=user_update,
        )

        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        return UserResponse.model_validate(updated_user).model_dump()

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/account")
async def deactivate_account(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Deactivate user account.

    Deactivates the current user's account. The account will no longer
    be able to authenticate, but data is preserved for security auditing.
    """
    user_service = UserService(db)

    deactivated_user = await user_service.deactivate_user(current_user.id)

    if not deactivated_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return {"message": "Account deactivated successfully"}


@router.post("/unlock")
async def unlock_account(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Unlock user account.

    Unlocks a locked user account, resetting failed login attempts.
    This is primarily for administrative use or self-service unlock.
    """
    user_service = UserService(db)

    unlocked_user = await user_service.unlock_user(current_user.id)

    if not unlocked_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return {"message": "Account unlocked successfully"}