"""WebAuthn biometric authentication endpoints."""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.user import User
from app.schemas.auth import LoginResponse
from app.schemas.webauthn import (
    CredentialList,
    CredentialResponse,
    WebAuthnAuthenticationComplete,
    WebAuthnAuthenticationOptions,
    WebAuthnAuthenticationStart,
    WebAuthnRegistrationComplete,
    WebAuthnRegistrationOptions,
    WebAuthnRegistrationStart,
)
from app.security.auth import create_session_token, get_current_active_user
from app.services.user_service import UserService
from app.services.webauthn_service import WebAuthnService

router = APIRouter()


@router.post("/register/begin", response_model=WebAuthnRegistrationOptions)
async def begin_webauthn_registration(
    registration_data: WebAuthnRegistrationStart,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Begin WebAuthn credential registration.

    Starts the WebAuthn registration ceremony by generating registration
    options that the client can use to create a new credential with
    biometric authentication.

    The client should call navigator.credentials.create() with these options
    to register a new biometric credential (fingerprint, face, etc.).
    """
    user_service = UserService(db)
    webauthn_service = WebAuthnService(db)

    # Check if user already exists
    user = await user_service.get_user_by_username(registration_data.username)
    if user:
        # User already exists - check if they have credentials
        existing_credentials = await webauthn_service.get_user_credentials(user.id)
        if existing_credentials:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User already has an account with biometric credentials. Please use the login tab instead."
            )
        # User exists but has no credentials - allow adding a credential
    else:
        # Create new user for WebAuthn registration
        try:
            from app.schemas.user import UserCreate
            user_create = UserCreate(
                username=registration_data.username,
                email=registration_data.email,
                display_name=registration_data.display_name,
            )
            user = await user_service.create_user(user_create)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e)
            )

    try:
        options = await webauthn_service.start_registration(
            user=user,
            credential_name=registration_data.credential_name,
        )
        return WebAuthnRegistrationOptions(**options)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/register/complete", response_model=CredentialResponse)
async def complete_webauthn_registration(
    registration_data: WebAuthnRegistrationComplete,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Complete WebAuthn credential registration.

    Verifies the credential creation response from the client and stores
    the new biometric credential in the database. The credential can then
    be used for future authentications.
    """
    webauthn_service = WebAuthnService(db)

    try:
        result = await webauthn_service.complete_registration(
            username=registration_data.username,
            credential_response=registration_data.credential,
            credential_name=registration_data.credential_name,
        )

        if not result.verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration verification failed"
            )

        # Get the newly created credential for response
        user = await webauthn_service.get_user_by_username(registration_data.username)
        credentials = await webauthn_service.get_user_credentials(user.id)
        latest_credential = max(credentials, key=lambda c: c.created_at)

        # Fix: Use by_alias=True to ensure credential_id_str is included
        return CredentialResponse.model_validate(latest_credential).model_dump(by_alias=True)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/authenticate/begin", response_model=WebAuthnAuthenticationOptions)
async def begin_webauthn_authentication(
    auth_data: WebAuthnAuthenticationStart,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Begin WebAuthn authentication.

    Starts the WebAuthn authentication ceremony by generating authentication
    options. The client can use these options to authenticate using a
    previously registered biometric credential.

    The client should call navigator.credentials.get() with these options
    to authenticate using biometric data (fingerprint, face, etc.).
    """
    webauthn_service = WebAuthnService(db)

    try:
        options = await webauthn_service.start_authentication(auth_data.username)
        return WebAuthnAuthenticationOptions(**options)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/authenticate/complete", response_model=LoginResponse)
async def complete_webauthn_authentication(
    auth_data: WebAuthnAuthenticationComplete,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Complete WebAuthn authentication.

    Verifies the authentication assertion from the client and, if successful,
    returns a JWT access token that can be used for API authentication.

    This completes the biometric login process - the user is now authenticated
    and can access protected endpoints using the returned token.
    """
    webauthn_service = WebAuthnService(db)
    user_service = UserService(db)

    try:
        result = await webauthn_service.complete_authentication(
            username=auth_data.username,
            credential_response=auth_data.credential,
        )

        if not result.verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication verification failed"
            )

        # Get user for token creation
        user = await user_service.get_user_by_id(result.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Record successful login
        client_ip = getattr(request.client, 'host', None) if request.client else None
        user_agent = request.headers.get('user-agent')

        await user_service.record_login_attempt(
            user=user,
            success=True,
            ip_address=client_ip,
            user_agent=user_agent,
        )

        # Refresh user to get updated fields
        await db.refresh(user)

        # Create session token
        token_data = create_session_token(user)

        from app.schemas.user import UserResponse
        from app.schemas.auth import Token

        return LoginResponse(
            user=UserResponse.model_validate(user).model_dump(),
            token=Token(
                access_token=token_data["access_token"],
                token_type=token_data["token_type"],
                expires_in=token_data["expires_in"],
            ),
            session_id=token_data.get("session_id", ""),
        )

    except ValueError as e:
        # Record failed login attempt
        try:
            user = await webauthn_service.get_user_by_username(auth_data.username)
            if user:
                client_ip = getattr(request.client, 'host', None) if request.client else None
                user_agent = request.headers.get('user-agent')

                await user_service.record_login_attempt(
                    user=user,
                    success=False,
                    ip_address=client_ip,
                    user_agent=user_agent,
                )
        except Exception:
            pass  # Don't fail the response if logging fails

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.get("/credentials", response_model=CredentialList)
async def get_user_credentials(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Get current user's WebAuthn credentials.

    Returns a list of all registered biometric credentials for the
    authenticated user, including metadata like last usage and device type.
    """
    webauthn_service = WebAuthnService(db)

    credentials = await webauthn_service.get_user_credentials(current_user.id)
    credential_responses = [
        CredentialResponse.model_validate(cred).model_dump(by_alias=True) for cred in credentials
    ]

    return CredentialList(
        credentials=credential_responses,
        total=len(credential_responses),
        active_count=len([c for c in credential_responses if c["is_active"]]),
    )


@router.delete("/credentials/{credential_id}")
async def disable_credential(
    credential_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Disable a WebAuthn credential.

    Disables the specified credential so it can no longer be used for
    authentication. This is useful for removing compromised or unused
    biometric credentials.
    """
    webauthn_service = WebAuthnService(db)

    try:
        cred_uuid = credential_id

        credential = await webauthn_service.disable_credential(
            credential_id=cred_uuid,
            user_id=current_user.id,
        )

        if not credential:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Credential not found"
            )

        return {"message": "Credential disabled successfully"}

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid credential ID"
        )