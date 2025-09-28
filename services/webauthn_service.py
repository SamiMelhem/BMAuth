"""WebAuthn service for handling biometric authentication operations."""

import base64
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from app.config import settings
from app.models.security_log import SecurityEventType, SecurityLog
from app.models.user import User
from app.models.webauthn_credential import WebAuthnCredential
from app.models.webauthn_challenge import WebAuthnChallenge as WebAuthnChallengeModel
from app.schemas.webauthn import (
    AttestationResult,
    AssertionResult,
    WebAuthnChallenge,
)


class WebAuthnService:
    """Service class for WebAuthn operations."""

    def __init__(self, db: AsyncSession):
        """Initialize WebAuthn service with database session."""
        self.db = db

    async def start_registration(
        self,
        user: User,
        credential_name: Optional[str] = None
    ) -> Dict:
        """
        Start WebAuthn registration process.

        Args:
            user: User object
            credential_name: Optional name for the credential

        Returns:
            Dict: Registration options for the client
        """
        # Get existing credentials to exclude
        existing_credentials = await self.get_user_credentials(user.id)
        exclude_credentials = [
            PublicKeyCredentialDescriptor(id=cred.credential_id)
            for cred in existing_credentials
            if cred.is_active
        ]

        # Generate registration options
        registration_options = generate_registration_options(
            rp_id=settings.rp_id,
            rp_name=settings.rp_name,
            user_id=user.get_webauthn_user_handle(),
            user_name=user.username,
            user_display_name=user.display_name,
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment="platform",  # Prefer built-in authenticators
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            challenge=secrets.token_bytes(32),
            exclude_credentials=exclude_credentials,
            supported_pub_key_algs=[-7, -257],  # ES256 and RS256
            timeout=60000,  # 60 seconds
        )

        # Store challenge in database
        challenge_data = WebAuthnChallengeModel.create_challenge(
            challenge=base64.b64encode(registration_options.challenge).decode(),
            username=user.username,
            challenge_type="registration",
            user_id=str(user.id),
            expires_in_minutes=5
        )
        self.db.add(challenge_data)
        await self.db.commit()

        # Log registration start
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.REGISTRATION_START,
            description=f"WebAuthn registration started: {user.username}",
            user_id=user.id,
        )
        self.db.add(security_log)
        await self.db.commit()

        return {
            "challenge": base64.b64encode(registration_options.challenge).decode(),
            "rp": {"id": settings.rp_id, "name": settings.rp_name},
            "user": {
                "id": base64.b64encode(user.get_webauthn_user_handle().encode('utf-8')).decode(),
                "name": user.username,
                "displayName": user.display_name,
            },
            "pubKeyCredParams": [
                {"alg": -7, "type": "public-key"},   # ES256
                {"alg": -257, "type": "public-key"}, # RS256
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": True,
                "userVerification": "required",
            },
            "attestation": "direct",
            "excludeCredentials": [
                {
                    "id": base64.b64encode(cred.credential_id).decode(),
                    "type": "public-key",
                    "transports": cred.transports_list,
                }
                for cred in existing_credentials
                if cred.is_active
            ],
            "timeout": 60000,
        }

    async def complete_registration(
        self,
        username: str,
        credential_response: Dict,
        credential_name: Optional[str] = None,
    ) -> AttestationResult:
        """
        Complete WebAuthn registration process.

        Args:
            username: Username
            credential_response: Client credential creation response
            credential_name: Optional name for the credential

        Returns:
            AttestationResult: Registration verification result

        Raises:
            ValueError: If registration fails
        """
        # Get stored challenge from database (most recent one)
        stmt = select(WebAuthnChallengeModel).where(
            WebAuthnChallengeModel.username == username,
            WebAuthnChallengeModel.challenge_type == "registration"
        ).order_by(WebAuthnChallengeModel.created_at.desc()).limit(1)
        
        result = await self.db.execute(stmt)
        challenge_data = result.scalar_one_or_none()
        
        if not challenge_data:
            raise ValueError("Invalid or expired challenge")

        if challenge_data.is_expired():
            # Clean up expired challenge
            await self.db.delete(challenge_data)
            await self.db.commit()
            raise ValueError("Challenge expired")

        # Get user
        user = await self.get_user_by_username(username)
        if not user:
            raise ValueError("User not found")

        try:
            # Verify registration response
            verification = verify_registration_response(
                credential=credential_response,
                expected_challenge=base64.b64decode(challenge_data.challenge),
                expected_origin=settings.origin,
                expected_rp_id=settings.rp_id,
            )

            # Registration verification succeeded if we get here without exception

            # Check if credential already exists
            existing_cred = await self.get_credential_by_id(
                verification.credential_id
            )
            if existing_cred:
                raise ValueError("Credential already registered")

            # Create new credential
            credential = WebAuthnCredential(
                user_id=user.id,
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                aaguid=verification.aaguid.encode('utf-8') if verification.aaguid else None,
                attestation_type=verification.fmt.value if verification.fmt else None,
                transports="internal",  # Default transport
                name=credential_name,
                device_type="platform",  # Assume platform authenticator
                backup_eligible=verification.credential_backed_up,
                backup_state=verification.credential_backed_up,
            )

            self.db.add(credential)

            # Log successful registration
            security_log = SecurityLog.create_log(
                event_type=SecurityEventType.REGISTRATION_SUCCESS,
                description=f"WebAuthn credential registered: {user.username}",
                user_id=user.id,
                metadata={
                    "credential_id": base64.b64encode(verification.credential_id).decode(),
                    "attestation_type": verification.fmt.value if verification.fmt else None,
                    "backup_eligible": verification.credential_backed_up,
                },
            )
            self.db.add(security_log)

            await self.db.commit()
            await self.db.refresh(credential)

            # Clean up challenge
            await self.db.delete(challenge_data)
            await self.db.commit()

            return AttestationResult(
                verified=True,
                credential_id=base64.b64encode(verification.credential_id).decode(),
                public_key=base64.b64encode(verification.credential_public_key).decode(),
                sign_count=verification.sign_count,
                aaguid=verification.aaguid if verification.aaguid else None,
                attestation_type=verification.fmt.value if verification.fmt else None,
            )

        except Exception as e:
            # Log failed registration
            security_log = SecurityLog.create_log(
                event_type=SecurityEventType.REGISTRATION_FAILED,
                description=f"WebAuthn registration failed: {user.username} - {str(e)}",
                user_id=user.id,
                risk_level="medium",
            )
            self.db.add(security_log)
            await self.db.commit()

            # Clean up challenge
            if challenge_data:
                await self.db.delete(challenge_data)
                await self.db.commit()

            raise ValueError(f"Registration failed: {str(e)}")

    async def start_authentication(self, username: str) -> Dict:
        """
        Start WebAuthn authentication process.

        Args:
            username: Username to authenticate

        Returns:
            Dict: Authentication options for the client

        Raises:
            ValueError: If user not found or has no credentials
        """
        # Get user and credentials
        user = await self.get_user_by_username(username)
        if not user or not user.can_authenticate():
            raise ValueError("User not found or cannot authenticate")

        credentials = await self.get_user_credentials(user.id, active_only=True)
        if not credentials:
            raise ValueError("No active credentials found")

        # Generate authentication options
        authentication_options = generate_authentication_options(
            rp_id=settings.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=cred.credential_id,
                    transports=cred.transports_list or ["internal"],
                )
                for cred in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
            challenge=secrets.token_bytes(32),
            timeout=60000,  # 60 seconds
        )

        # Store challenge in database
        challenge_data = WebAuthnChallengeModel.create_challenge(
            challenge=base64.b64encode(authentication_options.challenge).decode(),
            username=user.username,
            challenge_type="authentication",
            user_id=str(user.id),
            expires_in_minutes=5
        )
        self.db.add(challenge_data)
        await self.db.commit()

        return {
            "challenge": base64.b64encode(authentication_options.challenge).decode(),
            "allowCredentials": [
                {
                    "id": base64.b64encode(cred.credential_id).decode(),
                    "type": "public-key",
                    "transports": cred.transports_list or ["internal"],
                }
                for cred in credentials
            ],
            "userVerification": "required",
            "timeout": 60000,
        }

    async def complete_authentication(
        self,
        username: str,
        credential_response: Dict,
    ) -> AssertionResult:
        """
        Complete WebAuthn authentication process.

        Args:
            username: Username
            credential_response: Client authentication assertion response

        Returns:
            AssertionResult: Authentication verification result

        Raises:
            ValueError: If authentication fails
        """
        # Get stored challenge from database (most recent one)
        stmt = select(WebAuthnChallengeModel).where(
            WebAuthnChallengeModel.username == username,
            WebAuthnChallengeModel.challenge_type == "authentication"
        ).order_by(WebAuthnChallengeModel.created_at.desc()).limit(1)
        
        result = await self.db.execute(stmt)
        challenge_data = result.scalar_one_or_none()
        
        if not challenge_data:
            raise ValueError("Invalid or expired challenge")

        if challenge_data.is_expired():
            # Clean up expired challenge
            await self.db.delete(challenge_data)
            await self.db.commit()
            raise ValueError("Challenge expired")

        # Get user
        user = await self.get_user_by_username(username)
        if not user or not user.can_authenticate():
            raise ValueError("User not found or cannot authenticate")

        # Get credential
        try:
            # Fix base64 padding if needed
            credential_id_str = credential_response["id"]
            # Add padding if missing
            missing_padding = len(credential_id_str) % 4
            if missing_padding:
                credential_id_str += '=' * (4 - missing_padding)
            
            credential_id = base64.b64decode(credential_id_str)
        except Exception as e:
            raise ValueError(f"Invalid credential ID format: {e}")
        
        credential = await self.get_credential_by_id(credential_id)
        if not credential or credential.user_id != user.id or not credential.is_active:
            raise ValueError("Invalid credential")

        try:
            # Verify authentication response
            verification = verify_authentication_response(
                credential=credential_response,
                expected_challenge=base64.b64decode(challenge_data.challenge),
                expected_origin=settings.origin,
                expected_rp_id=settings.rp_id,
                credential_public_key=credential.public_key,
                credential_current_sign_count=credential.sign_count,
            )

            # Authentication verification succeeded if we get here without exception

            # Update credential usage
            credential.update_usage()
            credential.sign_count = verification.new_sign_count
            credential.risk_score = credential.calculate_risk_score()

            await self.db.commit()

            # Clean up challenge
            await self.db.delete(challenge_data)
            await self.db.commit()

            return AssertionResult(
                verified=True,
                new_sign_count=verification.new_sign_count,
                user_id=user.id,
                credential_id=base64.b64encode(credential_id).decode(),
            )

        except Exception as e:
            # Clean up challenge
            if challenge_data:
                await self.db.delete(challenge_data)
                await self.db.commit()

            raise ValueError(f"Authentication failed: {str(e)}")

    async def get_user_credentials(
        self,
        user_id: str,
        active_only: bool = False
    ) -> List[WebAuthnCredential]:
        """
        Get user's WebAuthn credentials.

        Args:
            user_id: User's unique identifier
            active_only: Whether to return only active credentials

        Returns:
            List[WebAuthnCredential]: User's credentials
        """
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.user_id == user_id
        )

        if active_only:
            stmt = stmt.where(WebAuthnCredential.is_active == True)

        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_credential_by_id(
        self,
        credential_id: bytes
    ) -> Optional[WebAuthnCredential]:
        """
        Get credential by credential ID.

        Args:
            credential_id: WebAuthn credential ID

        Returns:
            WebAuthnCredential: Credential object or None
        """
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.credential_id == credential_id
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username with credentials loaded."""
        stmt = (
            select(User)
            .options(selectinload(User.credentials))
            .where(User.username == username.lower())
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def disable_credential(
        self,
        credential_id: str,
        user_id: str
    ) -> Optional[WebAuthnCredential]:
        """
        Disable a user's credential.

        Args:
            credential_id: Credential record ID
            user_id: User's unique identifier

        Returns:
            WebAuthnCredential: Disabled credential or None
        """
        stmt = select(WebAuthnCredential).where(
            WebAuthnCredential.id == credential_id,
            WebAuthnCredential.user_id == user_id
        )
        result = await self.db.execute(stmt)
        credential = result.scalar_one_or_none()

        if credential:
            credential.is_active = False
            credential.updated_at = datetime.utcnow()

            # Log credential disabling
            security_log = SecurityLog.create_log(
                event_type=SecurityEventType.CREDENTIAL_DISABLED,
                description=f"WebAuthn credential disabled",
                user_id=user_id,
                metadata={"credential_id": str(credential_id)},
            )
            self.db.add(security_log)

            await self.db.commit()
            await self.db.refresh(credential)

        return credential

    async def cleanup_expired_challenges(self) -> None:
        """Clean up expired challenges from database."""
        stmt = select(WebAuthnChallengeModel).where(
            WebAuthnChallengeModel.expires_at < datetime.utcnow()
        )
        result = await self.db.execute(stmt)
        expired_challenges = result.scalars().all()

        for challenge in expired_challenges:
            await self.db.delete(challenge)
        
        if expired_challenges:
            await self.db.commit()