"""User service for managing user accounts and operations."""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.security_log import SecurityEventType, SecurityLog
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


class UserService:
    """Service class for user-related operations."""

    def __init__(self, db: AsyncSession):
        """Initialize user service with database session."""
        self.db = db

    async def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user account.

        Args:
            user_data: User creation data

        Returns:
            User: Created user object

        Raises:
            ValueError: If username or email already exists
        """
        # Check if username already exists
        existing_user = await self.get_user_by_username(user_data.username)
        if existing_user:
            raise ValueError("Username already exists")

        # Check if email already exists
        existing_email = await self.get_user_by_email(user_data.email)
        if existing_email:
            raise ValueError("Email already exists")

        # Create new user
        user = User(
            username=user_data.username.lower(),
            email=user_data.email.lower(),
            display_name=user_data.display_name,
        )

        self.db.add(user)
        await self.db.flush()  # Flush to get the ID

        # Log user creation
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.USER_CREATED,
            description=f"User account created: {user.username}",
            user_id=user.id,
        )
        self.db.add(security_log)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def get_user_by_id(self, user_id: str) -> Optional[User]:
        """
        Get user by ID.

        Args:
            user_id: User's unique identifier

        Returns:
            User: User object or None if not found
        """
        stmt = (
            select(User)
            .options(selectinload(User.credentials))
            .where(User.id == user_id)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Get user by username.

        Args:
            username: Username to search for

        Returns:
            User: User object or None if not found
        """
        stmt = (
            select(User)
            .options(selectinload(User.credentials))
            .where(User.username == username.lower())
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address.

        Args:
            email: Email address to search for

        Returns:
            User: User object or None if not found
        """
        stmt = (
            select(User)
            .options(selectinload(User.credentials))
            .where(User.email == email.lower())
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def update_user(self, user_id: str, user_data: UserUpdate) -> Optional[User]:
        """
        Update user information.

        Args:
            user_id: User's unique identifier
            user_data: Updated user data

        Returns:
            User: Updated user object or None if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        # Update fields if provided
        if user_data.display_name is not None:
            user.display_name = user_data.display_name

        if user_data.email is not None:
            # Check if new email already exists
            existing_email = await self.get_user_by_email(user_data.email)
            if existing_email and existing_email.id != user_id:
                raise ValueError("Email already exists")
            user.email = user_data.email.lower()
            user.is_verified = False  # Reset verification status

        user.updated_at = datetime.utcnow()

        # Log user update
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.USER_UPDATED,
            description=f"User profile updated: {user.username}",
            user_id=user.id,
        )
        self.db.add(security_log)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def deactivate_user(self, user_id: str) -> Optional[User]:
        """
        Deactivate a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            User: Deactivated user object or None if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        user.is_active = False
        user.updated_at = datetime.utcnow()

        # Log user deactivation
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.USER_DELETED,
            description=f"User account deactivated: {user.username}",
            user_id=user.id,
        )
        self.db.add(security_log)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def record_login_attempt(
        self,
        user: User,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        """
        Record a login attempt for security monitoring.

        Args:
            user: User attempting to log in
            success: Whether the login was successful
            ip_address: Client IP address
            user_agent: Client user agent
        """
        if success:
            # Reset failed attempts and update last login
            user.failed_login_attempts = 0
            user.last_login_at = datetime.utcnow()
            user.locked_until = None

            # Log successful login
            security_log = SecurityLog.create_log(
                event_type=SecurityEventType.LOGIN_SUCCESS,
                description=f"Successful login: {user.username}",
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
            )

        else:
            # Increment failed attempts
            user.failed_login_attempts += 1

            # Lock account after too many failed attempts
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)

                security_log = SecurityLog.create_log(
                    event_type=SecurityEventType.ACCOUNT_LOCKED,
                    description=f"Account locked due to failed attempts: {user.username}",
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    risk_level="high",
                )

            elif user.failed_login_attempts >= 3:
                security_log = SecurityLog.create_log(
                    event_type=SecurityEventType.MULTIPLE_FAILED_ATTEMPTS,
                    description=f"Multiple failed login attempts: {user.username}",
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    risk_level="medium",
                )

            else:
                security_log = SecurityLog.create_log(
                    event_type=SecurityEventType.LOGIN_FAILED,
                    description=f"Failed login attempt: {user.username}",
                    user_id=user.id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

        self.db.add(security_log)
        await self.db.commit()

    async def unlock_user(self, user_id: str) -> Optional[User]:
        """
        Manually unlock a user account.

        Args:
            user_id: User's unique identifier

        Returns:
            User: Unlocked user object or None if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        user.locked_until = None
        user.failed_login_attempts = 0
        user.updated_at = datetime.utcnow()

        # Log account unlock
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.ACCOUNT_UNLOCKED,
            description=f"Account manually unlocked: {user.username}",
            user_id=user.id,
        )
        self.db.add(security_log)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def verify_email(self, user_id: str) -> Optional[User]:
        """
        Mark user's email as verified.

        Args:
            user_id: User's unique identifier

        Returns:
            User: User with verified email or None if not found
        """
        user = await self.get_user_by_id(user_id)
        if not user:
            return None

        user.is_verified = True
        user.updated_at = datetime.utcnow()

        # Log email verification
        security_log = SecurityLog.create_log(
            event_type=SecurityEventType.EMAIL_VERIFIED,
            description=f"Email verified: {user.email}",
            user_id=user.id,
        )
        self.db.add(security_log)

        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def get_users_paginated(
        self,
        page: int = 1,
        per_page: int = 20
    ) -> tuple[List[User], int]:
        """
        Get paginated list of users.

        Args:
            page: Page number (1-based)
            per_page: Items per page

        Returns:
            tuple: List of users and total count
        """
        offset = (page - 1) * per_page

        # Get total count
        count_stmt = select(func.count(User.id))
        count_result = await self.db.execute(count_stmt)
        total = count_result.scalar()

        # Get users for current page
        stmt = (
            select(User)
            .options(selectinload(User.credentials))
            .offset(offset)
            .limit(per_page)
            .order_by(User.created_at.desc())
        )
        result = await self.db.execute(stmt)
        users = result.scalars().all()

        return list(users), total

    async def get_user_stats(self) -> dict:
        """
        Get user statistics.

        Returns:
            dict: User statistics
        """
        # Total users
        total_stmt = select(func.count(User.id))
        total_result = await self.db.execute(total_stmt)
        total_users = total_result.scalar()

        # Active users
        active_stmt = select(func.count(User.id)).where(User.is_active == True)
        active_result = await self.db.execute(active_stmt)
        active_users = active_result.scalar()

        # Verified users
        verified_stmt = select(func.count(User.id)).where(User.is_verified == True)
        verified_result = await self.db.execute(verified_stmt)
        verified_users = verified_result.scalar()

        # Recent registrations (last 7 days)
        recent_date = datetime.utcnow() - timedelta(days=7)
        recent_stmt = select(func.count(User.id)).where(User.created_at >= recent_date)
        recent_result = await self.db.execute(recent_stmt)
        recent_registrations = recent_result.scalar()

        # Users with WebAuthn credentials
        # This would require a join query - simplified for now
        users_with_creds = 0  # TODO: Implement proper query

        return {
            "total_users": total_users,
            "active_users": active_users,
            "verified_users": verified_users,
            "users_with_credentials": users_with_creds,
            "recent_registrations": recent_registrations,
        }