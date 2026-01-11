"""
Auth Service

Authentication business logic separated from HTTP handling.
"""

import logging
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User
from database.auth import (
    authenticate_user, create_user, create_access_token,
    create_refresh_token, hash_password, verify_password,
    store_refresh_token, verify_refresh_token, revoke_refresh_token,
    get_user_by_email, get_user_by_id
)

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Authentication error"""
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthService:
    """
    Authentication service.
    
    Handles all auth-related business logic:
    - User registration
    - Login/logout
    - Token management
    - Password changes
    """
    
    @staticmethod
    async def register_user(
        db: AsyncSession,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None,
        company: Optional[str] = None
    ) -> Tuple[User, str]:
        """
        Register a new user.
        
        Returns:
            Tuple of (user, message)
            
        Raises:
            AuthError: If registration fails
        """
        # Check existing email
        existing = await get_user_by_email(db, email)
        if existing:
            raise AuthError("Email already registered", "EMAIL_EXISTS")
        
        # Create user
        user = await create_user(
            db,
            email=email,
            username=username,
            password=password,
            full_name=full_name,
            company=company
        )
        
        logger.info(f"New user registered: {email}")
        
        return user, "Registration successful. Please wait for admin approval."
    
    @staticmethod
    async def login(
        db: AsyncSession,
        email: str,
        password: str,
        client_ip: str = None
    ) -> Dict[str, Any]:
        """
        Authenticate user and generate tokens.
        
        Returns:
            Dict with tokens and user info
            
        Raises:
            AuthError: If authentication fails
        """
        # Authenticate
        user = await authenticate_user(db, email, password)
        
        if not user:
            logger.warning(f"Failed login attempt for {email} from {client_ip}")
            raise AuthError("Invalid email or password", "INVALID_CREDENTIALS")
        
        # Check if account is active
        if not user.is_active:
            raise AuthError("Account is disabled", "ACCOUNT_DISABLED")
        
        # Check approval status
        if hasattr(user, 'approval_status') and user.approval_status == 'pending':
            raise AuthError("Account pending approval", "PENDING_APPROVAL")
        
        if hasattr(user, 'approval_status') and user.approval_status == 'rejected':
            raise AuthError("Account has been rejected", "ACCOUNT_REJECTED")
        
        # Generate tokens
        access_token = create_access_token(data={"sub": str(user.id)})
        refresh_token = create_refresh_token(data={"sub": str(user.id)})
        
        # Store refresh token
        await store_refresh_token(db, user.id, refresh_token)
        
        # Update last login
        user.last_login = datetime.utcnow()
        await db.commit()
        
        logger.info(f"User logged in: {email} from {client_ip}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": 900,  # 15 minutes
            "user": {
                "id": str(user.id),
                "email": user.email,
                "username": user.username,
                "full_name": user.full_name,
                "company": user.company,
                "is_active": user.is_active,
                "is_verified": getattr(user, 'is_verified', False),
                "is_superuser": getattr(user, 'is_superuser', False),
                "plan": getattr(user, 'plan', 'free'),
                "role": AuthService._get_user_role(user),
                "approval_status": getattr(user, 'approval_status', 'approved'),
            },
            "requires_2fa": getattr(user, 'two_factor_enabled', False)
        }
    
    @staticmethod
    def _get_user_role(user: User) -> str:
        """Determine user role"""
        if getattr(user, 'is_superuser', False):
            return 'super_admin'
        if getattr(user, 'is_admin', False):
            return 'admin'
        return 'user'
    
    @staticmethod
    async def refresh_tokens(
        db: AsyncSession,
        refresh_token: str
    ) -> Dict[str, Any]:
        """
        Refresh access token using refresh token.
        
        Returns:
            Dict with new tokens
            
        Raises:
            AuthError: If refresh fails
        """
        # Verify refresh token
        user_id = await verify_refresh_token(db, refresh_token)
        
        if not user_id:
            raise AuthError("Invalid or expired refresh token", "INVALID_REFRESH_TOKEN")
        
        # Get user
        user = await get_user_by_id(db, user_id)
        if not user or not user.is_active:
            raise AuthError("User not found or inactive", "USER_INACTIVE")
        
        # Revoke old refresh token
        await revoke_refresh_token(db, refresh_token)
        
        # Generate new tokens
        new_access_token = create_access_token(data={"sub": str(user.id)})
        new_refresh_token = create_refresh_token(data={"sub": str(user.id)})
        
        # Store new refresh token
        await store_refresh_token(db, user.id, new_refresh_token)
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": 900
        }
    
    @staticmethod
    async def logout(
        db: AsyncSession,
        refresh_token: str
    ) -> bool:
        """Logout by revoking refresh token"""
        await revoke_refresh_token(db, refresh_token)
        return True
    
    @staticmethod
    async def change_password(
        db: AsyncSession,
        user: User,
        current_password: str,
        new_password: str
    ) -> bool:
        """
        Change user password.
        
        Raises:
            AuthError: If current password is wrong
        """
        # Verify current password
        if not verify_password(current_password, user.hashed_password):
            raise AuthError("Current password is incorrect", "WRONG_PASSWORD")
        
        # Update password
        user.hashed_password = hash_password(new_password)
        await db.commit()
        
        logger.info(f"Password changed for user {user.email}")
        
        return True


# Global instance
auth_service = AuthService()
