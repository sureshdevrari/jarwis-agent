"""
User Settings Service

Business logic for user profile, preferences, and data management.
Follows layered architecture: API Routes -> Services -> Database
"""

import io
import json
import logging
import zipfile
from typing import Dict, Any, Optional, List
from datetime import datetime

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User, ScanHistory, LoginHistory, Finding

logger = logging.getLogger(__name__)


class UserSettingsError(Exception):
    """User settings error"""
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class UserSettingsService:
    """
    User settings service.
    
    Handles all user settings business logic:
    - Profile updates
    - Notification preferences
    - Scan preferences
    - Data export (GDPR)
    - Account/data deletion
    """
    
    @staticmethod
    async def update_profile(
        db: AsyncSession,
        user: User,
        profile_data: Dict[str, Any]
    ) -> User:
        """
        Update user profile fields.
        
        Args:
            db: Database session
            user: Current user
            profile_data: Dict with profile fields (bio, job_title, etc.)
            
        Returns:
            Updated user object
        """
        allowed_fields = {
            'bio', 'job_title', 'company', 'phone_number',
            'linkedin_url', 'twitter_url', 'github_url', 'website_url',
            'timezone', 'language'
        }
        
        for field, value in profile_data.items():
            if field in allowed_fields:
                # Validate URLs
                if field.endswith('_url') and value:
                    if not value.startswith(('http://', 'https://')):
                        raise UserSettingsError(
                            f"Invalid URL for {field}. Must start with http:// or https://",
                            "INVALID_URL"
                        )
                setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        
        logger.info(f"Profile updated for user {user.id}")
        return user
    
    @staticmethod
    async def update_notifications(
        db: AsyncSession,
        user: User,
        settings: Dict[str, bool]
    ) -> Dict[str, bool]:
        """
        Update notification preferences.
        
        Args:
            db: Database session
            user: Current user
            settings: Dict of notification settings
            
        Returns:
            Updated notification settings
        """
        # Merge with existing settings
        current = user.notification_settings or {}
        current.update(settings)
        user.notification_settings = current
        
        await db.commit()
        logger.info(f"Notification settings updated for user {user.id}")
        
        return current
    
    @staticmethod
    async def update_preferences(
        db: AsyncSession,
        user: User,
        preferences: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update scan preferences.
        
        Args:
            db: Database session
            user: Current user
            preferences: Dict of scan preferences
            
        Returns:
            Updated preferences
        """
        # Merge with existing preferences
        current = user.scan_preferences or {}
        current.update(preferences)
        user.scan_preferences = current
        
        await db.commit()
        logger.info(f"Scan preferences updated for user {user.id}")
        
        return current
    
    @staticmethod
    async def export_user_data(
        db: AsyncSession,
        user: User
    ) -> io.BytesIO:
        """
        Export all user data as a ZIP file (GDPR compliance).
        
        Args:
            db: Database session
            user: Current user
            
        Returns:
            BytesIO object containing ZIP file
        """
        # Gather user profile data
        profile_data = {
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "company": user.company,
            "bio": user.bio,
            "job_title": user.job_title,
            "plan": user.plan,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "notification_settings": user.notification_settings,
            "scan_preferences": user.scan_preferences,
        }
        
        # Gather scan history
        result = await db.execute(
            select(ScanHistory).where(ScanHistory.user_id == user.id)
        )
        scans = result.scalars().all()
        scans_data = []
        for scan in scans:
            scans_data.append({
                "scan_id": scan.scan_id,
                "target_url": scan.target_url,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "findings_count": scan.findings_count,
            })
        
        # Gather login history
        result = await db.execute(
            select(LoginHistory)
            .where(LoginHistory.user_id == user.id)
            .order_by(LoginHistory.created_at.desc())
            .limit(100)
        )
        logins = result.scalars().all()
        logins_data = []
        for login in logins:
            logins_data.append({
                "ip_address": login.ip_address,
                "device_type": login.device_type,
                "browser": login.browser,
                "location": login.location,
                "success": login.success,
                "created_at": login.created_at.isoformat() if login.created_at else None,
            })
        
        # Create ZIP file in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('profile.json', json.dumps(profile_data, indent=2))
            zip_file.writestr('scans.json', json.dumps(scans_data, indent=2))
            zip_file.writestr('login_history.json', json.dumps(logins_data, indent=2))
            zip_file.writestr('README.txt', f"""
Jarwis Data Export
==================
Exported for: {user.email}
Date: {datetime.utcnow().isoformat()}

Contents:
- profile.json: Your profile information
- scans.json: Your scan history
- login_history.json: Recent login activity

For questions, contact support@jarwis.ai
""")
        
        zip_buffer.seek(0)
        logger.info(f"Data exported for user {user.id}")
        
        return zip_buffer
    
    @staticmethod
    async def delete_user_data(
        db: AsyncSession,
        user: User,
        password: str
    ) -> bool:
        """
        Delete all user scan data while keeping the account.
        
        Args:
            db: Database session
            user: Current user
            password: Password for verification
            
        Returns:
            True if successful
            
        Raises:
            UserSettingsError: If password is invalid
        """
        from database.auth import verify_password
        
        # Verify password
        if not verify_password(password, user.hashed_password):
            raise UserSettingsError("Invalid password", "INVALID_PASSWORD")
        
        # Delete scan history
        await db.execute(
            delete(ScanHistory).where(ScanHistory.user_id == user.id)
        )
        
        # Delete findings
        await db.execute(
            delete(Finding).where(Finding.user_id == user.id)
        )
        
        await db.commit()
        logger.info(f"All scan data deleted for user {user.id}")
        
        return True
    
    @staticmethod
    async def delete_account(
        db: AsyncSession,
        user: User,
        password: str
    ) -> bool:
        """
        Delete user account and all associated data.
        
        Args:
            db: Database session
            user: Current user
            password: Password for verification
            
        Returns:
            True if successful
            
        Raises:
            UserSettingsError: If password is invalid
        """
        from database.auth import verify_password
        
        # Verify password
        if not verify_password(password, user.hashed_password):
            raise UserSettingsError("Invalid password", "INVALID_PASSWORD")
        
        # Delete all associated data
        await db.execute(
            delete(ScanHistory).where(ScanHistory.user_id == user.id)
        )
        await db.execute(
            delete(Finding).where(Finding.user_id == user.id)
        )
        await db.execute(
            delete(LoginHistory).where(LoginHistory.user_id == user.id)
        )
        
        # Delete the user
        await db.delete(user)
        await db.commit()
        
        logger.info(f"Account deleted for user {user.id}")
        return True
    
    @staticmethod
    async def get_user_stats(
        db: AsyncSession,
        user: User
    ) -> Dict[str, Any]:
        """
        Get user statistics for dashboard.
        
        Args:
            db: Database session
            user: Current user
            
        Returns:
            Dict with user stats
        """
        # Count scans
        result = await db.execute(
            select(ScanHistory).where(ScanHistory.user_id == user.id)
        )
        scans = result.scalars().all()
        
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.status == 'completed'])
        total_findings = sum(s.findings_count or 0 for s in scans)
        
        # Get scans by type
        scan_types = {}
        for scan in scans:
            scan_type = scan.scan_type or 'web'
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
            "scans_by_type": scan_types,
            "member_since": user.created_at.isoformat() if user.created_at else None,
        }


# Singleton instance for convenience
user_settings_service = UserSettingsService()
