#!/usr/bin/env python3
"""
Add Developer User - FOR TESTING ONLY
=====================================
Creates a developer user with unlimited access for testing purposes.

TODO: DELETE THIS USER AND SCRIPT BEFORE PRODUCTION!

Usage:
    python scripts/add_developer_user.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
from database.connection import AsyncSessionLocal
from database.models import User
from database.auth import hash_password
from sqlalchemy import select, update

# Developer credentials
DEV_EMAIL = "dev@jarwis.ai"
DEV_PASSWORD = "12341234"
DEV_PLAN = "developer"


async def add_developer_user():
    """Create or update the developer user with unlimited access."""
    print("=" * 60)
    print("  ADDING DEVELOPER USER (FOR TESTING ONLY)")
    print("=" * 60)
    print()
    
    async with AsyncSessionLocal() as db:
        # Check if user already exists
        result = await db.execute(select(User).where(User.email == DEV_EMAIL))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            print(f"[UPDATE] User {DEV_EMAIL} already exists, updating...")
            await db.execute(
                update(User)
                .where(User.email == DEV_EMAIL)
                .values(
                    hashed_password=hash_password(DEV_PASSWORD),
                    plan=DEV_PLAN,
                    is_active=True,
                    is_verified=True,
                    is_superuser=False,  # NOT admin - regular user with dev plan
                    approval_status="approved",
                    max_scans_per_month=999999999,
                    scans_this_month=0,
                    max_websites=999999,
                    max_users=999999,
                    dashboard_access_days=999999,
                    has_api_testing=True,
                    has_credential_scanning=True,
                    has_chatbot_access=True,
                    has_mobile_pentest=True,
                    has_cloud_scanning=True,
                    has_network_scanning=True,
                )
            )
            await db.commit()
            print(f"[OK] User updated successfully!")
        else:
            print(f"[CREATE] Creating new user {DEV_EMAIL}...")
            new_user = User(
                email=DEV_EMAIL,
                username="developer",  # Required field
                hashed_password=hash_password(DEV_PASSWORD),
                full_name="Developer Account",
                company="Jarwis Internal",
                plan=DEV_PLAN,
                is_active=True,
                is_verified=True,
                is_superuser=False,  # NOT admin - regular user with dev plan
                approval_status="approved",
                max_scans_per_month=999999999,
                scans_this_month=0,
                max_websites=999999,
                max_users=999999,
                dashboard_access_days=999999,
                has_api_testing=True,
                has_credential_scanning=True,
                has_chatbot_access=True,
                has_mobile_pentest=True,
                has_cloud_scanning=True,
                has_network_scanning=True,
            )
            db.add(new_user)
            await db.commit()
            print(f"[OK] User created successfully!")
    
    print()
    print("-" * 60)
    print("  DEVELOPER LOGIN CREDENTIALS")
    print("-" * 60)
    print(f"  Email:    {DEV_EMAIL}")
    print(f"  Password: {DEV_PASSWORD}")
    print(f"  Plan:     {DEV_PLAN} (unlimited everything)")
    print("-" * 60)
    print()
    print("  ⚠️  TODO: DELETE BEFORE PRODUCTION!")
    print()


if __name__ == "__main__":
    asyncio.run(add_developer_user())
