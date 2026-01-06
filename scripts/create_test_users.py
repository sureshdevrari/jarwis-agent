"""
Create Test Users with Different Subscription Plans

Creates 3 test users:
- user1 (Individual plan)
- user2 (Professional plan)  
- user3 (Enterprise plan)

All with password: 12341234
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from database.connection import AsyncSessionLocal, init_db, engine
from database.models import User, Base
from database.auth import hash_password
from sqlalchemy import select, text


# Subscription plan configurations based on PricingPlans.jsx
SUBSCRIPTION_PLANS = {
    "individual": {
        "plan": "individual",
        "max_users": 1,
        "max_websites": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,
        "has_credential_scanning": False,
        "has_chatbot_access": False,
        "has_mobile_pentest": False,
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "professional": {
        "plan": "professional",
        "max_users": 3,
        "max_websites": 10,
        "dashboard_access_days": 365,  # Until plan is active
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,
        "has_mobile_pentest": False,
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "enterprise": {
        "plan": "enterprise",
        "max_users": 999,  # Unlimited
        "max_websites": 999,  # Unlimited
        "dashboard_access_days": 365,  # Until plan is active
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,
        "has_mobile_pentest": True,
        "has_compliance_audits": True,
        "has_dedicated_support": True,
    },
}


# Test users to create
TEST_USERS = [
    {
        "username": "user1",
        "email": "user1@jarwis.ai",
        "password": "12341234",
        "full_name": "Individual User",
        "company": "Personal",
        "plan_type": "individual",
        "approval_status": "approved",
    },
    {
        "username": "user2",
        "email": "user2@jarwis.ai",
        "password": "12341234",
        "full_name": "Professional User",
        "company": "Pro Company Ltd",
        "plan_type": "professional",
        "approval_status": "approved",
    },
    {
        "username": "user3",
        "email": "user3@jarwis.ai",
        "password": "12341234",
        "full_name": "Enterprise User",
        "company": "Enterprise Corp",
        "plan_type": "enterprise",
        "approval_status": "approved",
    },
]


async def recreate_database():
    """Drop and recreate all tables to apply schema changes"""
    print("🔄 Recreating database tables with new schema...")
    async with engine.begin() as conn:
        # Drop all tables
        await conn.run_sync(Base.metadata.drop_all)
        # Create all tables
        await conn.run_sync(Base.metadata.create_all)
    print("[OK] Database tables recreated")


async def create_test_users(recreate_db: bool = False):
    """Create test users with different subscription plans"""
    
    # Recreate database if needed (to apply schema changes)
    if recreate_db:
        await recreate_database()
    else:
        # Just initialize (create tables if not exist)
        await init_db()
    
    async with AsyncSessionLocal() as db:
        created_users = []
        
        for user_data in TEST_USERS:
            # Check if user already exists
            existing = await db.execute(
                select(User).where(
                    (User.email == user_data["email"]) | 
                    (User.username == user_data["username"])
                )
            )
            existing_user = existing.scalar_one_or_none()
            
            if existing_user:
                print(f"[!] User '{user_data['username']}' already exists, updating...")
                # Update existing user
                plan_config = SUBSCRIPTION_PLANS[user_data["plan_type"]]
                existing_user.full_name = user_data["full_name"]
                existing_user.company = user_data["company"]
                existing_user.plan = plan_config["plan"]
                existing_user.max_users = plan_config["max_users"]
                existing_user.max_websites = plan_config["max_websites"]
                existing_user.dashboard_access_days = plan_config["dashboard_access_days"]
                existing_user.has_api_testing = plan_config["has_api_testing"]
                existing_user.has_credential_scanning = plan_config["has_credential_scanning"]
                existing_user.has_chatbot_access = plan_config["has_chatbot_access"]
                existing_user.has_mobile_pentest = plan_config["has_mobile_pentest"]
                existing_user.has_compliance_audits = plan_config["has_compliance_audits"]
                existing_user.has_dedicated_support = plan_config["has_dedicated_support"]
                existing_user.approval_status = user_data["approval_status"]
                existing_user.is_active = True
                existing_user.is_verified = True
                existing_user.hashed_password = hash_password(user_data["password"])
                existing_user.subscription_start = datetime.now(timezone.utc)
                existing_user.subscription_end = datetime.now(timezone.utc) + timedelta(days=365)
                created_users.append((existing_user, "updated"))
            else:
                # Create new user
                plan_config = SUBSCRIPTION_PLANS[user_data["plan_type"]]
                
                new_user = User(
                    username=user_data["username"],
                    email=user_data["email"],
                    hashed_password=hash_password(user_data["password"]),
                    full_name=user_data["full_name"],
                    company=user_data["company"],
                    is_active=True,
                    is_verified=True,
                    plan=plan_config["plan"],
                    max_users=plan_config["max_users"],
                    max_websites=plan_config["max_websites"],
                    dashboard_access_days=plan_config["dashboard_access_days"],
                    has_api_testing=plan_config["has_api_testing"],
                    has_credential_scanning=plan_config["has_credential_scanning"],
                    has_chatbot_access=plan_config["has_chatbot_access"],
                    has_mobile_pentest=plan_config["has_mobile_pentest"],
                    has_compliance_audits=plan_config["has_compliance_audits"],
                    has_dedicated_support=plan_config["has_dedicated_support"],
                    approval_status=user_data["approval_status"],
                    subscription_start=datetime.now(timezone.utc),
                    subscription_end=datetime.now(timezone.utc) + timedelta(days=365),
                )
                db.add(new_user)
                created_users.append((new_user, "created"))
        
        await db.commit()
        
        # Refresh and print results
        print("\n" + "="*60)
        print("TEST USERS CREATED/UPDATED")
        print("="*60)
        
        for user, action in created_users:
            await db.refresh(user)
            print(f"\n[OK] {action.upper()}: {user.username}")
            print(f"  Email: {user.email}")
            print(f"  Plan: {user.plan}")
            print(f"  Status: {user.approval_status}")
            print(f"  Max Users: {user.max_users}")
            print(f"  Max Websites: {user.max_websites}")
            print(f"  Dashboard Days: {user.dashboard_access_days}")
            print(f"  API Testing: {user.has_api_testing}")
            print(f"  Credential Scanning: {user.has_credential_scanning}")
            print(f"  Chatbot Access: {user.has_chatbot_access}")
            print(f"  Mobile Pentest: {user.has_mobile_pentest}")
            print(f"  Compliance: {user.has_compliance_audits}")
            print(f"  Dedicated Support: {user.has_dedicated_support}")
        
        print("\n" + "="*60)
        print("Login credentials for all users:")
        print("Password: 12341234")
        print("="*60 + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Create test users with subscription plans")
    parser.add_argument("--recreate-db", action="store_true", 
                        help="Drop and recreate database tables (WARNING: deletes all data)")
    args = parser.parse_args()
    
    if args.recreate_db:
        print("[!]  WARNING: This will delete all existing data in the database!")
        confirm = input("Type 'yes' to confirm: ")
        if confirm.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)
    
    asyncio.run(create_test_users(recreate_db=args.recreate_db))
