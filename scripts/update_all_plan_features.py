#!/usr/bin/env python3
"""
Update All Users Plan Features

This script updates all existing users in the database to match
the new plan feature definitions from the pricing page.

Plan Summary (from pricing page):
- Free: Corporate email required, admin assigns scan quota, no chatbot, web only
- Individual: 1 website, web scan only, no API/mobile/cloud/network, no chatbot, 7-day access
- Professional: 10 scans (all types), 3 users, chatbot 500K, dashboard until active
- Enterprise: Unlimited everything, chatbot 5M, dedicated support

Run: python scripts/update_all_plan_features.py
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from database.connection import AsyncSessionLocal
from database.models import User


# Plan features configuration matching pricing page
PLAN_FEATURES = {
    "free": {
        "max_websites": 0,  # Admin assigns after approval
        "max_scans_per_month": 0,  # Admin assigns quota
        "max_users": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,
        "has_credential_scanning": False,
        "has_chatbot_access": False,
        "has_mobile_pentest": False,
        "has_cloud_scanning": False,
        "has_network_scanning": False,
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "trial": {
        "max_websites": 0,  # Admin assigns after approval
        "max_scans_per_month": 0,  # Admin assigns quota
        "max_users": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,
        "has_credential_scanning": False,
        "has_chatbot_access": False,
        "has_mobile_pentest": False,
        "has_cloud_scanning": False,
        "has_network_scanning": False,
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "individual": {
        "max_websites": 1,  # 1 website only
        "max_scans_per_month": 1,
        "max_users": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,  # No API testing
        "has_credential_scanning": False,  # No credential-based scanning
        "has_chatbot_access": False,  # No Jarwis AGI
        "has_mobile_pentest": False,  # Web only
        "has_cloud_scanning": False,  # Web only
        "has_network_scanning": False,  # Web only
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "professional": {
        "max_websites": 10,
        "max_scans_per_month": 10,
        "max_users": 3,
        "dashboard_access_days": 0,  # Until plan active
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,  # Suru 1.1 - 500K tokens
        "has_mobile_pentest": True,
        "has_cloud_scanning": True,
        "has_network_scanning": True,
        "has_compliance_audits": True,
        "has_dedicated_support": False,
    },
    "enterprise": {
        "max_websites": 999999,
        "max_scans_per_month": 999999,
        "max_users": 999999,
        "dashboard_access_days": 0,  # Until plan active
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,  # Savi 3.1 - 5M tokens
        "has_mobile_pentest": True,
        "has_cloud_scanning": True,
        "has_network_scanning": True,
        "has_compliance_audits": True,
        "has_dedicated_support": True,
    },
}


async def update_all_users():
    """Update all users with the correct plan features"""
    async with AsyncSessionLocal() as db:
        # Get all users
        result = await db.execute(select(User))
        users = result.scalars().all()
        
        print(f"\n{'='*60}")
        print(f"UPDATING ALL USERS TO MATCH PRICING PAGE")
        print(f"{'='*60}\n")
        
        updated_count = 0
        for user in users:
            plan = user.plan or "free"
            features = PLAN_FEATURES.get(plan, PLAN_FEATURES["free"])
            
            old_chatbot = getattr(user, 'has_chatbot_access', None)
            
            # Apply all features
            user.max_websites = features["max_websites"]
            user.max_users = features["max_users"]
            user.dashboard_access_days = features["dashboard_access_days"]
            user.has_api_testing = features["has_api_testing"]
            user.has_credential_scanning = features["has_credential_scanning"]
            user.has_chatbot_access = features["has_chatbot_access"]
            user.has_mobile_pentest = features["has_mobile_pentest"]
            user.has_compliance_audits = features["has_compliance_audits"]
            user.has_dedicated_support = features["has_dedicated_support"]
            
            # New fields (if they exist in the model)
            if hasattr(user, 'max_scans_per_month'):
                # For free users, preserve any admin-assigned quota
                if plan not in ["free", "trial"]:
                    user.max_scans_per_month = features["max_scans_per_month"]
            if hasattr(user, 'has_cloud_scanning'):
                user.has_cloud_scanning = features["has_cloud_scanning"]
            if hasattr(user, 'has_network_scanning'):
                user.has_network_scanning = features["has_network_scanning"]
            
            updated_count += 1
            
            status_icon = "✓" if features["has_chatbot_access"] else "✗"
            print(f"  [{plan.upper():12}] {user.email}")
            print(f"               Chatbot: {status_icon}")
            print(f"               API Testing: {'✓' if features['has_api_testing'] else '✗'}")
            print(f"               Mobile/Cloud/Network: {'✓' if features['has_mobile_pentest'] else '✗'}")
            print()
        
        await db.commit()
        
        print(f"{'='*60}")
        print(f"UPDATED {updated_count} USERS")
        print(f"{'='*60}")
        
        # Summary
        print("\nPlan Capabilities Summary:")
        print("-" * 60)
        print(f"{'Plan':<15} {'Chat':<8} {'API':<8} {'Mobile':<8} {'Cloud':<8}")
        print("-" * 60)
        for plan_name, feat in PLAN_FEATURES.items():
            if plan_name == "trial":
                continue
            chat = "✓" if feat['has_chatbot_access'] else "✗"
            api = "✓" if feat['has_api_testing'] else "✗"
            mobile = "✓" if feat['has_mobile_pentest'] else "✗"
            cloud = "✓" if feat['has_cloud_scanning'] else "✗"
            print(f"{plan_name.capitalize():<15} {chat:<8} {api:<8} {mobile:<8} {cloud:<8}")
        print("-" * 60)


if __name__ == "__main__":
    asyncio.run(update_all_users())
