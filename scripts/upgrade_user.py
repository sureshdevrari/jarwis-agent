"""Upgrade user plan script"""
import asyncio
import sys
from database.connection import AsyncSessionLocal
from database.models import User
from shared.constants import PLAN_LIMITS
from sqlalchemy import update, select

async def upgrade_user():
    # Get email from args or prompt
    if len(sys.argv) > 1:
        email = sys.argv[1]
    else:
        email = input("Enter user email to upgrade: ").strip()
        
    if not email:
        print("No email provided.")
        return

    # Get plan from args or prompt
    if len(sys.argv) > 2:
        target_plan_id = sys.argv[2]
    else:
        print("\nAvailable plans: " + ", ".join(PLAN_LIMITS.keys()))
        target_plan_id = input(f"Enter plan ID (default: professional): ").strip() or 'professional'
    
    plan_config = PLAN_LIMITS.get(target_plan_id)
    if not plan_config:
        print(f"Error: Plan '{target_plan_id}' not found in PLAN_LIMITS.")
        return

    async with AsyncSessionLocal() as db:
        # Check if user exists
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        
        if not user:
            print(f"Error: User {email} not found.")
            return

        # Map PlanLimits to User model columns
        values = {
            'plan': target_plan_id,
            'max_users': plan_config.max_team_members,
            'dashboard_access_days': plan_config.report_retention_days,
            'has_api_testing': plan_config.features.api_testing,
            'has_credential_scanning': plan_config.features.credential_scanning,
            'has_chatbot_access': plan_config.features.chatbot_access,
            'has_mobile_pentest': plan_config.features.mobile_app_testing,
            'has_compliance_audits': plan_config.features.compliance_reports,
            'has_dedicated_support': plan_config.features.dedicated_support,
        }

        print(f"Upgrading {email} to {plan_config.name} plan...")
        
        result = await db.execute(
            update(User)
            .where(User.email == email)
            .values(**values)
        )
        await db.commit()
        
        if result.rowcount > 0:
            print(f'Success! Updated user {email} to {target_plan_id}.')
            print('Updated columns:')
            for k, v in values.items():
                print(f"  - {k}: {v}")
        else:
            print(f'User {email} not found or no changes needed.')

if __name__ == "__main__":
    asyncio.run(upgrade_user())
