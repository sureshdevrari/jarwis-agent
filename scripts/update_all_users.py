"""Update all users with correct credentials and plans"""
import asyncio
from database.connection import AsyncSessionLocal
from database.models import User
from database.auth import hash_password
from sqlalchemy import update, select

async def update_all_users():
    async with AsyncSessionLocal() as db:
        # User configurations
        users_config = [
            # Super Admin
            {"email": "akshaydevrari@gmail.com", "password": "Parilove@1", "plan": "enterprise", "is_superuser": True},
            {"email": "admin@jarwis.ai", "password": "admin123", "plan": "enterprise", "is_superuser": True},
            # Individual (Free) user
            {"email": "user1@jarwis.ai", "password": "12341234", "plan": "individual"},
            # Professional user
            {"email": "user2@jarwis.ai", "password": "12341234", "plan": "professional"},
            # Enterprise user
            {"email": "user3@jarwis.ai", "password": "12341234", "plan": "enterprise"},
        ]
        
        for config in users_config:
            email = config["email"]
            hashed = hash_password(config["password"])
            plan = config["plan"]
            is_superuser = config.get("is_superuser", False)
            
            # Check if user exists
            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            
            if user:
                # Update existing user
                await db.execute(
                    update(User)
                    .where(User.email == email)
                    .values(
                        hashed_password=hashed,
                        plan=plan,
                        is_superuser=is_superuser,
                        is_active=True,
                        is_verified=True
                    )
                )
                print(f"✓ Updated: {email} (plan={plan}, superuser={is_superuser})")
            else:
                # Create new user
                new_user = User(
                    email=email,
                    hashed_password=hashed,
                    plan=plan,
                    is_superuser=is_superuser,
                    is_active=True,
                    is_verified=True
                )
                db.add(new_user)
                print(f"✓ Created: {email} (plan={plan}, superuser={is_superuser})")
        
        await db.commit()
        print("\n✅ All users updated successfully!")

if __name__ == "__main__":
    asyncio.run(update_all_users())
