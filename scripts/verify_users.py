"""Verify test users in database."""
import asyncio
from sqlalchemy import select
from database.connection import AsyncSessionLocal
from database.models import User

async def verify():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.username.in_(['user1', 'user2', 'user3']))
        )
        users = result.scalars().all()
        
        print("=" * 50)
        print("TEST USERS IN DATABASE")
        print("=" * 50)
        
        for u in users:
            print(f"\n[OK] {u.username}")
            print(f"  Email: {u.email}")
            print(f"  Plan: {u.plan}")
            print(f"  Status: {u.approval_status}")
            print(f"  Max Websites: {getattr(u, 'max_websites', 'N/A')}")
            print(f"  API Testing: {getattr(u, 'api_testing_enabled', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(verify())
