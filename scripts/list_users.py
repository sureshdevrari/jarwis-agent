"""List all users in database"""
import asyncio
from database.connection import AsyncSessionLocal
from database.models import User
from sqlalchemy import select

async def list_users():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        print(f"\n{'='*60}")
        print(f"  Total Users: {len(users)}")
        print(f"{'='*60}\n")
        for u in users:
            role = "SUPERADMIN" if u.is_superuser else "User"
            print(f"  {u.email:<30} | {u.plan:<12} | {role}")
        print()

if __name__ == "__main__":
    asyncio.run(list_users())
