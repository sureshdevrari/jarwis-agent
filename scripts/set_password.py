"""Set password for test user"""
import asyncio
from database.connection import AsyncSessionLocal
from database.models import User
from database.auth import hash_password
from sqlalchemy import update

async def set_password():
    async with AsyncSessionLocal() as db:
        # Set password for user2@jarwis.ai (professional plan)
        hashed = hash_password("ProTest123!")
        result = await db.execute(
            update(User)
            .where(User.email == "user2@jarwis.ai")
            .values(hashed_password=hashed)
        )
        await db.commit()
        print(f"Updated password for user2@jarwis.ai: {result.rowcount} row(s)")

if __name__ == "__main__":
    asyncio.run(set_password())
