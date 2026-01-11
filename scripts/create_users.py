"""Create users script"""
import asyncio
from database.connection import AsyncSessionLocal
from database.models import User
from database.auth import hash_password
from sqlalchemy import select

async def create_users():
    async with AsyncSessionLocal() as session:
        users_to_create = [
            {
                'email': 'akshaydevrari@gmail.com',
                'username': 'akshay',
                'password': 'Parilove@1',
                'full_name': 'Akshay Devrari',
                'is_superuser': True,
                'plan': 'enterprise'
            },
            {
                'email': 'user1@jarwis.ai',
                'username': 'user1',
                'password': '12341234',
                'full_name': 'User Individual',
                'is_superuser': False,
                'plan': 'individual'
            },
            {
                'email': 'user2@jarwis.ai',
                'username': 'user2',
                'password': '12341234',
                'full_name': 'User Pro',
                'is_superuser': False,
                'plan': 'pro'
            },
            {
                'email': 'user3@jarwis.ai',
                'username': 'user3',
                'password': '12341234',
                'full_name': 'User Enterprise',
                'is_superuser': False,
                'plan': 'enterprise'
            }
        ]
        
        for u in users_to_create:
            result = await session.execute(select(User).where(User.email == u['email']))
            if result.scalar_one_or_none():
                print(f"EXISTS: {u['email']}")
                continue
            
            user = User(
                email=u['email'],
                username=u['username'],
                hashed_password=hash_password(u['password']),
                full_name=u['full_name'],
                is_active=True,
                is_verified=True,
                is_superuser=u['is_superuser'],
                plan=u['plan'],
                approval_status='approved'
            )
            session.add(user)
            print(f"CREATED: {u['email']} ({u['plan']}) Superadmin={u['is_superuser']}")
        
        await session.commit()
        print("\n[OK] All users created successfully!")

if __name__ == "__main__":
    asyncio.run(create_users())
