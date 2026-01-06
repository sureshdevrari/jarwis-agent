"""
Database Setup Script
Creates tables and an initial admin user
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.connection import engine, AsyncSessionLocal, Base
from database.models import User, ScanHistory, Finding, APIKey, RefreshToken
from database.auth import hash_password


async def create_tables():
    """Create all database tables"""
    print("Creating database tables...")
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print("[OK] Tables created successfully!")


async def create_admin_user(
    email: str = "admin@jarwis.ai",
    username: str = "admin",
    password: str = "admin123456"
):
    """Create an initial admin user"""
    print(f"Creating admin user: {username}...")
    
    async with AsyncSessionLocal() as session:
        # Check if admin already exists
        from sqlalchemy import select
        result = await session.execute(
            select(User).where(User.username == username)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            print(f"[OK] Admin user '{username}' already exists")
            return
        
        # Create admin user
        admin = User(
            email=email,
            username=username,
            hashed_password=hash_password(password),
            full_name="Jarwis Admin",
            is_active=True,
            is_verified=True,
            is_superuser=True,
            plan="enterprise"
        )
        
        session.add(admin)
        await session.commit()
        
        print(f"[OK] Admin user created!")
        print(f"  Email: {email}")
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print("\n  [!]  IMPORTANT: Change the admin password after first login!")


async def main():
    """Main setup function"""
    print("\n" + "="*60)
    print("  JARWIS DATABASE SETUP")
    print("="*60 + "\n")
    
    try:
        await create_tables()
        await create_admin_user()
        
        print("\n" + "="*60)
        print("  Database setup complete!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n[X] Error during setup: {e}")
        print("\nMake sure PostgreSQL is running and the database exists.")
        print("You can create the database with:")
        print("  CREATE DATABASE jarwis_db;")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
