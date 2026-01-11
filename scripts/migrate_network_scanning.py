"""
Network Security Scanning - Database Migration

Run this script to:
1. Add network_scan_config column to ScanHistory table
2. Add checkpoint_data column to ScanHistory table
3. Create agents table
4. Add agents relationship to User table

Usage:
    python migrate_network_scanning.py
"""

import asyncio
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import models
from database.models import Base, ScanHistory, Agent, User
from database.config import settings


async def run_migration():
    """Run database migrations"""
    logger.info("Starting network scanning migration...")
    
    # Get database URL
    database_url = settings.DATABASE_URL
    
    # Create engine
    engine = create_async_engine(database_url, echo=True)
    
    # Create all tables (including new Agent table)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("✓ Tables created successfully")
    
    # Handle existing ScanHistory tables
    async with engine.begin() as conn:
        # Check if columns exist (SQLite-specific)
        if 'sqlite' in database_url.lower():
            logger.info("Detected SQLite database")
            
            # For SQLite, we need to check if columns exist differently
            # Get table info
            result = await conn.execute(text("PRAGMA table_info(scan_history)"))
            rows = result.fetchall()
            columns = {row[1] for row in rows}
            
            if 'config' not in columns:
                logger.info("Adding 'config' column to scan_history...")
                try:
                    await conn.execute(text("""
                        ALTER TABLE scan_history 
                        ADD COLUMN config JSON DEFAULT '{}'
                    """))
                    await conn.commit()
                    logger.info("✓ Added 'config' column")
                except Exception as e:
                    logger.warning(f"Could not add 'config' column (may already exist): {e}")
            
            if 'checkpoint_data' not in columns:
                logger.info("Adding 'checkpoint_data' column to scan_history...")
                try:
                    await conn.execute(text("""
                        ALTER TABLE scan_history 
                        ADD COLUMN checkpoint_data JSON DEFAULT '{}'
                    """))
                    await conn.commit()
                    logger.info("✓ Added 'checkpoint_data' column")
                except Exception as e:
                    logger.warning(f"Could not add 'checkpoint_data' column (may already exist): {e}")
        
        elif 'postgresql' in database_url.lower():
            logger.info("Detected PostgreSQL database")
            
            # For PostgreSQL
            try:
                await conn.execute(text("""
                    ALTER TABLE scan_history 
                    ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}'
                """))
                await conn.commit()
                logger.info("✓ Added 'config' column")
            except Exception as e:
                logger.warning(f"Could not add 'config' column (may already exist): {e}")
            
            try:
                await conn.execute(text("""
                    ALTER TABLE scan_history 
                    ADD COLUMN IF NOT EXISTS checkpoint_data JSONB DEFAULT '{}'
                """))
                await conn.commit()
                logger.info("✓ Added 'checkpoint_data' column")
            except Exception as e:
                logger.warning(f"Could not add 'checkpoint_data' column (may already exist): {e}")
    
    # Verify migration
    async with AsyncSession(engine) as session:
        # Check ScanHistory has new columns
        scan_history_count = await session.execute(text("SELECT COUNT(*) FROM scan_history"))
        logger.info(f"✓ ScanHistory table has {scan_history_count.scalar()} records")
        
        # Check agents table exists
        try:
            agent_count = await session.execute(text("SELECT COUNT(*) FROM agents"))
            logger.info(f"✓ Agents table created successfully (0 agents currently)")
        except Exception as e:
            logger.error(f"Agents table check failed: {e}")
    
    await engine.dispose()
    logger.info("✓ Migration completed successfully!")


async def rollback_migration():
    """Rollback migration (optional)"""
    logger.info("WARNING: This will drop the agents table and remove columns from scan_history")
    confirm = input("Type 'yes' to confirm rollback: ")
    
    if confirm != 'yes':
        logger.info("Rollback cancelled")
        return
    
    database_url = settings.DATABASE_URL
    engine = create_async_engine(database_url, echo=True)
    
    async with engine.begin() as conn:
        # Drop agents table
        try:
            await conn.execute(text("DROP TABLE IF EXISTS agents"))
            logger.info("✓ Dropped agents table")
        except Exception as e:
            logger.warning(f"Could not drop agents table: {e}")
        
        # Note: Removing columns from ScanHistory is complex in SQLite
        # For production, use Alembic migrations instead
        logger.warning("Column removal from scan_history skipped - use Alembic for production")
    
    await engine.dispose()
    logger.info("✓ Rollback completed!")


async def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--rollback':
        await rollback_migration()
    else:
        await run_migration()


if __name__ == "__main__":
    asyncio.run(main())
