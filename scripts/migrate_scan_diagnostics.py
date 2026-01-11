"""
Database migration script to add new columns for scan error tracking.

Run this script to add:
- error_message column to scan_history
- last_successful_phase column to scan_history
- scan_logs table for persistent log storage

Usage:
    python migrate_scan_diagnostics.py
"""

import asyncio
import logging
from sqlalchemy import text
from database.connection import engine, AsyncSessionLocal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def migrate():
    """Run database migrations for scan diagnostics features."""
    
    async with engine.begin() as conn:
        # Check if we're using SQLite or PostgreSQL
        dialect = engine.dialect.name
        logger.info(f"Database dialect: {dialect}")
        
        # Add error_message column to scan_history
        try:
            if dialect == "sqlite":
                await conn.execute(text(
                    "ALTER TABLE scan_history ADD COLUMN error_message TEXT"
                ))
            else:
                await conn.execute(text(
                    "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS error_message TEXT"
                ))
            logger.info("✅ Added error_message column to scan_history")
        except Exception as e:
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                logger.info("ℹ️ error_message column already exists")
            else:
                logger.warning(f"⚠️ Could not add error_message: {e}")
        
        # Add last_successful_phase column to scan_history
        try:
            if dialect == "sqlite":
                await conn.execute(text(
                    "ALTER TABLE scan_history ADD COLUMN last_successful_phase VARCHAR(100)"
                ))
            else:
                await conn.execute(text(
                    "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS last_successful_phase VARCHAR(100)"
                ))
            logger.info("✅ Added last_successful_phase column to scan_history")
        except Exception as e:
            if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                logger.info("ℹ️ last_successful_phase column already exists")
            else:
                logger.warning(f"⚠️ Could not add last_successful_phase: {e}")
        
        # Create scan_logs table
        try:
            if dialect == "sqlite":
                await conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS scan_logs (
                        id VARCHAR(36) PRIMARY KEY,
                        scan_id VARCHAR(36) NOT NULL,
                        level VARCHAR(20) DEFAULT 'info',
                        message TEXT NOT NULL,
                        phase VARCHAR(100),
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
                    )
                """))
            else:
                await conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS scan_logs (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        scan_id UUID NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
                        level VARCHAR(20) DEFAULT 'info',
                        message TEXT NOT NULL,
                        phase VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """))
            logger.info("✅ Created scan_logs table")
        except Exception as e:
            if "already exists" in str(e).lower():
                logger.info("ℹ️ scan_logs table already exists")
            else:
                logger.warning(f"⚠️ Could not create scan_logs table: {e}")
        
        # Create index on scan_logs
        try:
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_scan_logs_scan_id ON scan_logs(scan_id)"
            ))
            logger.info("✅ Created index on scan_logs.scan_id")
        except Exception as e:
            logger.warning(f"⚠️ Could not create index: {e}")
    
    logger.info("✅ Migration completed!")


if __name__ == "__main__":
    asyncio.run(migrate())
