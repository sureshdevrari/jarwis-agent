"""
Database Connection Manager
Async SQLAlchemy engine and session management with proper error handling
"""

import asyncio
import logging
from typing import AsyncGenerator, Optional

# Configure logging
logger = logging.getLogger(__name__)

# Database connection state
_db_available: bool = False
_connection_error: Optional[str] = None
_greenlet_available: bool = True

# Try to import async SQLAlchemy - may fail if greenlet is blocked
try:
    from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
    from sqlalchemy.orm import declarative_base
    from sqlalchemy.exc import SQLAlchemyError, OperationalError
except ImportError as e:
    if "greenlet" in str(e).lower():
        logger.warning(f"Greenlet not available - async database disabled: {e}")
        _greenlet_available = False
        _db_available = False
        _connection_error = "Greenlet DLL blocked by Application Control policy - database disabled"
        # Create dummy types
        AsyncSession = None
        create_async_engine = None
        async_sessionmaker = None
        declarative_base = None
        SQLAlchemyError = Exception
        OperationalError = Exception
    else:
        raise

# Only import settings if we have async support
if _greenlet_available:
    from database.config import settings
else:
    settings = None


def is_db_available() -> bool:
    """Check if database is currently available"""
    return _db_available


def get_connection_error() -> Optional[str]:
    """Get the last connection error message if any"""
    return _connection_error


# Create async engine with appropriate settings for SQLite vs PostgreSQL
engine = None
AsyncSessionLocal = None
Base = None

if _greenlet_available and settings:
    engine_kwargs = {
        "echo": False,  # Set to True for SQL query logging
    }

    # SQLite-specific settings for better concurrent access
    if settings.DB_TYPE == "sqlite":
        # SQLite needs special handling for async concurrent access
        engine_kwargs.update({
            "connect_args": {
                "timeout": 30,  # 30 second timeout for SQLite locks
                "check_same_thread": False,  # Allow multi-threaded access
            },
            "pool_pre_ping": True,  # Check connection health before use
        })
    else:
        # PostgreSQL pool settings
        engine_kwargs.update({
            "pool_size": settings.DB_POOL_SIZE,
            "max_overflow": settings.DB_MAX_OVERFLOW,
            "pool_timeout": settings.DB_POOL_TIMEOUT,
            "pool_pre_ping": True,  # Automatically check connection health
            "pool_recycle": 3600,   # Recycle connections after 1 hour
        })

    try:
        engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)
    except Exception as e:
        logger.error(f"Failed to create database engine: {e}")
        engine = None

    # Create async session factory
    if engine:
        AsyncSessionLocal = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )

    # Base class for models - imported from models.py to avoid circular imports
    # This is re-exported for convenience
    try:
        from database.models import Base
    except ImportError:
        Base = declarative_base() if declarative_base else None
else:
    logger.warning("Database disabled - greenlet not available")


class DatabaseConnectionError(Exception):
    """Custom exception for database connection issues"""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI endpoints.
    Yields an async database session with proper error handling.
    
    Usage:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            ...
    """
    global _db_available, _connection_error
    
    if AsyncSessionLocal is None:
        _db_available = False
        _connection_error = "Database engine not initialized"
        raise DatabaseConnectionError(_connection_error)
    
    try:
        async with AsyncSessionLocal() as session:
            try:
                yield session
                await session.commit()
                _db_available = True
                _connection_error = None
            except OperationalError as e:
                await session.rollback()
                _db_available = False
                _connection_error = f"Database operational error: {str(e)}"
                logger.error(_connection_error)
                raise DatabaseConnectionError(_connection_error) from e
            except SQLAlchemyError as e:
                await session.rollback()
                logger.error(f"Database error: {e}")
                raise
            except Exception as e:
                await session.rollback()
                logger.error(f"Unexpected error during database operation: {e}")
                raise
            finally:
                await session.close()
    except OperationalError as e:
        _db_available = False
        _connection_error = f"Failed to connect to database: {str(e)}"
        logger.error(_connection_error)
        raise DatabaseConnectionError(_connection_error) from e


async def init_db(max_retries: int = 3, retry_delay: float = 2.0) -> bool:
    """
    Initialize database tables with retry logic.
    
    Args:
        max_retries: Maximum number of connection attempts
        retry_delay: Delay between retries in seconds
        
    Returns:
        True if successful, False otherwise
    """
    global _db_available, _connection_error
    
    if engine is None:
        _db_available = False
        _connection_error = "Database engine not created"
        logger.error(_connection_error)
        return False
    
    for attempt in range(1, max_retries + 1):
        try:
            async with engine.begin() as conn:
                # Import models to register them with Base
                from database import models  # noqa
                await conn.run_sync(Base.metadata.create_all)
            
            _db_available = True
            _connection_error = None
            logger.info(f"Database initialized successfully on attempt {attempt}")
            return True
            
        except OperationalError as e:
            _connection_error = f"Database connection failed (attempt {attempt}/{max_retries}): {str(e)}"
            logger.warning(_connection_error)
            
            if attempt < max_retries:
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
                retry_delay *= 1.5  # Exponential backoff
            else:
                _db_available = False
                logger.error(f"Failed to initialize database after {max_retries} attempts")
                return False
                
        except Exception as e:
            _db_available = False
            _connection_error = f"Unexpected error during database initialization: {str(e)}"
            logger.error(_connection_error)
            return False
    
    return False


async def test_connection() -> tuple[bool, Optional[str]]:
    """
    Test the database connection.
    
    Returns:
        Tuple of (is_connected, error_message)
    """
    global _db_available, _connection_error
    
    if engine is None or AsyncSessionLocal is None:
        _db_available = False
        _connection_error = "Database not configured"
        return False, _connection_error
    
    try:
        from sqlalchemy import text
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        _db_available = True
        _connection_error = None
        return True, None
    except OperationalError as e:
        _db_available = False
        _connection_error = f"Database connection test failed: {str(e)}"
        logger.error(_connection_error)
        return False, _connection_error
    except Exception as e:
        _db_available = False
        _connection_error = f"Unexpected error testing connection: {str(e)}"
        logger.error(_connection_error)
        return False, _connection_error


async def close_db():
    """Close database connections gracefully"""
    global _db_available
    
    if engine:
        try:
            await engine.dispose()
            logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
        finally:
            _db_available = False
