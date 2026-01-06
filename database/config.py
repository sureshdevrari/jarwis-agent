"""
Database Configuration
Loads settings from environment variables
"""

import os
from pathlib import Path
from pydantic_settings import BaseSettings
from functools import lru_cache

# Get the absolute path to the jarwis-ai-pentest directory (database always lives here)
_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
_DEFAULT_SQLITE_PATH = str(_PROJECT_ROOT / "jarwis.db")


class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    
    # Database type: "postgresql" or "sqlite"
    DB_TYPE: str = "sqlite"  # Default to SQLite for local development
    
    # SQLite settings (for local development) - uses absolute path by default
    SQLITE_PATH: str = _DEFAULT_SQLITE_PATH
    
    # PostgreSQL connection settings
    POSTGRES_USER: str = "jarwis"
    POSTGRES_PASSWORD: str = "jarwis_secret_2026"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "jarwis_db"
    
    # Connection pool settings
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    
    # For AWS RDS, set these environment variables:
    # POSTGRES_HOST=your-rds-endpoint.region.rds.amazonaws.com
    # POSTGRES_PASSWORD=your_secure_password
    
    @property
    def DATABASE_URL(self) -> str:
        """Construct async database URL"""
        if self.DB_TYPE == "sqlite":
            return f"sqlite+aiosqlite:///{self.SQLITE_PATH}"
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
    
    @property
    def DATABASE_URL_SYNC(self) -> str:
        """Construct sync database URL (for Alembic migrations)"""
        if self.DB_TYPE == "sqlite":
            return f"sqlite:///{self.SQLITE_PATH}"
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


@lru_cache()
def get_settings() -> DatabaseSettings:
    """Get cached database settings"""
    return DatabaseSettings()


# Export settings instance
settings = get_settings()
