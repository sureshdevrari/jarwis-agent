"""
Credential Migration Job

Migrates existing plaintext credentials to encrypted storage using the Trust Agent.
Run this script to encrypt existing SCM tokens, cloud credentials, and other sensitive data.

Usage:
    python scripts/migrate_credentials.py --dry-run    # Preview what will be migrated
    python scripts/migrate_credentials.py              # Run migration
    python scripts/migrate_credentials.py --force      # Force re-encryption of all

Environment Variables:
    JARWIS_ENCRYPTION_KEY - Base64 encoded 32-byte key (auto-generated if not set)
    DATABASE_URL - Database connection string
"""

import asyncio
import argparse
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CredentialMigration:
    """Handles migration of plaintext credentials to encrypted storage"""
    
    def __init__(self, db_url: str, dry_run: bool = True):
        self.db_url = db_url
        self.dry_run = dry_run
        self.trust_agent = None
        self.session_factory = None
        
        # Migration stats
        self.stats = {
            "scm_tokens_migrated": 0,
            "cloud_credentials_migrated": 0,
            "network_credentials_migrated": 0,
            "errors": [],
            "skipped": 0
        }
    
    async def initialize(self):
        """Initialize database and trust agent"""
        # Create async engine
        engine = create_async_engine(self.db_url, echo=False)
        self.session_factory = sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        
        # Initialize trust agent
        from core.trust_agent import get_trust_agent
        self.trust_agent = get_trust_agent()
        
        logger.info("Initialized migration with Trust Agent")
        if self.dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
    
    async def migrate_scm_connections(self):
        """Migrate SCM OAuth tokens to encrypted storage"""
        from database.models import SCMConnection, User
        
        logger.info("Migrating SCM connections...")
        
        async with self.session_factory() as session:
            # Find all SCM connections with plaintext tokens
            result = await session.execute(
                select(SCMConnection, User)
                .join(User, SCMConnection.user_id == User.id)
                .where(SCMConnection.access_token.isnot(None))
                .where(SCMConnection.access_token != "")
            )
            connections = result.all()
            
            logger.info(f"Found {len(connections)} SCM connections to migrate")
            
            for scm, user in connections:
                try:
                    # Check if already encrypted (starts with encrypted: prefix)
                    if scm.access_token.startswith("encrypted:"):
                        self.stats["skipped"] += 1
                        continue
                    
                    # Prepare credential data
                    credential_data = {
                        "access_token": scm.access_token,
                        "refresh_token": scm.refresh_token,
                        "provider": scm.provider,
                        "provider_user_id": scm.provider_user_id,
                        "scopes": scm.scopes
                    }
                    
                    if self.dry_run:
                        logger.info(f"  Would migrate SCM: {scm.provider}:{scm.provider_username} (user: {user.email})")
                        self.stats["scm_tokens_migrated"] += 1
                        continue
                    
                    # Store encrypted credential
                    # Use user_id as tenant_id for non-enterprise users
                    credential_id = await self.trust_agent.store_credential(
                        name=f"SCM-{scm.provider}-{scm.provider_username}",
                        credential_type="scm_token",
                        credential_data=credential_data,
                        tenant_id=str(user.id),
                        created_by=str(user.id),
                        rotation_days=90
                    )
                    
                    # Update SCM connection to reference encrypted credential
                    # Store credential ID and clear plaintext
                    scm.access_token = f"encrypted:{credential_id}"
                    scm.refresh_token = None  # Stored in encrypted credential
                    
                    self.stats["scm_tokens_migrated"] += 1
                    logger.info(f"  Migrated SCM: {scm.provider}:{scm.provider_username}")
                    
                except Exception as e:
                    error_msg = f"Failed to migrate SCM {scm.id}: {str(e)}"
                    self.stats["errors"].append(error_msg)
                    logger.error(error_msg)
            
            if not self.dry_run:
                await session.commit()
    
    async def migrate_cloud_scan_credentials(self):
        """Migrate cloud scan credentials from ScanHistory config"""
        from database.models import ScanHistory, User
        
        logger.info("Migrating cloud scan credentials...")
        
        async with self.session_factory() as session:
            # Find cloud scans with credentials in config
            result = await session.execute(
                select(ScanHistory, User)
                .join(User, ScanHistory.user_id == User.id)
                .where(ScanHistory.scan_type == "cloud")
                .where(ScanHistory.config.isnot(None))
            )
            scans = result.all()
            
            credentials_found = 0
            
            for scan, user in scans:
                config = scan.config or {}
                
                # Check for AWS credentials
                if config.get("aws_access_key_id") and not config.get("_encrypted"):
                    credentials_found += 1
                    
                    if self.dry_run:
                        logger.info(f"  Would encrypt AWS credentials in scan {scan.scan_id}")
                        continue
                    
                    try:
                        credential_data = {
                            "aws_access_key_id": config.get("aws_access_key_id"),
                            "aws_secret_access_key": config.get("aws_secret_access_key"),
                            "aws_region": config.get("aws_region", "us-east-1")
                        }
                        
                        credential_id = await self.trust_agent.store_credential(
                            name=f"AWS-{scan.scan_id[:8]}",
                            credential_type="aws_credentials",
                            credential_data=credential_data,
                            tenant_id=str(user.id),
                            created_by=str(user.id)
                        )
                        
                        # Update scan config to reference credential
                        config["_encrypted"] = True
                        config["credential_id"] = credential_id
                        config.pop("aws_access_key_id", None)
                        config.pop("aws_secret_access_key", None)
                        scan.config = config
                        
                        self.stats["cloud_credentials_migrated"] += 1
                        logger.info(f"  Migrated AWS credentials for scan {scan.scan_id}")
                        
                    except Exception as e:
                        self.stats["errors"].append(f"AWS creds in {scan.scan_id}: {e}")
                
                # Check for Azure credentials
                if config.get("azure_client_secret") and not config.get("_encrypted"):
                    credentials_found += 1
                    
                    if self.dry_run:
                        logger.info(f"  Would encrypt Azure credentials in scan {scan.scan_id}")
                        continue
                    
                    try:
                        credential_data = {
                            "tenant_id": config.get("azure_tenant_id"),
                            "client_id": config.get("azure_client_id"),
                            "client_secret": config.get("azure_client_secret")
                        }
                        
                        credential_id = await self.trust_agent.store_credential(
                            name=f"Azure-{scan.scan_id[:8]}",
                            credential_type="azure_service_principal",
                            credential_data=credential_data,
                            tenant_id=str(user.id),
                            created_by=str(user.id)
                        )
                        
                        config["_encrypted"] = True
                        config["credential_id"] = credential_id
                        config.pop("azure_client_secret", None)
                        scan.config = config
                        
                        self.stats["cloud_credentials_migrated"] += 1
                        
                    except Exception as e:
                        self.stats["errors"].append(f"Azure creds in {scan.scan_id}: {e}")
                
                # Check for GCP credentials
                if config.get("gcp_service_account_key") and not config.get("_encrypted"):
                    credentials_found += 1
                    
                    if self.dry_run:
                        logger.info(f"  Would encrypt GCP credentials in scan {scan.scan_id}")
                        continue
                    
                    try:
                        credential_id = await self.trust_agent.store_credential(
                            name=f"GCP-{scan.scan_id[:8]}",
                            credential_type="gcp_service_account",
                            credential_data={"service_account_key": config.get("gcp_service_account_key")},
                            tenant_id=str(user.id),
                            created_by=str(user.id)
                        )
                        
                        config["_encrypted"] = True
                        config["credential_id"] = credential_id
                        config.pop("gcp_service_account_key", None)
                        scan.config = config
                        
                        self.stats["cloud_credentials_migrated"] += 1
                        
                    except Exception as e:
                        self.stats["errors"].append(f"GCP creds in {scan.scan_id}: {e}")
            
            logger.info(f"Found {credentials_found} cloud credentials to migrate")
            
            if not self.dry_run:
                await session.commit()
    
    async def migrate_network_credentials(self):
        """Migrate network scan credentials from ScanHistory config"""
        from database.models import ScanHistory, User
        
        logger.info("Migrating network scan credentials...")
        
        async with self.session_factory() as session:
            result = await session.execute(
                select(ScanHistory, User)
                .join(User, ScanHistory.user_id == User.id)
                .where(ScanHistory.scan_type == "network")
                .where(ScanHistory.config.isnot(None))
            )
            scans = result.all()
            
            credentials_found = 0
            
            for scan, user in scans:
                config = scan.config or {}
                credentials = config.get("credentials", {})
                
                if not credentials or config.get("_encrypted"):
                    continue
                
                # Check for SSH credentials
                ssh_creds = credentials.get("ssh", {})
                if ssh_creds.get("password") or ssh_creds.get("private_key"):
                    credentials_found += 1
                    
                    if self.dry_run:
                        logger.info(f"  Would encrypt SSH credentials in scan {scan.scan_id}")
                        continue
                    
                    try:
                        cred_type = "ssh_key" if ssh_creds.get("private_key") else "ssh_password"
                        credential_id = await self.trust_agent.store_credential(
                            name=f"SSH-{scan.scan_id[:8]}",
                            credential_type=cred_type,
                            credential_data=ssh_creds,
                            tenant_id=str(user.id),
                            created_by=str(user.id)
                        )
                        
                        credentials["ssh"] = {"credential_id": credential_id}
                        config["credentials"] = credentials
                        config["_encrypted"] = True
                        scan.config = config
                        
                        self.stats["network_credentials_migrated"] += 1
                        
                    except Exception as e:
                        self.stats["errors"].append(f"SSH creds in {scan.scan_id}: {e}")
                
                # Check for database credentials
                db_creds = credentials.get("database", {})
                if db_creds.get("password"):
                    credentials_found += 1
                    
                    if self.dry_run:
                        logger.info(f"  Would encrypt DB credentials in scan {scan.scan_id}")
                        continue
                    
                    try:
                        credential_id = await self.trust_agent.store_credential(
                            name=f"DB-{scan.scan_id[:8]}",
                            credential_type="database_credentials",
                            credential_data=db_creds,
                            tenant_id=str(user.id),
                            created_by=str(user.id)
                        )
                        
                        credentials["database"] = {"credential_id": credential_id}
                        config["credentials"] = credentials
                        config["_encrypted"] = True
                        scan.config = config
                        
                        self.stats["network_credentials_migrated"] += 1
                        
                    except Exception as e:
                        self.stats["errors"].append(f"DB creds in {scan.scan_id}: {e}")
            
            logger.info(f"Found {credentials_found} network credentials to migrate")
            
            if not self.dry_run:
                await session.commit()
    
    async def run(self):
        """Run full migration"""
        await self.initialize()
        
        logger.info("=" * 60)
        logger.info("Starting Credential Migration")
        logger.info(f"Mode: {'DRY RUN' if self.dry_run else 'LIVE'}")
        logger.info("=" * 60)
        
        await self.migrate_scm_connections()
        await self.migrate_cloud_scan_credentials()
        await self.migrate_network_credentials()
        
        # Print summary
        logger.info("=" * 60)
        logger.info("Migration Summary")
        logger.info("=" * 60)
        logger.info(f"SCM tokens migrated: {self.stats['scm_tokens_migrated']}")
        logger.info(f"Cloud credentials migrated: {self.stats['cloud_credentials_migrated']}")
        logger.info(f"Network credentials migrated: {self.stats['network_credentials_migrated']}")
        logger.info(f"Skipped (already encrypted): {self.stats['skipped']}")
        
        if self.stats["errors"]:
            logger.error(f"Errors: {len(self.stats['errors'])}")
            for error in self.stats["errors"]:
                logger.error(f"  - {error}")
        else:
            logger.info("Errors: 0")
        
        if self.dry_run:
            logger.info("")
            logger.info("This was a DRY RUN. Run without --dry-run to apply changes.")
        
        return self.stats


async def main():
    parser = argparse.ArgumentParser(description="Migrate credentials to encrypted storage")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without applying")
    parser.add_argument("--force", action="store_true", help="Force re-encryption of all credentials")
    parser.add_argument("--db-url", help="Database URL (default: from config)")
    
    args = parser.parse_args()
    
    # Get database URL
    db_url = args.db_url
    if not db_url:
        # Try to get from config
        try:
            from database.config import get_database_url
            db_url = get_database_url()
        except ImportError:
            db_url = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./jarwis.db")
    
    # Ensure async driver
    if "sqlite://" in db_url and "aiosqlite" not in db_url:
        db_url = db_url.replace("sqlite://", "sqlite+aiosqlite://")
    
    migration = CredentialMigration(db_url, dry_run=args.dry_run)
    await migration.run()


if __name__ == "__main__":
    asyncio.run(main())
