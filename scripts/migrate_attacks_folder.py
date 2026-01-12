#!/usr/bin/env python3
"""
Attacks Folder Migration Script

This script restructures the attacks/ folder to be organized by:
- Web: OWASP Top 10 categories
- Cloud: Provider (AWS, Azure, GCP) + shared
- Mobile: Phase (static, dynamic, platform)
- SAST: Function (providers, analyzers, languages)
- Network: Already well organized (no changes)

It creates backward-compatible imports so existing code continues to work.

Usage:
    python scripts/migrate_attacks_folder.py --dry-run    # Preview changes
    python scripts/migrate_attacks_folder.py --execute    # Execute migration
    python scripts/migrate_attacks_folder.py --rollback   # Undo migration
"""

import os
import shutil
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

# Base paths
PROJECT_ROOT = Path(__file__).parent.parent
ATTACKS_DIR = PROJECT_ROOT / "attacks"
BACKUP_DIR = PROJECT_ROOT / "attacks_backup"

# ============================================================================
# MIGRATION MAPPINGS
# ============================================================================

# Web scanners organized by OWASP 2021 category
WEB_OWASP_MAPPING = {
    # A01: Broken Access Control
    "a01_broken_access": [
        "idor_scanner.py",
        "access_control_scanner.py",
        "auth_bypass_scanner.py",
        "path_traversal_scanner.py",
    ],
    
    # A02: Cryptographic Failures
    "a02_crypto": [
        "jwt_scanner.py",
        "session_scanner.py",
    ],
    
    # A03: Injection
    "a03_injection": [
        "injection_scanner.py",
        "sqli_advanced_scanner.py",
        "xss_scanner.py",
        "xss_advanced_scanner.py",
        "xss_reflected_scanner.py",
        "xss_stored_scanner.py",
        "ssti_scanner.py",
        "xxe_scanner.py",
        "ldap_injection_scanner.py",
    ],
    
    # A04: Insecure Design
    "a04_insecure_design": [
        "business_logic_scanner.py",
        "race_condition_scanner.py",
        "captcha_scanner.py",
    ],
    
    # A05: Security Misconfiguration
    "a05_misconfig": [
        "cors_scanner.py",
        "security_headers_scanner.py",
        "misconfig_scanner.py",
        "host_header_scanner.py",
        "open_redirect_scanner.py",
        "info_disclosure_scanner.py",
        "framework_scanner.py",
        "hpp_scanner.py",
        "response_manipulation_scanner.py",
        "response_manipulation_addon.py",
        "response_swap_scanner.py",
    ],
    
    # A06: Vulnerable Components
    "a06_vulnerable_components": [
        "subdomain_takeover_scanner.py",
    ],
    
    # A07: Auth Failures
    "a07_auth_failures": [
        "auth_scanner.py",
        "csrf_scanner.py",
        "clickjacking_scanner.py",
        "oauth_scanner.py",
        "oauth_saml_scanner.py",
    ],
    
    # A08: Integrity Failures
    "a08_integrity": [
        "prototype_pollution_scanner.py",
    ],
    
    # A09: Logging Failures (usually detected via other means)
    "a09_logging": [
        "sensitive_data_scanner.py",
    ],
    
    # A10: SSRF
    "a10_ssrf": [
        "ssrf_scanner.py",
        "ssrf_advanced_scanner.py",  # Will be merged
    ],
    
    # API Security (separate category for clarity)
    "api": [
        "api_scanner.py",
        "api_security_scanner.py",
        "graphql_scanner.py",
        "websocket_scanner.py",
    ],
    
    # File/Upload related
    "file_upload": [
        "file_upload_scanner.py",
        "upload_scanner.py",  # Will be merged
    ],
    
    # Other/Uncategorized
    "other": [
        "post_method_scanner.py",
        "smuggling_scanner.py",
        "rate_limit_scanner.py",
    ],
}

# Cloud scanners organized by provider
CLOUD_PROVIDER_MAPPING = {
    "aws": [
        "aws_scanner.py",
    ],
    "azure": [
        "azure_scanner_complete.py",  # Primary - will be renamed to azure_scanner.py
        # azure_scanner.py will be removed (duplicate)
    ],
    "gcp": [
        "gcp_scanner.py",
    ],
    "kubernetes": [
        "kubernetes_scanner.py",
        "container_scanner.py",
    ],
    "shared": [
        "base.py",
        "cloud_scanner.py",
        "iac_scanner.py",
        "compliance_mapper.py",
        "config.py",
        "schemas.py",
        "exceptions.py",
    ],
    "cnapp": [
        "ciem_scanner.py",
        "runtime_scanner.py",
        "drift_scanner.py",
        "data_security_scanner.py",
        "sbom_generator.py",
    ],
}

# Mobile scanners organized by phase
MOBILE_PHASE_MAPPING = {
    "static": [
        "static_analyzer.py",
        "unpacker.py",
    ],
    "dynamic": [
        "dynamic_crawler.py",
        "runtime_analyzer.py",
        "app_crawler.py",
        "frida_ssl_bypass.py",
    ],
    "platform/android": [
        "android_attacks.py",
        "emulator_manager.py",
    ],
    "platform/ios": [
        "ios_attacks.py",
        "ios_simulator_manager.py",
    ],
    "api": [
        "api_discovery.py",
        "mobile_mitm.py",
        "burp_interceptor.py",
    ],
    "orchestration": [
        "mobile_orchestrator.py",
        # mobile_orchestrator_new.py will be removed (duplicate)
        "mobile_scanner.py",
        "mobile_post_scanner.py",
    ],
    "utils": [
        "auth_detector.py",
        "otp_handler.py",
        "llm_analyzer.py",
        "deeplink_scanner.py",
        "mobile_xss_scanner.py",
    ],
}

# SAST scanners organized by function
SAST_FUNCTION_MAPPING = {
    "providers": [
        "github_scanner.py",
        "gitlab_scanner.py",
        "bitbucket_scanner.py",
        "azure_devops_scanner.py",
        "aws_codecommit_scanner.py",
        "gitea_scanner.py",
        "generic_scanner.py",
    ],
    "analyzers": [
        "secret_scanner.py",
        "dependency_scanner.py",
        "code_analyzer.py",
    ],
    # language_analyzers already exists and is well organized
}

# Files to DELETE (duplicates)
FILES_TO_DELETE = [
    "attacks/cloud/azure_scanner.py",  # Duplicate of azure_scanner_complete.py
    "attacks/mobile/mobile_orchestrator_new.py",  # Duplicate
]

# Files to MOVE OUT of wrong location
MISPLACED_FILES = {
    "attacks/web/pre_login/mobile_security_scanner.py": "attacks/mobile/utils/mobile_security_scanner.py",
}

# Files to RENAME
FILES_TO_RENAME = {
    "attacks/cloud/azure/azure_scanner_complete.py": "attacks/cloud/azure/azure_scanner.py",
}


# ============================================================================
# MIGRATION FUNCTIONS
# ============================================================================

def create_backup():
    """Create a backup of the attacks folder."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR.parent / f"attacks_backup_{timestamp}"
    
    if ATTACKS_DIR.exists():
        shutil.copytree(ATTACKS_DIR, backup_path)
        print(f"✅ Backup created: {backup_path}")
        return backup_path
    return None


def create_init_file(directory: Path, imports: List[str] = None):
    """Create an __init__.py file with optional imports."""
    init_path = directory / "__init__.py"
    
    content = f'''"""
{directory.name} module

Auto-generated during attacks folder restructure.
"""

'''
    
    if imports:
        for imp in imports:
            content += f"{imp}\n"
    
    init_path.write_text(content)
    print(f"  Created: {init_path}")


def create_compat_import(old_path: Path, new_path: Path, class_names: List[str]):
    """
    Create a backward-compatible import file at old location.
    This allows existing code to continue working.
    """
    # Calculate relative import path
    old_parts = old_path.relative_to(PROJECT_ROOT).parts
    new_parts = new_path.relative_to(PROJECT_ROOT).parts
    
    # Build import statement
    new_module = ".".join(new_parts).replace(".py", "")
    
    content = f'''"""
DEPRECATED: This file has been moved to {new_path.relative_to(PROJECT_ROOT)}

This file provides backward-compatible imports.
Please update your imports to use the new location.
"""

import warnings
warnings.warn(
    f"Importing from {{__name__}} is deprecated. "
    f"Use {new_module} instead.",
    DeprecationWarning,
    stacklevel=2
)

# Re-export everything from new location
from {new_module} import *
'''
    
    old_path.write_text(content)
    print(f"  Created compat import: {old_path}")


def migrate_web_scanners(dry_run: bool = True):
    """Migrate web scanners to OWASP-organized folders."""
    print("\n📁 Migrating Web Scanners...")
    
    pre_login_dir = ATTACKS_DIR / "web" / "pre_login"
    
    for category, files in WEB_OWASP_MAPPING.items():
        new_dir = ATTACKS_DIR / "web" / category
        
        if not dry_run:
            new_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n  Category: {category}/")
        
        for filename in files:
            old_path = pre_login_dir / filename
            new_path = new_dir / filename
            
            if old_path.exists():
                if dry_run:
                    print(f"    Would move: {filename}")
                else:
                    # Copy to new location
                    shutil.copy2(old_path, new_path)
                    print(f"    Moved: {filename}")
            else:
                print(f"    ⚠️ Not found: {filename}")
        
        if not dry_run:
            create_init_file(new_dir)


def migrate_cloud_scanners(dry_run: bool = True):
    """Migrate cloud scanners to provider-organized folders."""
    print("\n☁️ Migrating Cloud Scanners...")
    
    cloud_dir = ATTACKS_DIR / "cloud"
    
    for provider, files in CLOUD_PROVIDER_MAPPING.items():
        new_dir = cloud_dir / provider
        
        if not dry_run:
            new_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n  Provider: {provider}/")
        
        for filename in files:
            old_path = cloud_dir / filename
            new_path = new_dir / filename
            
            if old_path.exists():
                if dry_run:
                    print(f"    Would move: {filename}")
                else:
                    shutil.copy2(old_path, new_path)
                    print(f"    Moved: {filename}")
            else:
                print(f"    ⚠️ Not found: {filename}")
        
        if not dry_run:
            create_init_file(new_dir)


def migrate_mobile_scanners(dry_run: bool = True):
    """Migrate mobile scanners to phase-organized folders."""
    print("\n📱 Migrating Mobile Scanners...")
    
    mobile_dir = ATTACKS_DIR / "mobile"
    
    for phase, files in MOBILE_PHASE_MAPPING.items():
        new_dir = mobile_dir / phase
        
        if not dry_run:
            new_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n  Phase: {phase}/")
        
        for filename in files:
            old_path = mobile_dir / filename
            new_path = new_dir / filename
            
            if old_path.exists():
                if dry_run:
                    print(f"    Would move: {filename}")
                else:
                    shutil.copy2(old_path, new_path)
                    print(f"    Moved: {filename}")
            else:
                print(f"    ⚠️ Not found: {filename}")
        
        if not dry_run:
            create_init_file(new_dir)


def migrate_sast_scanners(dry_run: bool = True):
    """Migrate SAST scanners to function-organized folders."""
    print("\n🔍 Migrating SAST Scanners...")
    
    sast_dir = ATTACKS_DIR / "sast"
    
    for function, files in SAST_FUNCTION_MAPPING.items():
        new_dir = sast_dir / function
        
        if not dry_run:
            new_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"\n  Function: {function}/")
        
        for filename in files:
            old_path = sast_dir / filename
            new_path = new_dir / filename
            
            if old_path.exists():
                if dry_run:
                    print(f"    Would move: {filename}")
                else:
                    shutil.copy2(old_path, new_path)
                    print(f"    Moved: {filename}")
            else:
                print(f"    ⚠️ Not found: {filename}")
        
        if not dry_run:
            create_init_file(new_dir)


def handle_duplicates(dry_run: bool = True):
    """Remove duplicate files."""
    print("\n🗑️ Handling Duplicates...")
    
    for filepath in FILES_TO_DELETE:
        full_path = PROJECT_ROOT / filepath
        
        if full_path.exists():
            if dry_run:
                print(f"  Would delete: {filepath}")
            else:
                full_path.unlink()
                print(f"  Deleted: {filepath}")
        else:
            print(f"  ⚠️ Not found: {filepath}")


def handle_misplaced_files(dry_run: bool = True):
    """Move misplaced files to correct locations."""
    print("\n📦 Moving Misplaced Files...")
    
    for old_loc, new_loc in MISPLACED_FILES.items():
        old_path = PROJECT_ROOT / old_loc
        new_path = PROJECT_ROOT / new_loc
        
        if old_path.exists():
            if dry_run:
                print(f"  Would move: {old_loc} → {new_loc}")
            else:
                new_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(old_path), str(new_path))
                print(f"  Moved: {old_loc} → {new_loc}")
        else:
            print(f"  ⚠️ Not found: {old_loc}")


def handle_renames(dry_run: bool = True):
    """Rename files."""
    print("\n✏️ Renaming Files...")
    
    for old_name, new_name in FILES_TO_RENAME.items():
        old_path = PROJECT_ROOT / old_name
        new_path = PROJECT_ROOT / new_name
        
        if old_path.exists():
            if dry_run:
                print(f"  Would rename: {old_name} → {new_name}")
            else:
                shutil.move(str(old_path), str(new_path))
                print(f"  Renamed: {old_name} → {new_name}")


def create_unified_registry(dry_run: bool = True):
    """Create a single unified scanner registry."""
    print("\n📋 Creating Unified Registry...")
    
    registry_path = ATTACKS_DIR / "registry.py"
    
    content = '''"""
Unified Scanner Registry

Single source of truth for all scanner discovery and management.
Consolidates the previous 3 registries:
- attacks/__init__.py (AttackDispatcher)
- attacks/scanner_registry.py (ScannerRegistry)
- attacks/unified_registry.py (UnifiedScannerRegistry)

Usage:
    from attacks.registry import ScannerRegistry
    
    # Get all scanners for a scan type
    web_scanners = ScannerRegistry.get_scanners("web")
    
    # Get specific scanner
    sqli_scanner = ScannerRegistry.get_scanner("sqli")
"""

import logging
from typing import Dict, List, Type, Optional, Any
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ScanType(Enum):
    """Supported scan types."""
    WEB = "web"
    MOBILE = "mobile"
    NETWORK = "network"
    CLOUD = "cloud"
    SAST = "sast"


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS = "A01"
    A02_CRYPTO = "A02"
    A03_INJECTION = "A03"
    A04_INSECURE_DESIGN = "A04"
    A05_MISCONFIG = "A05"
    A06_VULNERABLE_COMPONENTS = "A06"
    A07_AUTH_FAILURES = "A07"
    A08_INTEGRITY = "A08"
    A09_LOGGING = "A09"
    A10_SSRF = "A10"


@dataclass
class ScannerInfo:
    """Metadata about a scanner."""
    name: str
    scan_type: ScanType
    owasp_category: Optional[OWASPCategory] = None
    description: str = ""
    enabled: bool = True
    class_name: str = ""
    module_path: str = ""


class ScannerRegistry:
    """
    Unified scanner registry for all scan types.
    
    Provides:
    - Scanner discovery by scan type
    - Scanner lookup by name
    - OWASP category filtering
    - Health checking
    """
    
    _scanners: Dict[str, ScannerInfo] = {}
    _initialized: bool = False
    
    @classmethod
    def initialize(cls) -> None:
        """Initialize the registry by discovering all scanners."""
        if cls._initialized:
            return
        
        cls._discover_web_scanners()
        cls._discover_mobile_scanners()
        cls._discover_network_scanners()
        cls._discover_cloud_scanners()
        cls._discover_sast_scanners()
        
        cls._initialized = True
        logger.info(f"Scanner registry initialized with {len(cls._scanners)} scanners")
    
    @classmethod
    def _discover_web_scanners(cls) -> None:
        """Discover web scanners from attacks/web/."""
        web_dir = Path(__file__).parent / "web"
        
        # Scan OWASP category folders
        for category_dir in web_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("_"):
                for scanner_file in category_dir.glob("*_scanner.py"):
                    cls._register_scanner_from_file(
                        scanner_file, 
                        ScanType.WEB,
                        category_dir.name
                    )
    
    @classmethod
    def _discover_mobile_scanners(cls) -> None:
        """Discover mobile scanners from attacks/mobile/."""
        mobile_dir = Path(__file__).parent / "mobile"
        
        for phase_dir in mobile_dir.iterdir():
            if phase_dir.is_dir() and not phase_dir.name.startswith("_"):
                for scanner_file in phase_dir.glob("*.py"):
                    if not scanner_file.name.startswith("_"):
                        cls._register_scanner_from_file(
                            scanner_file,
                            ScanType.MOBILE,
                            phase_dir.name
                        )
    
    @classmethod
    def _discover_network_scanners(cls) -> None:
        """Discover network scanners from attacks/network/."""
        network_dir = Path(__file__).parent / "network"
        scanners_dir = network_dir / "scanners"
        
        if scanners_dir.exists():
            for scanner_file in scanners_dir.glob("*.py"):
                if not scanner_file.name.startswith("_"):
                    cls._register_scanner_from_file(
                        scanner_file,
                        ScanType.NETWORK
                    )
    
    @classmethod
    def _discover_cloud_scanners(cls) -> None:
        """Discover cloud scanners from attacks/cloud/."""
        cloud_dir = Path(__file__).parent / "cloud"
        
        for provider_dir in cloud_dir.iterdir():
            if provider_dir.is_dir() and not provider_dir.name.startswith("_"):
                for scanner_file in provider_dir.glob("*_scanner.py"):
                    cls._register_scanner_from_file(
                        scanner_file,
                        ScanType.CLOUD,
                        provider_dir.name
                    )
    
    @classmethod
    def _discover_sast_scanners(cls) -> None:
        """Discover SAST scanners from attacks/sast/."""
        sast_dir = Path(__file__).parent / "sast"
        
        for func_dir in sast_dir.iterdir():
            if func_dir.is_dir() and not func_dir.name.startswith("_"):
                for scanner_file in func_dir.glob("*.py"):
                    if not scanner_file.name.startswith("_"):
                        cls._register_scanner_from_file(
                            scanner_file,
                            ScanType.SAST,
                            func_dir.name
                        )
    
    @classmethod
    def _register_scanner_from_file(
        cls,
        file_path: Path,
        scan_type: ScanType,
        category: str = None
    ) -> None:
        """Register a scanner from its file path."""
        name = file_path.stem
        module_path = str(file_path.relative_to(Path(__file__).parent.parent))
        module_path = module_path.replace("/", ".").replace("\\\\", ".").replace(".py", "")
        
        # Map category to OWASP
        owasp = None
        if scan_type == ScanType.WEB and category:
            owasp_map = {
                "a01_broken_access": OWASPCategory.A01_BROKEN_ACCESS,
                "a02_crypto": OWASPCategory.A02_CRYPTO,
                "a03_injection": OWASPCategory.A03_INJECTION,
                "a04_insecure_design": OWASPCategory.A04_INSECURE_DESIGN,
                "a05_misconfig": OWASPCategory.A05_MISCONFIG,
                "a06_vulnerable_components": OWASPCategory.A06_VULNERABLE_COMPONENTS,
                "a07_auth_failures": OWASPCategory.A07_AUTH_FAILURES,
                "a08_integrity": OWASPCategory.A08_INTEGRITY,
                "a09_logging": OWASPCategory.A09_LOGGING,
                "a10_ssrf": OWASPCategory.A10_SSRF,
            }
            owasp = owasp_map.get(category)
        
        cls._scanners[name] = ScannerInfo(
            name=name,
            scan_type=scan_type,
            owasp_category=owasp,
            module_path=module_path,
        )
    
    @classmethod
    def get_scanners(
        cls,
        scan_type: ScanType = None,
        owasp_category: OWASPCategory = None,
        enabled_only: bool = True
    ) -> List[ScannerInfo]:
        """Get scanners matching filters."""
        cls.initialize()
        
        result = []
        for scanner in cls._scanners.values():
            if scan_type and scanner.scan_type != scan_type:
                continue
            if owasp_category and scanner.owasp_category != owasp_category:
                continue
            if enabled_only and not scanner.enabled:
                continue
            result.append(scanner)
        
        return result
    
    @classmethod
    def get_scanner(cls, name: str) -> Optional[ScannerInfo]:
        """Get a specific scanner by name."""
        cls.initialize()
        return cls._scanners.get(name)
    
    @classmethod
    def get_scanner_class(cls, name: str) -> Optional[Type]:
        """Dynamically import and return the scanner class."""
        scanner = cls.get_scanner(name)
        if not scanner:
            return None
        
        try:
            import importlib
            module = importlib.import_module(scanner.module_path)
            
            # Try common class name patterns
            class_names = [
                scanner.class_name,
                f"{name.title().replace('_', '')}Scanner",
                f"{name.title().replace('_', '')}",
            ]
            
            for class_name in class_names:
                if class_name and hasattr(module, class_name):
                    return getattr(module, class_name)
            
            return None
        except ImportError as e:
            logger.error(f"Failed to import scanner {name}: {e}")
            return None


# Initialize on import
ScannerRegistry.initialize()
'''
    
    if dry_run:
        print("  Would create: attacks/registry.py")
    else:
        registry_path.write_text(content)
        print("  Created: attacks/registry.py")


def run_migration(dry_run: bool = True):
    """Run the complete migration."""
    print("=" * 60)
    print("ATTACKS FOLDER MIGRATION")
    print("=" * 60)
    
    if dry_run:
        print("\n⚠️ DRY RUN MODE - No changes will be made\n")
    else:
        print("\n🚀 EXECUTING MIGRATION\n")
        
        # Create backup first
        backup_path = create_backup()
        if backup_path:
            print(f"\n📦 Backup saved to: {backup_path}")
    
    # Run migrations
    migrate_web_scanners(dry_run)
    migrate_cloud_scanners(dry_run)
    migrate_mobile_scanners(dry_run)
    migrate_sast_scanners(dry_run)
    handle_misplaced_files(dry_run)
    handle_duplicates(dry_run)
    handle_renames(dry_run)
    create_unified_registry(dry_run)
    
    print("\n" + "=" * 60)
    if dry_run:
        print("DRY RUN COMPLETE - Run with --execute to apply changes")
    else:
        print("MIGRATION COMPLETE")
        print(f"Backup available at: {backup_path}")
    print("=" * 60)


def rollback_migration():
    """Rollback to the most recent backup."""
    print("🔄 Rolling back migration...")
    
    # Find most recent backup
    backup_pattern = PROJECT_ROOT / "attacks_backup_*"
    backups = sorted(Path(PROJECT_ROOT).glob("attacks_backup_*"), reverse=True)
    
    if not backups:
        print("❌ No backups found!")
        return
    
    latest_backup = backups[0]
    print(f"  Found backup: {latest_backup}")
    
    # Remove current attacks folder
    if ATTACKS_DIR.exists():
        shutil.rmtree(ATTACKS_DIR)
        print("  Removed current attacks/")
    
    # Restore from backup
    shutil.copytree(latest_backup, ATTACKS_DIR)
    print(f"  Restored from: {latest_backup}")
    
    print("✅ Rollback complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate attacks folder structure")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Preview changes without making them")
    group.add_argument("--execute", action="store_true", help="Execute the migration")
    group.add_argument("--rollback", action="store_true", help="Rollback to backup")
    
    args = parser.parse_args()
    
    if args.rollback:
        rollback_migration()
    else:
        run_migration(dry_run=args.dry_run)
