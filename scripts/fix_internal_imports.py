#!/usr/bin/env python3
"""
Fix Internal Imports Script

After the attacks folder migration, some internal imports within the
moved files need to be updated to use the new paths.

This script updates relative imports to use absolute imports or
corrected relative imports for the new folder structure.
"""

import os
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
ATTACKS_DIR = PROJECT_ROOT / "attacks"

# Mapping of old import paths to new paths
IMPORT_FIXES = {
    # Mobile orchestration -> static
    "from .static_analyzer import": "from attacks.mobile.static.static_analyzer import",
    "from .runtime_analyzer import": "from attacks.mobile.dynamic.runtime_analyzer import",
    "from .api_discovery import": "from attacks.mobile.api.api_discovery import",
    "from .app_crawler import": "from attacks.mobile.dynamic.app_crawler import",
    "from .dynamic_crawler import": "from attacks.mobile.dynamic.dynamic_crawler import",
    "from .unpacker import": "from attacks.mobile.static.unpacker import",
    "from .android_attacks import": "from attacks.mobile.platform.android.android_attacks import",
    "from .ios_attacks import": "from attacks.mobile.platform.ios.ios_attacks import",
    "from .mobile_mitm import": "from attacks.mobile.api.mobile_mitm import",
    "from .burp_interceptor import": "from attacks.mobile.api.burp_interceptor import",
    "from .frida_ssl_bypass import": "from attacks.mobile.dynamic.frida_ssl_bypass import",
    "from .emulator_manager import": "from attacks.mobile.platform.android.emulator_manager import",
    "from .ios_simulator_manager import": "from attacks.mobile.platform.ios.ios_simulator_manager import",
    "from .mobile_orchestrator import": "from attacks.mobile.orchestration.mobile_orchestrator import",
    "from .mobile_scanner import": "from attacks.mobile.orchestration.mobile_scanner import",
    "from .auth_detector import": "from attacks.mobile.utils.auth_detector import",
    "from .otp_handler import": "from attacks.mobile.utils.otp_handler import",
    "from .llm_analyzer import": "from attacks.mobile.utils.llm_analyzer import",
    "from .deeplink_scanner import": "from attacks.mobile.utils.deeplink_scanner import",
    "from .mobile_xss_scanner import": "from attacks.mobile.utils.mobile_xss_scanner import",
    
    # Cloud provider internal imports
    "from .cloud_scanner import": "from attacks.cloud.shared.cloud_scanner import",
    "from .base import": "from attacks.cloud.shared.base import",
    "from .iac_scanner import": "from attacks.cloud.shared.iac_scanner import",
    "from .compliance_mapper import": "from attacks.cloud.shared.compliance_mapper import",
    "from .config import CloudConfig": "from attacks.cloud.shared.config import CloudConfig",
    "from .schemas import": "from attacks.cloud.shared.schemas import",
    "from .exceptions import": "from attacks.cloud.shared.exceptions import",
    
    # Cloud CNAPP internal imports
    "from .ciem_scanner import": "from attacks.cloud.cnapp.ciem_scanner import",
    "from .runtime_scanner import RuntimeScanner": "from attacks.cloud.cnapp.runtime_scanner import RuntimeScanner",
    "from .drift_scanner import": "from attacks.cloud.cnapp.drift_scanner import",
    "from .data_security_scanner import": "from attacks.cloud.cnapp.data_security_scanner import",
    "from .sbom_generator import": "from attacks.cloud.cnapp.sbom_generator import",
    
    # SAST internal imports
    "from .secret_scanner import": "from attacks.sast.analyzers.secret_scanner import",
    "from .dependency_scanner import": "from attacks.sast.analyzers.dependency_scanner import",
    "from .code_analyzer import": "from attacks.sast.analyzers.code_analyzer import",
}

# Files to update (within the new structure)
FILES_TO_UPDATE = [
    # Mobile orchestration files
    ATTACKS_DIR / "mobile" / "orchestration" / "mobile_scanner.py",
    ATTACKS_DIR / "mobile" / "orchestration" / "mobile_orchestrator.py",
    ATTACKS_DIR / "mobile" / "orchestration" / "mobile_post_scanner.py",
    
    # Mobile dynamic files
    ATTACKS_DIR / "mobile" / "dynamic" / "dynamic_crawler.py",
    ATTACKS_DIR / "mobile" / "dynamic" / "runtime_analyzer.py",
    ATTACKS_DIR / "mobile" / "dynamic" / "app_crawler.py",
    
    # Mobile platform files
    ATTACKS_DIR / "mobile" / "platform" / "android" / "android_attacks.py",
    ATTACKS_DIR / "mobile" / "platform" / "ios" / "ios_attacks.py",
    
    # Mobile utils files
    ATTACKS_DIR / "mobile" / "utils" / "auth_detector.py",
    ATTACKS_DIR / "mobile" / "utils" / "mobile_xss_scanner.py",
    
    # Cloud provider files
    ATTACKS_DIR / "cloud" / "aws" / "aws_scanner.py",
    ATTACKS_DIR / "cloud" / "azure" / "azure_scanner.py",
    ATTACKS_DIR / "cloud" / "gcp" / "gcp_scanner.py",
    ATTACKS_DIR / "cloud" / "kubernetes" / "kubernetes_scanner.py",
    ATTACKS_DIR / "cloud" / "kubernetes" / "container_scanner.py",
    
    # Cloud CNAPP files
    ATTACKS_DIR / "cloud" / "cnapp" / "ciem_scanner.py",
    ATTACKS_DIR / "cloud" / "cnapp" / "runtime_scanner.py",
    ATTACKS_DIR / "cloud" / "cnapp" / "drift_scanner.py",
    ATTACKS_DIR / "cloud" / "cnapp" / "data_security_scanner.py",
    ATTACKS_DIR / "cloud" / "cnapp" / "sbom_generator.py",
    
    # SAST provider files
    ATTACKS_DIR / "sast" / "providers" / "github_scanner.py",
    ATTACKS_DIR / "sast" / "providers" / "gitlab_scanner.py",
    ATTACKS_DIR / "sast" / "providers" / "bitbucket_scanner.py",
    ATTACKS_DIR / "sast" / "providers" / "azure_devops_scanner.py",
    ATTACKS_DIR / "sast" / "providers" / "generic_scanner.py",
]


def fix_imports_in_file(filepath: Path) -> int:
    """Fix imports in a single file. Returns number of fixes applied."""
    if not filepath.exists():
        print(f"  ⚠️ File not found: {filepath}")
        return 0
    
    content = filepath.read_text(encoding='utf-8')
    original_content = content
    fixes_applied = 0
    
    for old_import, new_import in IMPORT_FIXES.items():
        if old_import in content:
            content = content.replace(old_import, new_import)
            fixes_applied += 1
    
    if fixes_applied > 0:
        filepath.write_text(content, encoding='utf-8')
        print(f"  ✅ Fixed {fixes_applied} imports in: {filepath.name}")
    
    return fixes_applied


def main():
    print("=" * 60)
    print("FIX INTERNAL IMPORTS")
    print("=" * 60)
    
    total_fixes = 0
    files_fixed = 0
    
    for filepath in FILES_TO_UPDATE:
        fixes = fix_imports_in_file(filepath)
        if fixes > 0:
            total_fixes += fixes
            files_fixed += 1
    
    print("\n" + "=" * 60)
    print(f"COMPLETE: Fixed {total_fixes} imports in {files_fixed} files")
    print("=" * 60)


if __name__ == "__main__":
    main()
