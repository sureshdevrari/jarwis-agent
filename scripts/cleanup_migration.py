#!/usr/bin/env python3
"""
Cleanup script to remove files from old locations after migration.
Only removes files that now exist in their new OWASP-organized locations.
"""

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
ATTACKS_DIR = PROJECT_ROOT / "attacks"

# Files that were migrated to OWASP categories (should be removed from pre_login)
WEB_MIGRATED_FILES = [
    # A01: Broken Access Control
    "idor_scanner.py",
    "access_control_scanner.py",
    "auth_bypass_scanner.py",
    "path_traversal_scanner.py",
    # A02: Cryptographic Failures
    "jwt_scanner.py",
    "session_scanner.py",
    # A03: Injection
    "injection_scanner.py",
    "sqli_advanced_scanner.py",
    "xss_scanner.py",
    "xss_advanced_scanner.py",
    "xss_reflected_scanner.py",
    "xss_stored_scanner.py",
    "ssti_scanner.py",
    "xxe_scanner.py",
    "ldap_injection_scanner.py",
    # A04: Insecure Design
    "business_logic_scanner.py",
    "race_condition_scanner.py",
    "captcha_scanner.py",
    # A05: Security Misconfiguration
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
    # A06: Vulnerable Components
    "subdomain_takeover_scanner.py",
    # A07: Auth Failures
    "auth_scanner.py",
    "csrf_scanner.py",
    "clickjacking_scanner.py",
    "oauth_scanner.py",
    "oauth_saml_scanner.py",
    # A08: Integrity
    "prototype_pollution_scanner.py",
    # A09: Logging
    "sensitive_data_scanner.py",
    # A10: SSRF
    "ssrf_scanner.py",
    "ssrf_advanced_scanner.py",
    # API
    "api_scanner.py",
    "api_security_scanner.py",
    "graphql_scanner.py",
    "websocket_scanner.py",
    # File Upload
    "file_upload_scanner.py",
    "upload_scanner.py",
    # Other
    "post_method_scanner.py",
    "smuggling_scanner.py",
    "rate_limit_scanner.py",
]

# Cloud files that were migrated (should be removed from cloud root)
CLOUD_MIGRATED_FILES = [
    "aws_scanner.py",
    "azure_scanner_complete.py",
    "gcp_scanner.py",
    "kubernetes_scanner.py",
    "container_scanner.py",
    "base.py",
    "cloud_scanner.py",
    "iac_scanner.py",
    "compliance_mapper.py",
    "config.py",
    "schemas.py",
    "exceptions.py",
    "ciem_scanner.py",
    "runtime_scanner.py",
    "drift_scanner.py",
    "data_security_scanner.py",
    "sbom_generator.py",
]

# Mobile files that were migrated (should be removed from mobile root)
MOBILE_MIGRATED_FILES = [
    "static_analyzer.py",
    "unpacker.py",
    "dynamic_crawler.py",
    "runtime_analyzer.py",
    "app_crawler.py",
    "frida_ssl_bypass.py",
    "android_attacks.py",
    "emulator_manager.py",
    "ios_attacks.py",
    "ios_simulator_manager.py",
    "api_discovery.py",
    "mobile_mitm.py",
    "burp_interceptor.py",
    "mobile_orchestrator.py",
    "mobile_scanner.py",
    "mobile_post_scanner.py",
    "auth_detector.py",
    "otp_handler.py",
    "llm_analyzer.py",
    "deeplink_scanner.py",
    "mobile_xss_scanner.py",
]

# SAST files that were migrated (should be removed from sast root)
SAST_MIGRATED_FILES = [
    "github_scanner.py",
    "gitlab_scanner.py",
    "bitbucket_scanner.py",
    "azure_devops_scanner.py",
    "aws_codecommit_scanner.py",
    "gitea_scanner.py",
    "generic_scanner.py",
    "secret_scanner.py",
    "dependency_scanner.py",
    "code_analyzer.py",
]


def cleanup_web():
    """Remove migrated web files from pre_login folder."""
    pre_login_dir = ATTACKS_DIR / "web" / "pre_login"
    print("\n📁 Cleaning up Web/pre_login folder...")
    
    removed = 0
    for filename in WEB_MIGRATED_FILES:
        filepath = pre_login_dir / filename
        if filepath.exists():
            filepath.unlink()
            print(f"  Removed: {filename}")
            removed += 1
    
    print(f"  Total removed: {removed} files")


def cleanup_cloud():
    """Remove migrated cloud files from cloud root folder."""
    cloud_dir = ATTACKS_DIR / "cloud"
    print("\n☁️ Cleaning up Cloud root folder...")
    
    removed = 0
    for filename in CLOUD_MIGRATED_FILES:
        filepath = cloud_dir / filename
        if filepath.exists():
            filepath.unlink()
            print(f"  Removed: {filename}")
            removed += 1
    
    print(f"  Total removed: {removed} files")


def cleanup_mobile():
    """Remove migrated mobile files from mobile root folder."""
    mobile_dir = ATTACKS_DIR / "mobile"
    print("\n📱 Cleaning up Mobile root folder...")
    
    removed = 0
    for filename in MOBILE_MIGRATED_FILES:
        filepath = mobile_dir / filename
        if filepath.exists():
            filepath.unlink()
            print(f"  Removed: {filename}")
            removed += 1
    
    print(f"  Total removed: {removed} files")


def cleanup_sast():
    """Remove migrated SAST files from sast root folder."""
    sast_dir = ATTACKS_DIR / "sast"
    print("\n🔍 Cleaning up SAST root folder...")
    
    removed = 0
    for filename in SAST_MIGRATED_FILES:
        filepath = sast_dir / filename
        if filepath.exists():
            filepath.unlink()
            print(f"  Removed: {filename}")
            removed += 1
    
    print(f"  Total removed: {removed} files")


def main():
    print("=" * 60)
    print("POST-MIGRATION CLEANUP")
    print("=" * 60)
    
    cleanup_web()
    cleanup_cloud()
    cleanup_mobile()
    cleanup_sast()
    
    print("\n" + "=" * 60)
    print("CLEANUP COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
