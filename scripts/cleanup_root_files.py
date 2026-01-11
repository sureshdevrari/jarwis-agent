#!/usr/bin/env python3
"""
Jarwis Root Directory Cleanup Script
=====================================

This script moves misplaced files from the root directory to their proper locations.

Files are categorized as:
- Tests (test_*.py) → tests/
- Scripts (utilities, migrations, debugging) → scripts/
- Docs (*.md documentation) → docs/
- Logs (*.log) → logs/ or DELETE
- Temporary files → DELETE

Usage:
    python scripts/cleanup_root_files.py --dry-run    # Preview changes
    python scripts/cleanup_root_files.py              # Execute cleanup
    python scripts/cleanup_root_files.py --revert     # Undo changes (if manifest exists)

Author: Jarwis AI
Date: January 9, 2026
"""

import os
import sys
import shutil
import json
import argparse
from pathlib import Path
from datetime import datetime

# Project root
ROOT_DIR = Path(__file__).parent.parent

# Cleanup manifest (for undo support)
MANIFEST_FILE = ROOT_DIR / "scripts" / ".cleanup_manifest.json"


# =============================================================================
# FILE CATEGORIZATION
# =============================================================================

# Files to move to tests/
TESTS = [
    "test_all_apis.py",
    "test_all_scan_types.py",
    "test_all_scans_integration.py",
    "test_api.py",
    "test_api_full.py",
    "test_attack_demo.py",
    "test_auth_attacks.py",
    "test_cloud_e2e.py",
    "test_cloud_integration.py",
    "test_crawl_only.py",
    "test_dashboard_api.py",
    "test_e2e_scan.py",
    "test_https_scan.py",
    "test_input_attacks.py",
    "test_login_api.py",
    "test_network_api.py",
    "test_password.py",
    "test_resilience.py",
    "test_runner.py",
    "test_scan.py",
    "test_simple_scan.py",
    "test_startup_debug.py",
    "test_web_scan_complete.py",
    "temp_scan_test.py",
]

# Files to move to scripts/
SCRIPTS = [
    "audit_dashboard.py",
    "check_latest_scans.py",
    "check_logs.py",
    "check_scans.py",
    "check_user2_issue.py",
    "check_user2_scans.py",
    "clean_jsx_ascii.py",
    "create_users.py",
    "deploy_gateway.py",
    "diagnose_login.py",
    "fix_jsx_patterns.py",
    "generate_cloud_scanners.py",
    "list_users.py",
    "migrate_network_scanning.py",
    "migrate_scan_diagnostics.py",
    "requiredtools.py",
    "set_password.py",
    "setup_emulator.py",
    "update_all_users.py",
    "upgrade_user.py",
    "validate_network_architecture.py",
    "validate_restructure.py",
    "NETWORK_SCANNING_QUICKSTART.py",
    "run_mobile_scan.py",
    "jarwis_agent.py",
]

# Files to move to docs/
DOCS = [
    "CLOUD_VISUAL_SUMMARY.txt",
    "DASHBOARD_QUICK_START.md",
    "ENTERPRISE_DASHBOARD_IMPLEMENTATION.md",
    "NETWORK_SCANNING_COMPLETED.md",
    "NETWORK_SCANNING_REFACTOR.md",
    "NETWORK_SCANNING_SUMMARY.md",
    "SYSTEM_REQUIREMENTS.md",
]

# Files to DELETE (temporary logs)
DELETE = [
    "test_error2.log",
    "test_final_output.log",
    "test_full_output.log",
    "test_output.log",
    "test_output2.log",
    "test_report_output.log",
]

# Files to move to logs/
LOGS = [
    "server.log",
]

# Files that should STAY in root (entry points, config)
KEEP_IN_ROOT = [
    "main.py",
    "requirements.txt",
    "docker-compose.yml",
    "Dockerfile.backend",
    "Dockerfile.frontend",
    "README.md",
    "START_HERE.md",
    "start_jarwis.py",
    "start_jarwis.ps1",
    "start_server.py",
    "start_server_windows.py",
    "start_backend.bat",
    "start_frontend.bat",
    "start_dev.ps1",
    "nginx.conf",
    "package.json",
    "package-lock.json",
    ".env",
    ".env.example",
    "cleanup.ps1",
    "deploy.ps1",
    "deploy.sh",
    "diagnose_api.ps1",
    "monitor_services.ps1",
    "restore.ps1",
    "install_jarwis_tools.sh",
    "deployment_manifest.json",
    "key.txt",
    "jarwis.db",
]


# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

def get_file_moves():
    """Build list of file moves"""
    moves = []
    
    # Tests → tests/
    for f in TESTS:
        src = ROOT_DIR / f
        if src.exists():
            moves.append({
                "src": str(src),
                "dst": str(ROOT_DIR / "tests" / f),
                "category": "test"
            })
    
    # Scripts → scripts/
    for f in SCRIPTS:
        src = ROOT_DIR / f
        if src.exists():
            moves.append({
                "src": str(src),
                "dst": str(ROOT_DIR / "scripts" / f),
                "category": "script"
            })
    
    # Docs → docs/
    for f in DOCS:
        src = ROOT_DIR / f
        if src.exists():
            moves.append({
                "src": str(src),
                "dst": str(ROOT_DIR / "docs" / f),
                "category": "doc"
            })
    
    # Logs → logs/
    for f in LOGS:
        src = ROOT_DIR / f
        if src.exists():
            moves.append({
                "src": str(src),
                "dst": str(ROOT_DIR / "logs" / f),
                "category": "log"
            })
    
    return moves


def get_files_to_delete():
    """Get list of files to delete"""
    deletes = []
    for f in DELETE:
        src = ROOT_DIR / f
        if src.exists():
            deletes.append(str(src))
    return deletes


def preview_changes():
    """Show what will happen without making changes"""
    moves = get_file_moves()
    deletes = get_files_to_delete()
    
    print("\n" + "=" * 70)
    print(" JARWIS ROOT CLEANUP - DRY RUN PREVIEW")
    print("=" * 70)
    
    # Group by destination
    by_dest = {}
    for m in moves:
        dest_dir = Path(m["dst"]).parent.name
        if dest_dir not in by_dest:
            by_dest[dest_dir] = []
        by_dest[dest_dir].append(m)
    
    for dest, items in by_dest.items():
        print(f"\n📁 Move to {dest}/ ({len(items)} files)")
        for item in items:
            src_name = Path(item["src"]).name
            print(f"   ├── {src_name}")
    
    if deletes:
        print(f"\n🗑️  Delete ({len(deletes)} files)")
        for d in deletes:
            print(f"   ├── {Path(d).name}")
    
    # Summary
    print("\n" + "-" * 70)
    print(f"SUMMARY: {len(moves)} files to move, {len(deletes)} files to delete")
    print("-" * 70)
    
    # Files staying in root
    root_files = [f for f in os.listdir(ROOT_DIR) 
                  if os.path.isfile(ROOT_DIR / f) and f not in [Path(m["src"]).name for m in moves] and f not in [Path(d).name for d in deletes]]
    
    print(f"\n✅ Staying in root ({len(root_files)} files)")
    for f in sorted(root_files):
        if not f.startswith('.'):
            print(f"   ├── {f}")
    
    print("\n" + "=" * 70)
    print(" Run without --dry-run to execute these changes")
    print("=" * 70 + "\n")


def execute_cleanup():
    """Execute the cleanup"""
    moves = get_file_moves()
    deletes = get_files_to_delete()
    
    print("\n" + "=" * 70)
    print(" JARWIS ROOT CLEANUP - EXECUTING")
    print("=" * 70)
    
    # Save manifest for undo
    manifest = {
        "timestamp": datetime.now().isoformat(),
        "moves": [],
        "deletes": []
    }
    
    # Ensure target directories exist
    (ROOT_DIR / "tests").mkdir(exist_ok=True)
    (ROOT_DIR / "scripts").mkdir(exist_ok=True)
    (ROOT_DIR / "docs").mkdir(exist_ok=True)
    (ROOT_DIR / "logs").mkdir(exist_ok=True)
    
    # Execute moves
    moved_count = 0
    for m in moves:
        src = Path(m["src"])
        dst = Path(m["dst"])
        
        if src.exists():
            # Check if destination already has a file with same name
            if dst.exists():
                print(f"⚠️  SKIP (exists): {src.name} → {dst.parent.name}/")
                continue
            
            shutil.move(str(src), str(dst))
            manifest["moves"].append({"src": str(dst), "dst": str(src)})  # Reversed for undo
            print(f"✅ MOVED: {src.name} → {dst.parent.name}/")
            moved_count += 1
    
    # Execute deletes
    deleted_count = 0
    for d in deletes:
        src = Path(d)
        if src.exists():
            # Backup before delete (to logs/)
            backup_path = ROOT_DIR / "logs" / f".deleted_{src.name}"
            shutil.copy2(str(src), str(backup_path))
            os.remove(str(src))
            manifest["deletes"].append({"file": str(d), "backup": str(backup_path)})
            print(f"🗑️  DELETED: {src.name} (backup in logs/)")
            deleted_count += 1
    
    # Save manifest
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print("\n" + "-" * 70)
    print(f"COMPLETE: {moved_count} files moved, {deleted_count} files deleted")
    print(f"Manifest saved to: {MANIFEST_FILE}")
    print("-" * 70 + "\n")
    
    return moved_count, deleted_count


def revert_cleanup():
    """Revert the cleanup using manifest"""
    if not MANIFEST_FILE.exists():
        print("❌ No cleanup manifest found. Cannot revert.")
        return
    
    with open(MANIFEST_FILE, 'r') as f:
        manifest = json.load(f)
    
    print("\n" + "=" * 70)
    print(" JARWIS ROOT CLEANUP - REVERTING")
    print(f" Manifest from: {manifest['timestamp']}")
    print("=" * 70)
    
    # Restore deleted files
    for d in manifest.get("deletes", []):
        backup = Path(d["backup"])
        original = Path(d["file"])
        if backup.exists():
            shutil.move(str(backup), str(original))
            print(f"♻️  RESTORED: {original.name}")
    
    # Undo moves
    for m in manifest.get("moves", []):
        src = Path(m["src"])  # Current location
        dst = Path(m["dst"])  # Original location
        if src.exists():
            shutil.move(str(src), str(dst))
            print(f"↩️  REVERTED: {dst.name}")
    
    # Remove manifest
    os.remove(MANIFEST_FILE)
    print("\n✅ Cleanup reverted successfully\n")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Clean up misplaced files from Jarwis root directory"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true",
        help="Preview changes without executing"
    )
    parser.add_argument(
        "--revert",
        action="store_true",
        help="Revert previous cleanup using saved manifest"
    )
    
    args = parser.parse_args()
    
    if args.revert:
        revert_cleanup()
    elif args.dry_run:
        preview_changes()
    else:
        # Confirm before executing
        print("\n⚠️  This will move files from root to their proper directories.")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() == 'y':
            execute_cleanup()
        else:
            print("Cancelled.")


if __name__ == "__main__":
    main()
