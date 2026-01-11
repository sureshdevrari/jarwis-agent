#!/usr/bin/env python3
"""
Backup helper for Jarwis on Windows.
- Copies key source/config/test/docs assets to a destination folder.
- Excludes heavy/rebuildable artifacts (node_modules, .venv, caches, temp, uploads, logs).
- Optionally writes a fresh guide.txt and compresses the payload into a zip.

Usage (from repo root):
  python scripts/backup_project.py --dest "D:\\backup-8jan-2pm\\payload" --zip-name "jarwis-backup-8jan-2pm.zip"

You can override dest/zip and skip zip with --skip-zip.
"""

import argparse
import fnmatch
import os
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DEST = Path(r"D:\\backup-8jan-2pm\\payload")
DEFAULT_ZIP_NAME = "jarwis-backup-8jan-2pm.zip"

INCLUDE_DIRS = [
    "api",
    "services",
    "core",
    "attacks",
    "shared",
    "database",
    "config",
    "jarwisfrontend",
    "frontend",
    "tests",
    "templates",
    "reports",
    "docs",
    "scripts",
    "Ai_training",
    "Ai Logo",
    "jarwisfrontend-theme-demo",
    "frontend-design",
    "mobsec",
    "network security",
    "otp_logic",
    "developer_input",
    "reminders",
]

INCLUDE_FILES = [
    "requirements.txt",
    "package.json",
    "Dockerfile.backend",
    "Dockerfile.frontend",
    "docker-compose.yml",
    "deployment_manifest.json",
    "main.py",
    "start_server.py",
    "start_server_windows.py",
    "start_server.bat",
    "start_jarwis.py",
    "start_jarwis.ps1",
    "start_dev.ps1",
    "start_frontend.bat",
    "start_backend.bat",
    "README.md",
    "SYSTEM_REQUIREMENTS.md",
    "DASHBOARD_QUICK_START.md",
    "ENTERPRISE_DASHBOARD_IMPLEMENTATION.md",
    "CLOUD_IMPLEMENTATION_GUIDE.md",
    "CLOUD_FINAL_STATUS.md",
    "CLOUD_IMPLEMENTATION_STATUS.md",
    "test_all_apis.py",
    "test_runner.py",
    "test_all_scans_integration.py",
    "test_all_scan_types.py",
    "test_startup_debug.py",
    "test_login_api.py",
    "test_api.py",
    "test_web_scan_complete.py",
    "test_cloud_e2e.py",
    "test_cloud_integration.py",
    "test_dashboard_api.py",
    "test_network_api.py",
    "test_password.py",
    "key.txt",
]

EXCLUDE_DIR_NAMES = {
    "node_modules",
    ".venv",
    "__pycache__",
    ".git",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".cache",
    "temp",
    "uploads",
    "logs",
}

EXCLUDE_PATTERNS = {"*.pyc", "*.pyo", "*.log"}


def should_skip_dir(name: str) -> bool:
    return name in EXCLUDE_DIR_NAMES


def should_skip_file(filename: str) -> bool:
    return any(fnmatch.fnmatch(filename, pat) for pat in EXCLUDE_PATTERNS)


def copy_directory(src: Path, dest: Path, verbose: bool = False) -> None:
    if not src.exists():
        return
    for root, dirnames, filenames in os.walk(src):
        dirnames[:] = [d for d in dirnames if not should_skip_dir(d)]
        rel_root = Path(root).relative_to(src)
        dest_root = dest / rel_root
        dest_root.mkdir(parents=True, exist_ok=True)
        for fname in filenames:
            if should_skip_file(fname):
                continue
            src_file = Path(root) / fname
            dest_file = dest_root / fname
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)
            if verbose:
                print(f"copied {src_file} -> {dest_file}")


def copy_file(src: Path, dest: Path, verbose: bool = False) -> None:
    if not src.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    if verbose:
        print(f"copied {src} -> {dest}")


def write_guide(dest_root: Path) -> None:
    guide_path = dest_root / "guide.txt"
    content = (
        "Jarwis Backup Guide\n"
        "==================\n"
        "Scope: Backend (api, services, core, attacks, shared, database), frontend (jarwisfrontend, frontend), configs, tests, docs, scripts. Excludes node_modules/.venv/caches/temp/uploads/logs.\n\n"
        "Prereqs: Python 3.10+, Node.js LTS, optional Docker.\n\n"
        "Setup:\n"
        "1) python -m venv .venv\n"
        "2) .\\.venv\\Scripts\\Activate.ps1\n"
        "3) pip install -r requirements.txt\n"
        "4) python -m playwright install (for PDF/report)\n"
        "5) cd jarwisfrontend && npm install (and frontend/ if used)\n"
        "6) python shared/generate_frontend_types.py (if contracts changed)\n\n"
        "Run:\n"
        "- Backend: .\\.venv\\Scripts\\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload\n"
        "- Frontend: cd jarwisfrontend && npm start\n\n"
        "Notes: shared/ holds contracts; api routes call services; services hold business logic; core has scanners; jarwisfrontend/src/services/api.js is the API client.\n"
    )
    guide_path.write_text(content, encoding="utf-8")


def make_zip(source_root: Path, zip_path: Path, verbose: bool = False) -> None:
    if verbose:
        print(f"creating zip {zip_path}")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in source_root.rglob("*"):
            if file_path.is_dir():
                continue
            rel = file_path.relative_to(source_root)
            zf.write(file_path, rel)
            if verbose:
                print(f"zipped {file_path} as {rel}")


def run_backup(dest_root: Path, zip_name: str, skip_zip: bool, write_guide_file: bool, verbose: bool) -> Path:
    dest_root.mkdir(parents=True, exist_ok=True)

    for d in INCLUDE_DIRS:
        copy_directory(BASE_DIR / d, dest_root / d, verbose=verbose)

    for fname in INCLUDE_FILES:
        copy_file(BASE_DIR / fname, dest_root / fname, verbose=verbose)

    if write_guide_file:
        write_guide(dest_root)

    zip_path = dest_root.parent / zip_name
    if not skip_zip:
        make_zip(dest_root, zip_path, verbose=verbose)
    return zip_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update Jarwis backup folder and zip archive.")
    parser.add_argument("--dest", type=Path, default=DEFAULT_DEST, help="Destination folder for the backup payload")
    parser.add_argument("--zip-name", default=DEFAULT_ZIP_NAME, help="Zip filename to create alongside dest")
    parser.add_argument("--skip-zip", action="store_true", help="Skip creating the zip archive")
    parser.add_argument("--no-guide", action="store_true", help="Do not write guide.txt")
    parser.add_argument("--verbose", action="store_true", help="Verbose copy output")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    zip_path = run_backup(
        dest_root=args.dest,
        zip_name=args.zip_name,
        skip_zip=args.skip_zip,
        write_guide_file=not args.no_guide,
        verbose=args.verbose,
    )
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Backup completed at {timestamp}")
    print(f"Payload folder: {args.dest}")
    if not args.skip_zip:
        print(f"Zip archive: {zip_path}")


if __name__ == "__main__":
    main()
