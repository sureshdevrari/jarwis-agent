@echo off
REM Migrate existing plaintext credentials to encrypted storage
REM Run with --dry-run first to preview changes

echo ================================================
echo Jarwis Credential Migration Tool
echo ================================================
echo.

cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found
    echo Run: python -m venv .venv
    exit /b 1
)

set "PYTHON=.venv\Scripts\python.exe"

REM Check if encryption key is set
if "%JARWIS_ENCRYPTION_KEY%"=="" (
    echo WARNING: JARWIS_ENCRYPTION_KEY not set
    echo A temporary key will be generated and stored in .env
    echo For production, set this environment variable securely
    echo.
)

if "%1"=="--dry-run" (
    echo Running in DRY RUN mode - no changes will be made
    echo.
    %PYTHON% scripts/migrate_credentials.py --dry-run
) else if "%1"=="--help" (
    echo Usage:
    echo   MIGRATE_CREDENTIALS.bat --dry-run    Preview changes
    echo   MIGRATE_CREDENTIALS.bat              Apply migration
    echo   MIGRATE_CREDENTIALS.bat --force      Force re-encrypt all
    echo.
) else (
    echo Running LIVE migration
    echo.
    echo Press CTRL+C to cancel or any key to continue...
    pause >nul
    %PYTHON% scripts/migrate_credentials.py %*
)

echo.
echo ================================================
echo Migration complete
echo ================================================
