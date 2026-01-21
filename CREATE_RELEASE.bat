@echo off
:: ============================================================================
:: Jarwis Agent - Create New Release
:: ============================================================================
:: This script commits changes and creates a new tag to trigger the GitHub
:: Actions workflow that builds installers for all platforms.
::
:: Usage: CREATE_RELEASE.bat [version]
:: Example: CREATE_RELEASE.bat 2.2.0
:: ============================================================================

setlocal EnableDelayedExpansion

:: Get version from argument or prompt
if "%~1"=="" (
    set /p VERSION="Enter release version (e.g., 2.2.0): "
) else (
    set VERSION=%~1
)

if "%VERSION%"=="" (
    echo Error: Version is required
    exit /b 1
)

echo.
echo ============================================
echo   Jarwis Agent Release Creator
echo ============================================
echo.
echo Creating release: v%VERSION%
echo.

:: Check if git is available
where git >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Git is not installed or not in PATH
    exit /b 1
)

:: Check for uncommitted changes
git status --porcelain > nul
for /f %%i in ('git status --porcelain 2^>nul') do set HAS_CHANGES=1

if defined HAS_CHANGES (
    echo Found uncommitted changes. Committing them...
    git add .
    git commit -m "Release v%VERSION%"
    echo.
)

:: Check if tag already exists
git rev-parse "v%VERSION%" >nul 2>&1
if %errorlevel% equ 0 (
    echo Error: Tag v%VERSION% already exists!
    echo Use a different version number or delete the existing tag:
    echo   git tag -d v%VERSION%
    echo   git push origin :refs/tags/v%VERSION%
    exit /b 1
)

:: Create tag
echo Creating tag v%VERSION%...
git tag -a "v%VERSION%" -m "Release v%VERSION%"

:: Push to remote
echo.
echo Pushing to GitHub...
git push origin main
git push origin "v%VERSION%"

echo.
echo ============================================
echo   Release v%VERSION% created successfully!
echo ============================================
echo.
echo The GitHub Actions workflow will now:
echo   1. Build Windows installer (EXE, MSI, GUI Setup)
echo   2. Build macOS installer (Intel + Apple Silicon)
echo   3. Build Linux packages (DEB, RPM)
echo   4. Create GitHub Release with all assets
echo.
echo Track progress at:
echo   https://github.com/sureshdevrari/jarwis-agent/actions
echo.
echo View release when ready:
echo   https://github.com/sureshdevrari/jarwis-agent/releases/tag/v%VERSION%
echo.

pause
