@echo off
REM ===========================================================================
REM Jarwis Agent - Inno Setup Build Script
REM ===========================================================================
REM 
REM Builds the Windows EXE installer using Inno Setup.
REM This creates a user-friendly installer with GUI wizard.
REM 
REM Prerequisites:
REM   - Python 3.10+ with PyInstaller
REM   - Inno Setup 6.2+ (https://jrsoftware.org/isinfo.php)
REM   - Pillow (for icon generation)
REM
REM Usage:
REM   build_inno.bat                 - Build unsigned installer
REM   build_inno.bat --sign          - Build and sign installer
REM
REM ===========================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Jarwis Agent - Inno Setup Build
echo ============================================================
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..
set INSTALLER_DIR=%PROJECT_ROOT%\installer
set BUILD_DIR=%PROJECT_ROOT%\dist\windows\x64
set OUTPUT_DIR=%PROJECT_ROOT%\dist\inno

REM Parse arguments
set SIGN_BUILD=0
:parse_args
if "%1"=="" goto :done_args
if "%1"=="--sign" set SIGN_BUILD=1
shift
goto :parse_args
:done_args

REM Step 1: Create branding assets
echo [1/5] Generating branding assets...
cd /d "%INSTALLER_DIR%\assets"

if not exist "icons\jarwis-agent.ico" (
    echo Creating icons and bitmaps...
    python create_icons.py
    if errorlevel 1 (
        echo WARNING: Could not generate icons. Using defaults.
    )
)

REM Step 2: Build main executable with PyInstaller
echo [2/5] Building executable with PyInstaller...
cd /d "%PROJECT_ROOT%"

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

python -m PyInstaller "%INSTALLER_DIR%\jarwis-agent.spec" ^
    --distpath "%BUILD_DIR%\.." ^
    --workpath "%BUILD_DIR%\build" ^
    --clean ^
    --noconfirm

if errorlevel 1 (
    echo ERROR: PyInstaller build failed
    exit /b 1
)

REM Step 3: Build system tray application
echo [3/5] Building system tray application...

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --name jarwis-tray ^
    --icon "%INSTALLER_DIR%\assets\icons\jarwis-agent.ico" ^
    --distpath "%BUILD_DIR%" ^
    --workpath "%BUILD_DIR%\build" ^
    "%INSTALLER_DIR%\gui\system_tray.py"

if errorlevel 1 (
    echo WARNING: System tray build failed, continuing...
)

REM Step 4: Copy additional files
echo [4/5] Preparing installer files...
copy "%PROJECT_ROOT%\config\config.yaml" "%BUILD_DIR%\config.yaml" >nul 2>&1

REM Step 5: Build Inno Setup installer
echo [5/5] Building Inno Setup installer...

where iscc >nul 2>&1
if errorlevel 1 (
    echo ERROR: Inno Setup Compiler (ISCC) not found in PATH
    echo Download from: https://jrsoftware.org/isdl.php
    exit /b 1
)

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

cd /d "%INSTALLER_DIR%\inno"
iscc jarwis-agent.iss

if errorlevel 1 (
    echo ERROR: Inno Setup compilation failed
    exit /b 1
)

REM Optional: Sign the installer
if %SIGN_BUILD%==1 (
    echo Signing installer...
    
    REM Using Azure Trusted Signing
    az trustedsigning sign ^
        --account-name jarwis-signing ^
        --certificate-profile JarwisCodeSign ^
        --endpoint https://eus.codesigning.azure.net ^
        --files "%OUTPUT_DIR%\jarwis-agent-*-setup.exe" ^
        --description "Jarwis Security Agent Installer" ^
        --timestamp-rfc3161 http://timestamp.acs.microsoft.com ^
        --timestamp-digest SHA256
    
    if errorlevel 1 (
        echo WARNING: Code signing failed
    ) else (
        echo Installer signed successfully
    )
)

echo.
echo ============================================================
echo   Build Complete!
echo ============================================================
echo.
echo Output file:
for %%f in ("%OUTPUT_DIR%\jarwis-agent-*-setup.exe") do echo   %%f
echo.
echo The installer includes:
echo   - Welcome page with Jarwis branding
echo   - License agreement
echo   - Installation path selection
echo   - Feature selection (Web, Mobile, Network, Cloud, SAST)
echo   - Server configuration
echo   - Windows service installation
echo   - System tray application
echo   - Start menu shortcuts
echo.

endlocal
exit /b 0
