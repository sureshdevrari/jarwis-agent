@echo off
REM ===========================================================================
REM Jarwis Agent - Windows Build Script
REM ===========================================================================
REM 
REM Builds the Windows installer (MSI) for Jarwis Security Agent.
REM Supports both 32-bit (x86) and 64-bit (x64) architectures.
REM 
REM Prerequisites:
REM   - Python 3.10+ with PyInstaller (both x86 and x64 if building both)
REM   - WiX Toolset v3.11+ (https://wixtoolset.org)
REM   - Azure CLI (for code signing)
REM
REM Usage:
REM   build.bat                    - Build 64-bit unsigned
REM   build.bat --sign             - Build 64-bit and sign with Azure Trusted Signing
REM   build.bat --arch x86         - Build 32-bit unsigned
REM   build.bat --arch x64         - Build 64-bit unsigned
REM   build.bat --arch all         - Build both 32-bit and 64-bit
REM   build.bat --arch all --sign  - Build both and sign
REM
REM ===========================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Jarwis Agent - Windows Build
echo ============================================================
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..
set BUILD_DIR_BASE=%PROJECT_ROOT%\dist\windows
set INSTALLER_DIR=%PROJECT_ROOT%\installer

REM Parse arguments
set SIGN_BUILD=0
set BUILD_ARCH=x64
:parse_args
if "%1"=="" goto :done_args
if "%1"=="--sign" set SIGN_BUILD=1
if "%1"=="--arch" (
    set BUILD_ARCH=%2
    shift
)
shift
goto :parse_args
:done_args

REM Build for specified architecture(s)
if "%BUILD_ARCH%"=="all" (
    echo Building for both x86 and x64 architectures...
    call :build_arch x64
    call :build_arch x86
) else (
    call :build_arch %BUILD_ARCH%
)

echo.
echo ============================================================
echo   Build Complete!
echo ============================================================
echo.
if "%BUILD_ARCH%"=="all" (
    echo Output files:
    echo   64-bit: %BUILD_DIR_BASE%\x64\jarwis-agent_x64.msi
    echo   32-bit: %BUILD_DIR_BASE%\x86\jarwis-agent_x86.msi
) else (
    echo Output files:
    echo   Executable: %BUILD_DIR_BASE%\%BUILD_ARCH%\jarwis-agent.exe
    echo   Installer:  %BUILD_DIR_BASE%\%BUILD_ARCH%\jarwis-agent_%BUILD_ARCH%.msi
)
echo.
echo Silent install command:
echo   msiexec /i jarwis-agent_x64.msi /quiet ACTIVATION_KEY=xxx
echo.

endlocal
exit /b 0

REM ===========================================================================
REM Function: build_arch
REM Builds for a specific architecture (x86 or x64)
REM ===========================================================================
:build_arch
set ARCH=%1
set BUILD_DIR=%BUILD_DIR_BASE%\%ARCH%

echo.
echo --- Building for %ARCH% ---
echo.

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Building %ARCH% executable with PyInstaller...
cd /d "%PROJECT_ROOT%"

REM Set target arch for PyInstaller
if "%ARCH%"=="x86" (
    set PYINSTALLER_ARCH=--target-architecture x86
) else (
    set PYINSTALLER_ARCH=
)

python -m PyInstaller "%INSTALLER_DIR%\jarwis-agent.spec" ^
    --distpath "%BUILD_DIR%" ^
    --workpath "%BUILD_DIR%\build" ^
    %PYINSTALLER_ARCH% ^
    --clean ^
    --noconfirm

if errorlevel 1 (
    echo ERROR: PyInstaller build failed for %ARCH%
    exit /b 1
)

echo [2/4] Copying additional files...
copy "%PROJECT_ROOT%\config\config.yaml" "%BUILD_DIR%\config.yaml"
copy "%PROJECT_ROOT%\LICENSE" "%BUILD_DIR%\LICENSE.txt"
echo Jarwis Security Agent - See https://jarwis.io for documentation > "%BUILD_DIR%\README.txt"

REM Create license.rtf for WiX
echo {\rtf1 Jarwis Security Agent License Agreement\par\par End User License Agreement...} > "%BUILD_DIR%\license.rtf"

REM Create placeholder banner images if they don't exist
if not exist "%BUILD_DIR%\banner.bmp" (
    echo Creating placeholder installer images...
    copy nul "%BUILD_DIR%\banner.bmp" >nul
    copy nul "%BUILD_DIR%\dialog.bmp" >nul
)

if %SIGN_BUILD%==1 (
    echo [3/4] Signing executable with Azure Trusted Signing...
    
    az trustedsigning sign ^
        --account-name jarwis-signing ^
        --certificate-profile JarwisCodeSign ^
        --endpoint https://eus.codesigning.azure.net ^
        --files "%BUILD_DIR%\jarwis-agent.exe" ^
        --description "Jarwis Security Agent" ^
        --timestamp-rfc3161 http://timestamp.acs.microsoft.com ^
        --timestamp-digest SHA256
    
    if errorlevel 1 (
        echo WARNING: Code signing failed, continuing with unsigned build
    ) else (
        echo Executable signed successfully
    )
) else (
    echo [3/4] Skipping code signing (use --sign to enable)
)

echo [4/4] Building MSI installer for %ARCH%...

where candle >nul 2>&1
if errorlevel 1 (
    echo ERROR: WiX Toolset not found in PATH
    echo Download from: https://wixtoolset.org/releases/
    exit /b 1
)

cd /d "%BUILD_DIR%"

REM Set platform for WiX
if "%ARCH%"=="x86" (
    set WIX_PLATFORM=x86
) else (
    set WIX_PLATFORM=x64
)

candle "%INSTALLER_DIR%\windows\jarwis-agent.wxs" ^
    -dSourceDir="%BUILD_DIR%" ^
    -dPlatform=%WIX_PLATFORM% ^
    -arch %WIX_PLATFORM% ^
    -out jarwis-agent.wixobj

if errorlevel 1 (
    echo ERROR: WiX candle failed
    exit /b 1
)

light jarwis-agent.wixobj ^
    -ext WixUIExtension ^
    -ext WixUtilExtension ^
    -out jarwis-agent_%ARCH%.msi

if errorlevel 1 (
    echo ERROR: WiX light failed
    exit /b 1
)

if %SIGN_BUILD%==1 (
    echo Signing MSI installer...
    az trustedsigning sign ^
        --account-name jarwis-signing ^
        --certificate-profile JarwisCodeSign ^
        --endpoint https://eus.codesigning.azure.net ^
        --files "%BUILD_DIR%\jarwis-agent_%ARCH%.msi" ^
        --description "Jarwis Security Agent Installer" ^
        --timestamp-rfc3161 http://timestamp.acs.microsoft.com ^
        --timestamp-digest SHA256
)

echo Build complete for %ARCH%
exit /b 0
