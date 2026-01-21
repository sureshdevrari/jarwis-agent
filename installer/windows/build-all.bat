@echo off
REM ===========================================================================
REM Jarwis Agent - Windows Full Build Script (CLI + GUI Components)
REM ===========================================================================
REM 
REM Builds all Windows components:
REM   1. jarwis-agent.exe      - CLI agent (core)
REM   2. JarwisAgentSetup-GUI.exe - GUI installer wizard
REM   3. jarwis-tray.exe       - System tray status app
REM   4. jarwis-config.exe     - Configuration tool
REM   5. Inno Setup installer  - Combined EXE installer
REM   6. WiX MSI installer     - Enterprise deployment
REM 
REM Prerequisites:
REM   - Python 3.10+ with PyInstaller
REM   - PyQt6 (pip install PyQt6)
REM   - WiX Toolset v3.11+ (optional, for MSI)
REM   - Inno Setup 6.2+ (optional, for EXE installer)
REM
REM Usage:
REM   build-all.bat              - Build all components
REM   build-all.bat --cli-only   - Build only CLI agent
REM   build-all.bat --gui-only   - Build only GUI components
REM   build-all.bat --sign       - Build and sign with Azure
REM   build-all.bat --skip-msi   - Skip MSI/Inno Setup creation
REM
REM ===========================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Jarwis Agent - Windows Full Build
echo ============================================================
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..\..
set BUILD_DIR=%PROJECT_ROOT%\dist\windows\x64
set INSTALLER_DIR=%PROJECT_ROOT%\installer
set GUI_DIR=%INSTALLER_DIR%\gui
set ASSETS_DIR=%INSTALLER_DIR%\assets

REM Parse arguments
set BUILD_CLI=1
set BUILD_GUI=1
set BUILD_INSTALLERS=1
set SIGN_BUILD=0

:parse_args
if "%1"=="" goto :done_args
if "%1"=="--cli-only" (
    set BUILD_GUI=0
    set BUILD_INSTALLERS=0
)
if "%1"=="--gui-only" set BUILD_CLI=0
if "%1"=="--skip-msi" set BUILD_INSTALLERS=0
if "%1"=="--sign" set SIGN_BUILD=1
shift
goto :parse_args
:done_args

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Count total steps
set TOTAL_STEPS=0
if %BUILD_CLI%==1 set /a TOTAL_STEPS+=1
if %BUILD_GUI%==1 set /a TOTAL_STEPS+=3
if %BUILD_INSTALLERS%==1 set /a TOTAL_STEPS+=1
set CURRENT_STEP=0

cd /d "%PROJECT_ROOT%"

REM ===========================================================================
REM Step 1: Build CLI Agent
REM ===========================================================================
if %BUILD_CLI%==1 (
    set /a CURRENT_STEP+=1
    echo.
    echo [!CURRENT_STEP!/%TOTAL_STEPS%] Building CLI Agent (jarwis-agent.exe)...
    echo.
    
    python -m PyInstaller "%INSTALLER_DIR%\jarwis-agent.spec" ^
        --distpath "%BUILD_DIR%" ^
        --workpath "%BUILD_DIR%\build\cli" ^
        --clean ^
        --noconfirm
    
    if errorlevel 1 (
        echo ERROR: CLI agent build failed
        exit /b 1
    )
    
    REM Rename to avoid conflict with folder
    if exist "%BUILD_DIR%\jarwis-agent\jarwis-agent.exe" (
        move "%BUILD_DIR%\jarwis-agent\jarwis-agent.exe" "%BUILD_DIR%\jarwis-agent.exe"
        rmdir /s /q "%BUILD_DIR%\jarwis-agent" 2>nul
    )
    
    echo    ✓ jarwis-agent.exe built successfully
)

REM ===========================================================================
REM Step 2: Build GUI Setup Wizard
REM ===========================================================================
if %BUILD_GUI%==1 (
    set /a CURRENT_STEP+=1
    echo.
    echo [!CURRENT_STEP!/%TOTAL_STEPS%] Building GUI Setup Wizard (JarwisAgentSetup-GUI.exe)...
    echo.
    
    python -m PyInstaller "%INSTALLER_DIR%\jarwis-setup-gui.spec" ^
        --distpath "%BUILD_DIR%" ^
        --workpath "%BUILD_DIR%\build\setup-gui" ^
        --clean ^
        --noconfirm
    
    if errorlevel 1 (
        echo ERROR: GUI Setup Wizard build failed
        exit /b 1
    )
    echo    ✓ JarwisAgentSetup-GUI.exe built successfully
)

REM ===========================================================================
REM Step 3: Build System Tray App
REM ===========================================================================
if %BUILD_GUI%==1 (
    set /a CURRENT_STEP+=1
    echo.
    echo [!CURRENT_STEP!/%TOTAL_STEPS%] Building System Tray App (jarwis-tray.exe)...
    echo.
    
    python -m PyInstaller "%INSTALLER_DIR%\jarwis-tray.spec" ^
        --distpath "%BUILD_DIR%" ^
        --workpath "%BUILD_DIR%\build\tray" ^
        --clean ^
        --noconfirm
    
    if errorlevel 1 (
        echo ERROR: System Tray build failed
        exit /b 1
    )
    echo    ✓ jarwis-tray.exe built successfully
)

REM ===========================================================================
REM Step 4: Build Configuration Tool
REM ===========================================================================
if %BUILD_GUI%==1 (
    set /a CURRENT_STEP+=1
    echo.
    echo [!CURRENT_STEP!/%TOTAL_STEPS%] Building Configuration Tool (jarwis-config.exe)...
    echo.
    
    python -m PyInstaller "%INSTALLER_DIR%\jarwis-config.spec" ^
        --distpath "%BUILD_DIR%" ^
        --workpath "%BUILD_DIR%\build\config" ^
        --clean ^
        --noconfirm
    
    if errorlevel 1 (
        echo ERROR: Configuration Tool build failed
        exit /b 1
    )
    echo    ✓ jarwis-config.exe built successfully
)

REM ===========================================================================
REM Copy Additional Files
REM ===========================================================================
echo.
echo Copying additional files...

REM Copy config template
if exist "%PROJECT_ROOT%\config\config.yaml" (
    copy /y "%PROJECT_ROOT%\config\config.yaml" "%BUILD_DIR%\config.yaml" >nul
)

REM Copy license
if exist "%PROJECT_ROOT%\LICENSE" (
    copy /y "%PROJECT_ROOT%\LICENSE" "%BUILD_DIR%\LICENSE.txt" >nul
)

REM Copy branding assets
if exist "%ASSETS_DIR%\icons\jarwis-agent.ico" (
    copy /y "%ASSETS_DIR%\icons\jarwis-agent.ico" "%BUILD_DIR%\jarwis-agent.ico" >nul
)

REM ===========================================================================
REM Code Signing (if enabled)
REM ===========================================================================
if %SIGN_BUILD%==1 (
    echo.
    echo Signing executables with Azure Trusted Signing...
    
    set FILES_TO_SIGN=
    if exist "%BUILD_DIR%\jarwis-agent.exe" set FILES_TO_SIGN=!FILES_TO_SIGN! "%BUILD_DIR%\jarwis-agent.exe"
    if exist "%BUILD_DIR%\JarwisAgentSetup-GUI.exe" set FILES_TO_SIGN=!FILES_TO_SIGN! "%BUILD_DIR%\JarwisAgentSetup-GUI.exe"
    if exist "%BUILD_DIR%\jarwis-tray.exe" set FILES_TO_SIGN=!FILES_TO_SIGN! "%BUILD_DIR%\jarwis-tray.exe"
    if exist "%BUILD_DIR%\jarwis-config.exe" set FILES_TO_SIGN=!FILES_TO_SIGN! "%BUILD_DIR%\jarwis-config.exe"
    
    for %%f in (!FILES_TO_SIGN!) do (
        echo    Signing %%~nxf...
        az trustedsigning sign ^
            --account-name jarwis-signing ^
            --certificate-profile JarwisCodeSign ^
            --endpoint https://eus.codesigning.azure.net ^
            --files "%%f" ^
            --description "Jarwis Security Agent" ^
            --timestamp-rfc3161 http://timestamp.acs.microsoft.com ^
            --timestamp-digest SHA256 >nul 2>&1
        
        if errorlevel 1 (
            echo    WARNING: Failed to sign %%~nxf
        ) else (
            echo    ✓ %%~nxf signed
        )
    )
)

REM ===========================================================================
REM Build Inno Setup Installer (if available)
REM ===========================================================================
if %BUILD_INSTALLERS%==1 (
    where iscc >nul 2>&1
    if not errorlevel 1 (
        set /a CURRENT_STEP+=1
        echo.
        echo [!CURRENT_STEP!/%TOTAL_STEPS%] Building Inno Setup installer...
        
        iscc "%INSTALLER_DIR%\inno\jarwis-agent.iss" /DSourceDir="%BUILD_DIR%" /O"%BUILD_DIR%"
        
        if errorlevel 1 (
            echo WARNING: Inno Setup build failed
        ) else (
            echo    ✓ Inno Setup installer created
        )
    ) else (
        echo.
        echo NOTE: Inno Setup not found, skipping EXE installer creation
        echo       Download from: https://jrsoftware.org/isdl.php
    )
)

REM ===========================================================================
REM Summary
REM ===========================================================================
echo.
echo ============================================================
echo   Build Complete!
echo ============================================================
echo.
echo Output directory: %BUILD_DIR%
echo.
echo Built files:
if exist "%BUILD_DIR%\jarwis-agent.exe" (
    for %%A in ("%BUILD_DIR%\jarwis-agent.exe") do echo    ✓ jarwis-agent.exe          (%%~zA bytes^)
)
if exist "%BUILD_DIR%\JarwisAgentSetup-GUI.exe" (
    for %%A in ("%BUILD_DIR%\JarwisAgentSetup-GUI.exe") do echo    ✓ JarwisAgentSetup-GUI.exe  (%%~zA bytes^)
)
if exist "%BUILD_DIR%\jarwis-tray.exe" (
    for %%A in ("%BUILD_DIR%\jarwis-tray.exe") do echo    ✓ jarwis-tray.exe           (%%~zA bytes^)
)
if exist "%BUILD_DIR%\jarwis-config.exe" (
    for %%A in ("%BUILD_DIR%\jarwis-config.exe") do echo    ✓ jarwis-config.exe         (%%~zA bytes^)
)
if exist "%BUILD_DIR%\JarwisAgentSetup-*.exe" (
    echo    ✓ Inno Setup installer
)
echo.

endlocal
exit /b 0
