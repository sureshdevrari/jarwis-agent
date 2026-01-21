@echo off
REM ===========================================================================
REM Jarwis Agent - Master Build Script for Windows
REM ===========================================================================
REM
REM This script handles the complete build process including:
REM   1. Pre-flight validation
REM   2. PyInstaller executable build
REM   3. Inno Setup EXE installer (if available)
REM   4. WiX MSI installer (if available)
REM
REM Usage:
REM   BUILD_INSTALLER.bat                 - Build all (EXE + MSI)
REM   BUILD_INSTALLER.bat --exe           - Build Inno Setup EXE only
REM   BUILD_INSTALLER.bat --msi           - Build WiX MSI only
REM   BUILD_INSTALLER.bat --sign          - Build and sign all
REM   BUILD_INSTALLER.bat --skip-preflight - Skip pre-flight checks
REM
REM ===========================================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   Jarwis Agent - Windows Installer Build
echo ============================================================
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
set BUILD_EXE=1
set BUILD_MSI=1
set SIGN_BUILD=0
set SKIP_PREFLIGHT=0

REM Parse arguments
:parse_args
if "%1"=="" goto :done_args
if "%1"=="--exe" (
    set BUILD_MSI=0
    shift
    goto :parse_args
)
if "%1"=="--msi" (
    set BUILD_EXE=0
    shift
    goto :parse_args
)
if "%1"=="--sign" (
    set SIGN_BUILD=1
    shift
    goto :parse_args
)
if "%1"=="--skip-preflight" (
    set SKIP_PREFLIGHT=1
    shift
    goto :parse_args
)
shift
goto :parse_args
:done_args

REM Activate virtual environment
if exist "%PROJECT_ROOT%\.venv\Scripts\activate.bat" (
    call "%PROJECT_ROOT%\.venv\Scripts\activate.bat"
) else (
    echo WARNING: Virtual environment not found at %PROJECT_ROOT%\.venv
    echo Using system Python...
)

REM Step 1: Pre-flight check
if %SKIP_PREFLIGHT%==0 (
    echo [1/4] Running pre-flight validation...
    python "%SCRIPT_DIR%preflight_check.py" --platform windows
    if errorlevel 2 (
        echo.
        echo Pre-flight completed with warnings. Continue anyway? [Y/N]
        set /p CONTINUE_BUILD=
        if /i not "!CONTINUE_BUILD!"=="Y" (
            echo Build cancelled.
            exit /b 1
        )
    )
    if errorlevel 1 (
        echo.
        echo ERROR: Pre-flight validation failed. Fix errors before building.
        exit /b 1
    )
) else (
    echo [1/4] Skipping pre-flight validation...
)

REM Step 2: Build executable with PyInstaller
echo.
echo [2/4] Building executable with PyInstaller...
cd /d "%PROJECT_ROOT%"

python -m PyInstaller "%SCRIPT_DIR%jarwis-agent.spec" ^
    --distpath "%PROJECT_ROOT%\dist\jarwis-agent" ^
    --workpath "%PROJECT_ROOT%\dist\build" ^
    --clean ^
    --noconfirm

if errorlevel 1 (
    echo ERROR: PyInstaller build failed
    exit /b 1
)

REM Copy config and license
echo Copying configuration files...
if not exist "%PROJECT_ROOT%\dist\jarwis-agent\config" mkdir "%PROJECT_ROOT%\dist\jarwis-agent\config"
copy "%PROJECT_ROOT%\config\config.yaml" "%PROJECT_ROOT%\dist\jarwis-agent\config\" >nul
copy "%SCRIPT_DIR%LICENSE.rtf" "%PROJECT_ROOT%\dist\jarwis-agent\LICENSE.txt" >nul

echo PyInstaller build complete: dist\jarwis-agent\jarwis-agent.exe

REM Step 3: Build Inno Setup EXE
if %BUILD_EXE%==1 (
    echo.
    echo [3/4] Building Inno Setup EXE installer...
    
    REM Find Inno Setup compiler
    set ISCC_PATH=
    where iscc >nul 2>&1 && set ISCC_PATH=iscc
    if not defined ISCC_PATH (
        if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set ISCC_PATH="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
    )
    if not defined ISCC_PATH (
        if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set ISCC_PATH="C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    
    if defined ISCC_PATH (
        cd /d "%SCRIPT_DIR%inno"
        
        if %SIGN_BUILD%==1 (
            !ISCC_PATH! /DSignBuild=1 jarwis-agent.iss
        ) else (
            !ISCC_PATH! jarwis-agent.iss
        )
        
        if errorlevel 1 (
            echo WARNING: Inno Setup build failed
        ) else (
            echo Inno Setup build complete: dist\inno\jarwis-agent-*-setup.exe
        )
    ) else (
        echo WARNING: Inno Setup not found, skipping EXE installer build
        echo Download from: https://jrsoftware.org/isinfo.php
    )
) else (
    echo [3/4] Skipping Inno Setup EXE build...
)

REM Step 4: Build WiX MSI
if %BUILD_MSI%==1 (
    echo.
    echo [4/4] Building WiX MSI installer...
    
    where candle >nul 2>&1
    if errorlevel 1 (
        echo WARNING: WiX Toolset not found, skipping MSI build
        echo Download from: https://wixtoolset.org
    ) else (
        cd /d "%SCRIPT_DIR%windows"
        call build.bat
        if errorlevel 1 (
            echo WARNING: WiX MSI build failed
        ) else (
            echo WiX MSI build complete: dist\windows\x64\jarwis-agent_x64.msi
        )
    )
) else (
    echo [4/4] Skipping WiX MSI build...
)

REM Summary
echo.
echo ============================================================
echo   Build Complete!
echo ============================================================
echo.
echo Output files:
if exist "%PROJECT_ROOT%\dist\jarwis-agent\jarwis-agent.exe" (
    echo   Executable: dist\jarwis-agent\jarwis-agent.exe
)
if exist "%PROJECT_ROOT%\dist\inno\jarwis-agent-*-setup.exe" (
    echo   EXE Installer: dist\inno\jarwis-agent-*-setup.exe
)
if exist "%PROJECT_ROOT%\dist\windows\x64\jarwis-agent_x64.msi" (
    echo   MSI Installer: dist\windows\x64\jarwis-agent_x64.msi
)
echo.

endlocal
exit /b 0
