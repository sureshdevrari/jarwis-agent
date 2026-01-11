@echo off
title JARWIS Backend Server (Auto-restart)
setlocal enabledelayedexpansion
echo.
echo ========================================
echo   JARWIS Backend API Server
echo   Auto-restart enabled
echo ========================================
echo.

cd /d D:\jarwis-ai-pentest

REM Kill any existing processes on port 8000
echo [1/3] Cleaning up port 8000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8000 ^| findstr LISTENING 2^>nul') do (
    taskkill /F /PID %%a 2>nul
)
timeout /t 2 /nobreak >nul

REM Activate virtual environment
echo [2/3] Activating Python environment...
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
) else (
    echo ERROR: No virtual environment found!
    pause
    exit /b 1
)

REM Auto-restart loop
echo [3/3] Starting FastAPI server on port 8000...
echo.

set RESTART_COUNT=0
set MAX_RESTARTS=50

:restart_loop
set /a RESTART_COUNT+=1
echo [%TIME%] Starting uvicorn (attempt %RESTART_COUNT%/%MAX_RESTARTS%)...

python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload --reload-delay 1

set EXIT_CODE=%ERRORLEVEL%
echo.
echo [%TIME%] Server stopped with exit code: %EXIT_CODE%

if %EXIT_CODE% EQU 0 (
    echo Server stopped cleanly. Press any key to exit...
    pause >nul
    exit /b 0
)

if %RESTART_COUNT% GEQ %MAX_RESTARTS% (
    echo Max restarts reached. Press any key to exit...
    pause >nul
    exit /b 1
)

echo Waiting 5 seconds before restart...
timeout /t 5 /nobreak >nul
goto restart_loop

