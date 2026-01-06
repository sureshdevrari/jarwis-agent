@echo off
title JARWIS Frontend Server (Auto-restart)
setlocal enabledelayedexpansion
echo.
echo ========================================
echo   JARWIS Frontend React Server
echo   Auto-restart enabled
echo ========================================
echo.

cd /d D:\jarwis-ai-pentest\jarwisfrontend

REM Kill any existing processes on port 3000
echo [1/3] Cleaning up port 3000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :3000 ^| findstr LISTENING 2^>nul') do (
    taskkill /F /PID %%a 2>nul
)
timeout /t 2 /nobreak >nul

REM Check node_modules
echo [2/3] Checking dependencies...
if not exist "node_modules" (
    echo Installing dependencies...
    npm install
)

REM Auto-restart loop
echo [3/3] Starting React dev server on port 3000...
echo.
set PORT=3000
set BROWSER=none

set RESTART_COUNT=0
set MAX_RESTARTS=50

:restart_loop
set /a RESTART_COUNT+=1
echo [%TIME%] Starting React server (attempt %RESTART_COUNT%/%MAX_RESTARTS%)...

npm start

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

REM Quick crash - might need npm install
echo Checking dependencies and restarting in 10 seconds...
npm install 2>nul
timeout /t 10 /nobreak >nul
goto restart_loop

