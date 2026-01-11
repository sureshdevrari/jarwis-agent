@echo off
echo ============================================
echo   JARWIS AI AUTONOMOUS TRAINING DAEMON
echo ============================================
echo.
echo Starting AI training daemon...
echo This will run continuously in the background.
echo.
echo AUTO-RESTART ENABLED: If daemon crashes, it will restart automatically.
echo Press Ctrl+C TWICE to fully stop.
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

:restart_loop
echo.
echo [%date% %time%] Starting daemon...
python jarwis_ai\training\daemon.py run

REM Check exit code
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [%date% %time%] Daemon stopped unexpectedly! Restarting in 10 seconds...
    echo Press Ctrl+C now to stop completely.
    timeout /t 10 /nobreak
    goto restart_loop
)

echo.
echo Daemon stopped gracefully.
pause
