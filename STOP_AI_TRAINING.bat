@echo off
echo ============================================
echo   STOPPING JARWIS AI TRAINING DAEMON
echo ============================================
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Stop the daemon
python jarwis_ai\training\daemon.py stop

pause
