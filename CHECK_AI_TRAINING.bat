@echo off
echo ============================================
echo   JARWIS AI TRAINING STATUS
echo ============================================
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Check status
python jarwis_ai\training\daemon.py status

echo.
pause
