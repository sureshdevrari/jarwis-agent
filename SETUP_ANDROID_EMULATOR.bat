@echo off
echo ============================================================
echo   JARWIS ANDROID EMULATOR SETUP
echo   Setting up mobile dynamic testing environment...
echo ============================================================
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Run the setup script
python scripts\setup_android_emulator.py

echo.
pause
