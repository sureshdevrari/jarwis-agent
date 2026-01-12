@echo off
echo ============================================
echo   STOPPING JARWIS AI TRAINING DAEMON
echo ============================================
echo.
echo Progress will be saved and can be resumed later.
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Stop the daemon
python -m jarwis_ai.training.daemon stop

echo.
echo Training stopped. Run START_AI_TRAINING.bat to resume from checkpoint.
echo.
pause
