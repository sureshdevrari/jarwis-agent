@echo off
echo ============================================
echo   RESET JARWIS AI TRAINING
echo ============================================
echo.
echo This will reset all crawl timers and force re-crawl all sources.
echo Your learned data (knowledge base) will be PRESERVED.
echo Only the crawl schedule will be reset.
echo.
echo Press any key to continue or Ctrl+C to cancel...
pause > nul

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Stop daemon if running
echo.
echo Stopping daemon if running...
python -m jarwis_ai.training.daemon stop 2>nul

REM Reset crawl times
echo.
echo Resetting crawl timers...
python -m jarwis_ai.training.daemon reset

echo.
echo Done! Run START_AI_TRAINING.bat to begin fresh crawl.
echo.
pause
