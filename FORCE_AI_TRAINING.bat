@echo off
echo ============================================
echo   FORCE JARWIS AI TRAINING (RE-CRAWL ALL)
echo ============================================
echo.
echo This will FORCE re-crawl ALL sources immediately,
echo ignoring the normal refresh schedule.
echo.
echo Your existing learned data will be preserved and enhanced.
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Show status before starting
echo Current status:
python -m jarwis_ai.training.daemon status
echo.

:restart_loop
echo.
echo [%date% %time%] Starting FORCED training...
python -m jarwis_ai.training.daemon run --force

REM Check exit code
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [%date% %time%] Daemon stopped unexpectedly! Progress saved.
    echo Restarting in 10 seconds to resume from checkpoint...
    echo Press Ctrl+C now to stop completely.
    timeout /t 10 /nobreak
    goto restart_loop
)

echo.
echo Training stopped. All progress saved.
pause
