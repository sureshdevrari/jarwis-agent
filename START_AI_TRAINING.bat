@echo off
echo ============================================
echo   JARWIS AI AUTONOMOUS TRAINING DAEMON
echo ============================================
echo.
echo This will train the AI from cybersecurity knowledge sources.
echo.
echo FEATURES:
echo  - Network Resilience: Automatically pauses on connection loss
echo  - Checkpoint System: Resumes from exact position on restart
echo  - Auto-Restart: Recovers from crashes automatically
echo  - Auto-Refresh: Re-crawls sources on schedule (24h - 30 days)
echo.
echo OPTIONS:
echo  - Normal start: Just run this script
echo  - Force re-crawl: Run with --force flag or use RESET_AI_TRAINING.bat
echo.
echo Press Ctrl+C TWICE to fully stop.
echo.

cd /d "%~dp0"

REM Activate virtual environment if exists
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

REM Check if --force was passed
set FORCE_FLAG=
if "%1"=="--force" set FORCE_FLAG=--force
if "%1"=="-f" set FORCE_FLAG=--force

REM Show status before starting
echo Checking current status...
python -m jarwis_ai.training.daemon status
echo.

:restart_loop
echo.
echo [%date% %time%] Starting daemon %FORCE_FLAG%...
python -m jarwis_ai.training.daemon run %FORCE_FLAG%

REM Only use force flag on first run
set FORCE_FLAG=

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
echo Daemon stopped gracefully. All progress saved.
pause
