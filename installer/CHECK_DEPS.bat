@echo off
REM ===========================================================================
REM Jarwis Agent - Runtime Dependency Checker
REM ===========================================================================
REM
REM Checks for runtime dependencies required by Jarwis Agent features.
REM Run this to see what optional tools are available for scanning.
REM
REM ===========================================================================

echo.
echo Checking Jarwis Agent runtime dependencies...
echo.

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..

REM Activate virtual environment if available
if exist "%PROJECT_ROOT%\.venv\Scripts\activate.bat" (
    call "%PROJECT_ROOT%\.venv\Scripts\activate.bat"
)

python "%SCRIPT_DIR%runtime_deps.py" %*

pause
