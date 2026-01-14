@echo off
echo ============================================================
echo   JARWIS - START ALL SERVICES
echo   Starting all components for mobile security testing
echo ============================================================
echo.

cd /d "%~dp0"

REM Run PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\start_all_services.ps1"

pause
