@echo off
echo ============================================================
echo   JARWIS - STOP ALL SERVICES
echo ============================================================
echo.

echo Stopping Frontend (Node.js)...
taskkill /F /IM node.exe 2>nul
if %errorlevel%==0 (echo   [OK] Frontend stopped) else (echo   [--] Frontend not running)

echo Stopping Backend (Python)...
taskkill /F /IM python.exe 2>nul
if %errorlevel%==0 (echo   [OK] Backend stopped) else (echo   [--] Backend not running)

echo Stopping Android Emulator...
taskkill /F /IM qemu-system-x86_64.exe 2>nul
taskkill /F /IM emulator.exe 2>nul
if %errorlevel%==0 (echo   [OK] Emulator stopped) else (echo   [--] Emulator not running)

echo.
echo ============================================================
echo   All services stopped!
echo ============================================================
echo.
pause
