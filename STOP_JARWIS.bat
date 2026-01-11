@echo off
echo Stopping all Jarwis services...

:: Kill Python processes (backend)
taskkill /IM python.exe /F 2>nul

:: Kill Node processes (frontend)
taskkill /IM node.exe /F 2>nul

timeout /t 2 /nobreak > nul

echo.
echo All services stopped.
pause
