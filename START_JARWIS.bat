@echo off
echo ========================================
echo   Starting Jarwis Services
echo ========================================
echo.
echo Starting Backend (port 8000)...
start "Jarwis Backend" powershell -NoExit -Command "cd D:\jarwis-ai-pentest; .\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 5 /nobreak > nul

echo Starting Frontend (port 3000)...
start "Jarwis Frontend" powershell -NoExit -Command "cd D:\jarwis-ai-pentest\jarwisfrontend; $env:BROWSER='none'; npm start"

echo.
echo ========================================
echo   Services starting in separate windows
echo ========================================
echo.
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:3000
echo.
echo   Login:    http://localhost:3000/login
echo   Email:    user2@jarwis.ai
echo   Password: 12341234
echo.
echo ========================================
pause
