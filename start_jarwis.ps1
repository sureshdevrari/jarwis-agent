# Jarwis Development Environment Launcher
# Starts backend and frontend in separate terminals with auto-restart capability

param(
    [switch]$BackendOnly,
    [switch]$FrontendOnly
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JARWIS Development Launcher" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Configuration
$PROJECT_ROOT = "D:\jarwis-ai-pentest"
$BACKEND_PORT = 8000
$FRONTEND_PORT = 3000

# Function to kill processes on a specific port
function Stop-PortProcess {
    param([int]$Port)
    $pids = netstat -ano | Select-String ":$Port.*LISTEN" | ForEach-Object {
        $parts = $_ -split '\s+'
        if ($parts[-1] -match '^\d+$') { $parts[-1] }
    }
    foreach ($pid in $pids | Get-Unique) {
        try {
            Stop-Process -Id $pid -Force -ErrorAction Stop
            Write-Host "  Stopped process $pid on port $Port" -ForegroundColor Gray
        } catch {}
    }
}

# Step 1: Cleanup existing processes
Write-Host "[1/3] Cleaning up existing processes..." -ForegroundColor Yellow
if (-not $FrontendOnly) { Stop-PortProcess -Port $BACKEND_PORT }
if (-not $BackendOnly) { Stop-PortProcess -Port $FRONTEND_PORT }
Start-Sleep -Seconds 2
Write-Host "  Done!" -ForegroundColor Green

# Step 2: Start Backend in new terminal
if (-not $FrontendOnly) {
    Write-Host "[2/3] Starting Backend API (port $BACKEND_PORT)..." -ForegroundColor Yellow
    
    $backendScript = @"
`$host.UI.RawUI.WindowTitle = 'JARWIS Backend - Port $BACKEND_PORT'
`$ErrorActionPreference = 'Continue'

Set-Location '$PROJECT_ROOT'

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  JARWIS Backend Server' -ForegroundColor Cyan
Write-Host '  Auto-restart enabled' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

# Activate venv
if (Test-Path '.\.venv\Scripts\Activate.ps1') {
    & '.\.venv\Scripts\Activate.ps1'
} elseif (Test-Path '.\venv\Scripts\Activate.ps1') {
    & '.\venv\Scripts\Activate.ps1'
}

`$restartCount = 0
`$maxRestarts = 10
`$restartDelay = 3

while (`$restartCount -lt `$maxRestarts) {
    `$startTime = Get-Date
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting uvicorn server..." -ForegroundColor Green
    
    try {
        python -m uvicorn api.server:app --host 0.0.0.0 --port $BACKEND_PORT --reload --reload-delay 1
    } catch {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server crashed: `$_" -ForegroundColor Red
    }
    
    `$runTime = (Get-Date) - `$startTime
    
    if (`$runTime.TotalSeconds -lt 5) {
        # Crashed too quickly - likely a code error
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server crashed within 5s - waiting 10s before restart..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
    } else {
        # Reset counter if it ran for a reasonable time
        if (`$runTime.TotalMinutes -gt 1) { `$restartCount = 0 }
    }
    
    `$restartCount++
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Auto-restarting... (attempt `$restartCount/`$maxRestarts)" -ForegroundColor Yellow
    Start-Sleep -Seconds `$restartDelay
}

Write-Host 'Max restarts reached. Press any key to exit...' -ForegroundColor Red
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@

    Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendScript
    Write-Host "  Backend terminal opened!" -ForegroundColor Green
}

# Step 3: Start Frontend in new terminal
if (-not $BackendOnly) {
    # Wait a bit for backend to initialize first
    if (-not $FrontendOnly) {
        Write-Host "  Waiting for backend to initialize..." -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }
    
    Write-Host "[3/3] Starting Frontend (port $FRONTEND_PORT)..." -ForegroundColor Yellow
    
    $frontendScript = @"
`$host.UI.RawUI.WindowTitle = 'JARWIS Frontend - Port $FRONTEND_PORT'
`$ErrorActionPreference = 'Continue'

Set-Location '$PROJECT_ROOT\jarwisfrontend'

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  JARWIS Frontend Server' -ForegroundColor Cyan
Write-Host '  Auto-restart enabled' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

`$env:PORT = '$FRONTEND_PORT'
`$env:BROWSER = 'none'

`$restartCount = 0
`$maxRestarts = 10
`$restartDelay = 5

while (`$restartCount -lt `$maxRestarts) {
    `$startTime = Get-Date
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting React dev server..." -ForegroundColor Green
    
    try {
        npm start
    } catch {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server crashed: `$_" -ForegroundColor Red
    }
    
    `$runTime = (Get-Date) - `$startTime
    
    if (`$runTime.TotalSeconds -lt 10) {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server crashed quickly - checking for issues..." -ForegroundColor Yellow
        
        # Check if node_modules exists
        if (-not (Test-Path 'node_modules')) {
            Write-Host "  node_modules missing - running npm install..." -ForegroundColor Yellow
            npm install
        }
        
        Start-Sleep -Seconds 10
    } else {
        if (`$runTime.TotalMinutes -gt 2) { `$restartCount = 0 }
    }
    
    `$restartCount++
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Auto-restarting... (attempt `$restartCount/`$maxRestarts)" -ForegroundColor Yellow
    Start-Sleep -Seconds `$restartDelay
}

Write-Host 'Max restarts reached. Press any key to exit...' -ForegroundColor Red
`$null = `$Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
"@

    Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendScript
    Write-Host "  Frontend terminal opened!" -ForegroundColor Green
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JARWIS Services Launched!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n  Backend API:  http://localhost:$BACKEND_PORT" -ForegroundColor White
Write-Host "  Frontend:     http://localhost:$FRONTEND_PORT" -ForegroundColor White
Write-Host "`n  Both services have AUTO-RESTART enabled" -ForegroundColor Green
Write-Host "  Close the terminal windows to stop services" -ForegroundColor Gray
Write-Host "`n"
