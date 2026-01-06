# Jarwis Development Startup Script
# This script starts both backend and frontend with auto-restart and monitoring

param(
    [switch]$NoMonitor,  # Skip starting the health monitor
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"
if ($Verbose) { $VerbosePreference = "Continue" }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JARWIS Development Environment" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Configuration
$BACKEND_PORT = 8000
$FRONTEND_PORT = 3000
$PROJECT_ROOT = "D:\jarwis-ai-pentest"

# Step 1: Kill any existing processes on our ports
Write-Host "[1/5] Cleaning up existing processes..." -ForegroundColor Yellow

function Stop-PortProcess {
    param([int]$Port)
    $pids = netstat -ano 2>$null | Select-String ":$Port\s+.*LISTEN" | ForEach-Object {
        $parts = $_ -split '\s+'
        $parts[-1]
    } | Where-Object { $_ -match '^\d+$' } | Get-Unique
    
    foreach ($pid in $pids) {
        try {
            $proc = Get-Process -Id $pid -ErrorAction Stop
            Stop-Process -Id $pid -Force
            Write-Host "  Killed $($proc.ProcessName) (PID: $pid) on port $Port" -ForegroundColor Gray
        } catch {}
    }
}

Stop-PortProcess -Port $BACKEND_PORT
Stop-PortProcess -Port $FRONTEND_PORT

# Kill any orphaned job processes from previous runs
Get-Job -State Running -ErrorAction SilentlyContinue | Stop-Job -PassThru | Remove-Job -Force

Start-Sleep -Seconds 2
Write-Host "  Done!" -ForegroundColor Green

# Step 2: Check virtual environment
Write-Host "[2/5] Checking Python virtual environment..." -ForegroundColor Yellow
Set-Location $PROJECT_ROOT

$venvPath = $null
if (Test-Path "$PROJECT_ROOT\.venv\Scripts\Activate.ps1") {
    $venvPath = "$PROJECT_ROOT\.venv"
} elseif (Test-Path "$PROJECT_ROOT\venv\Scripts\Activate.ps1") {
    $venvPath = "$PROJECT_ROOT\venv"
}

if ($venvPath) {
    & "$venvPath\Scripts\Activate.ps1"
    Write-Host "  Activated: $venvPath" -ForegroundColor Green
} else {
    Write-Host "  WARNING: No virtual environment found!" -ForegroundColor Red
    Write-Host "  Run: python -m venv .venv" -ForegroundColor Yellow
}

# Step 3: Start Backend Server in separate process
Write-Host "[3/5] Starting Backend API on port $BACKEND_PORT..." -ForegroundColor Yellow

$backendScript = @"
`$host.UI.RawUI.WindowTitle = 'JARWIS Backend API (Port $BACKEND_PORT)'
`$ErrorActionPreference = 'Continue'
Set-Location '$PROJECT_ROOT'

# Activate venv
if (Test-Path '.\.venv\Scripts\Activate.ps1') { & '.\.venv\Scripts\Activate.ps1' }
elseif (Test-Path '.\venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  JARWIS Backend Server' -ForegroundColor Cyan
Write-Host '  Port: $BACKEND_PORT | Auto-restart: ON' -ForegroundColor Gray
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

`$restartCount = 0
`$maxRestarts = 50

while (`$restartCount -lt `$maxRestarts) {
    `$startTime = Get-Date
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting uvicorn..." -ForegroundColor Green
    
    python -m uvicorn api.server:app --host 0.0.0.0 --port $BACKEND_PORT --reload --reload-delay 1 2>&1
    `$exitCode = `$LASTEXITCODE
    
    `$runTime = (Get-Date) - `$startTime
    
    # Check why it stopped
    if (`$exitCode -eq 0) {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server stopped cleanly" -ForegroundColor Gray
        break
    }
    
    if (`$runTime.TotalSeconds -lt 5) {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Crashed quickly (exit: `$exitCode) - waiting 10s..." -ForegroundColor Red
        Start-Sleep -Seconds 10
    } else {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server stopped (exit: `$exitCode)" -ForegroundColor Yellow
        if (`$runTime.TotalMinutes -gt 1) { `$restartCount = 0 }
    }
    
    `$restartCount++
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Restarting... (`$restartCount/`$maxRestarts)" -ForegroundColor Yellow
    Start-Sleep -Seconds 3
}

Write-Host "`nMax restarts reached or clean exit. Press Enter to close..." -ForegroundColor Red
Read-Host
"@

$backendProc = Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendScript -PassThru
Write-Host "  Backend started (PID: $($backendProc.Id))" -ForegroundColor Green

# Step 4: Wait for backend and verify health
Write-Host "[4/5] Waiting for Backend to be ready..." -ForegroundColor Yellow
$maxRetries = 15
$retryCount = 0
$backendHealthy = $false

while ($retryCount -lt $maxRetries -and -not $backendHealthy) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:$BACKEND_PORT/api/health" -TimeoutSec 3 -ErrorAction Stop
        if ($response.status -eq "ok") {
            $backendHealthy = $true
            Write-Host "  Backend is healthy!" -ForegroundColor Green
        }
    } catch {
        $retryCount++
        Write-Host "  Waiting... ($retryCount/$maxRetries)" -ForegroundColor Gray
        Start-Sleep -Seconds 2
    }
}

if (-not $backendHealthy) {
    Write-Host "  Backend may still be starting. Continuing anyway..." -ForegroundColor Yellow
}

# Step 5: Start Frontend in separate process
Write-Host "[5/5] Starting Frontend on port $FRONTEND_PORT..." -ForegroundColor Yellow

$frontendScript = @"
`$host.UI.RawUI.WindowTitle = 'JARWIS Frontend (Port $FRONTEND_PORT)'
`$ErrorActionPreference = 'Continue'
Set-Location '$PROJECT_ROOT\jarwisfrontend'

`$env:PORT = '$FRONTEND_PORT'
`$env:BROWSER = 'none'

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '  JARWIS Frontend Server' -ForegroundColor Cyan
Write-Host '  Port: $FRONTEND_PORT | Auto-restart: ON' -ForegroundColor Gray
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ''

# Check node_modules
if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing dependencies...' -ForegroundColor Yellow
    npm install
}

`$restartCount = 0
`$maxRestarts = 50

while (`$restartCount -lt `$maxRestarts) {
    `$startTime = Get-Date
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Starting React dev server..." -ForegroundColor Green
    
    npm start 2>&1
    `$exitCode = `$LASTEXITCODE
    
    `$runTime = (Get-Date) - `$startTime
    
    if (`$exitCode -eq 0) {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Server stopped cleanly" -ForegroundColor Gray
        break
    }
    
    if (`$runTime.TotalSeconds -lt 10) {
        Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Crashed quickly - checking dependencies..." -ForegroundColor Red
        npm install
        Start-Sleep -Seconds 10
    } else {
        if (`$runTime.TotalMinutes -gt 2) { `$restartCount = 0 }
    }
    
    `$restartCount++
    Write-Host "[`$(Get-Date -Format 'HH:mm:ss')] Restarting... (`$restartCount/`$maxRestarts)" -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}

Write-Host "`nMax restarts reached or clean exit. Press Enter to close..." -ForegroundColor Red
Read-Host
"@

$frontendProc = Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendScript -PassThru
Write-Host "  Frontend started (PID: $($frontendProc.Id))" -ForegroundColor Green

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JARWIS Development Environment Ready" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "`n  Backend API:  http://localhost:$BACKEND_PORT" -ForegroundColor White
Write-Host "  Frontend:     http://localhost:$FRONTEND_PORT" -ForegroundColor White
Write-Host "`n  Features:" -ForegroundColor Gray
Write-Host "    - Auto-restart on crash (up to 50 times)" -ForegroundColor Green
Write-Host "    - Separate terminal windows for visibility" -ForegroundColor Green
Write-Host "    - Visual status in title bar" -ForegroundColor Green
Write-Host "`n  To stop: Close the terminal windows" -ForegroundColor Gray

# Optional: Start health monitor
if (-not $NoMonitor) {
    Write-Host "`n  Starting health monitor in background..." -ForegroundColor Yellow
    $monitorScript = "$PROJECT_ROOT\monitor_services.ps1"
    if (Test-Path $monitorScript) {
        Start-Process powershell -ArgumentList "-NoExit", "-File", $monitorScript, "-CheckIntervalSeconds", "60"
        Write-Host "  Health monitor active (checks every 60s)" -ForegroundColor Green
    }
}

Write-Host "`n"

