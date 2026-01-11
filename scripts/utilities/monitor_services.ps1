# Jarwis Service Health Monitor
# Runs in background and monitors both services, restarting if necessary

param(
    [int]$CheckIntervalSeconds = 30,
    [int]$BackendPort = 8000,
    [int]$FrontendPort = 3000
)

$ErrorActionPreference = "SilentlyContinue"
$PROJECT_ROOT = "D:\jarwis-ai-pentest"

$host.UI.RawUI.WindowTitle = "JARWIS Health Monitor"

Write-Host "`n========================================" -ForegroundColor Magenta
Write-Host "  JARWIS Service Health Monitor" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  Checking every $CheckIntervalSeconds seconds" -ForegroundColor Gray
Write-Host "  Press Ctrl+C to stop monitoring`n" -ForegroundColor Gray

function Test-ServiceHealth {
    param(
        [string]$Name,
        [string]$Url,
        [int]$TimeoutSeconds = 5
    )
    
    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSeconds -UseBasicParsing
        return $response.StatusCode -eq 200
    } catch {
        return $false
    }
}

function Restart-BackendService {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Restarting Backend..." -ForegroundColor Yellow
    
    # Kill existing backend
    $pids = netstat -ano | Select-String ":$BackendPort.*LISTEN" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Get-Unique
    
    foreach ($pid in $pids) {
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    
    Start-Sleep -Seconds 2
    
    # Start new backend in new terminal
    $script = @"
Set-Location '$PROJECT_ROOT'
if (Test-Path '.\.venv\Scripts\Activate.ps1') { & '.\.venv\Scripts\Activate.ps1' }
elseif (Test-Path '.\venv\Scripts\Activate.ps1') { & '.\venv\Scripts\Activate.ps1' }
python -m uvicorn api.server:app --host 0.0.0.0 --port $BackendPort --reload
"@
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $script
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Backend restart initiated" -ForegroundColor Green
}

function Restart-FrontendService {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Restarting Frontend..." -ForegroundColor Yellow
    
    # Kill existing frontend
    $pids = netstat -ano | Select-String ":$FrontendPort.*LISTEN" | ForEach-Object {
        ($_ -split '\s+')[-1]
    } | Get-Unique
    
    foreach ($pid in $pids) {
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
    
    Start-Sleep -Seconds 2
    
    # Start new frontend in new terminal
    $script = @"
Set-Location '$PROJECT_ROOT\jarwisfrontend'
`$env:PORT = '$FrontendPort'
`$env:BROWSER = 'none'
npm start
"@
    Start-Process powershell -ArgumentList "-NoExit", "-Command", $script
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Frontend restart initiated" -ForegroundColor Green
}

$backendDownCount = 0
$frontendDownCount = 0
$failThreshold = 2  # Restart after 2 consecutive failures

while ($true) {
    $timestamp = Get-Date -Format 'HH:mm:ss'
    
    # Check Backend
    $backendHealthy = Test-ServiceHealth -Name "Backend" -Url "http://localhost:$BackendPort/api/health"
    
    if ($backendHealthy) {
        Write-Host "[$timestamp] Backend: " -NoNewline
        Write-Host "OK" -ForegroundColor Green -NoNewline
        $backendDownCount = 0
    } else {
        Write-Host "[$timestamp] Backend: " -NoNewline
        Write-Host "DOWN" -ForegroundColor Red -NoNewline
        $backendDownCount++
        
        if ($backendDownCount -ge $failThreshold) {
            Restart-BackendService
            $backendDownCount = 0
            Start-Sleep -Seconds 10  # Wait for service to come up
        }
    }
    
    Write-Host " | " -NoNewline
    
    # Check Frontend
    $frontendHealthy = Test-ServiceHealth -Name "Frontend" -Url "http://localhost:$FrontendPort"
    
    if ($frontendHealthy) {
        Write-Host "Frontend: " -NoNewline
        Write-Host "OK" -ForegroundColor Green
        $frontendDownCount = 0
    } else {
        Write-Host "Frontend: " -NoNewline
        Write-Host "DOWN" -ForegroundColor Red
        $frontendDownCount++
        
        if ($frontendDownCount -ge $failThreshold) {
            Restart-FrontendService
            $frontendDownCount = 0
            Start-Sleep -Seconds 15  # Frontend takes longer to start
        }
    }
    
    Start-Sleep -Seconds $CheckIntervalSeconds
}
