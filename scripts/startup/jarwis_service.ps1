# Jarwis Service Manager
# Properly starts/stops/restarts backend and frontend services
# Fixes the "stale process" issue by aggressively cleaning up before starting

param(
    [Parameter(Position=0)]
    [ValidateSet('start', 'stop', 'restart', 'status')]
    [string]$Action = 'start',
    
    [switch]$BackendOnly,
    [switch]$FrontendOnly,
    [switch]$DevMode  # Enable --reload for development (causes restarts on file changes)
)

$ErrorActionPreference = "SilentlyContinue"
$PROJECT_ROOT = "D:\jarwis-ai-pentest"
$BACKEND_PORT = 8000
$FRONTEND_PORT = 3000

# PID file locations to track our processes
$PID_DIR = "$PROJECT_ROOT\data\temp"
$BACKEND_PID_FILE = "$PID_DIR\backend.pid"
$FRONTEND_PID_FILE = "$PID_DIR\frontend.pid"

# Ensure PID directory exists
if (-not (Test-Path $PID_DIR)) {
    New-Item -ItemType Directory -Path $PID_DIR -Force | Out-Null
}

function Write-Status {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-PortProcess {
    param([int]$Port)
    $result = netstat -ano | Select-String ":$Port\s.*LISTEN"
    if ($result) {
        $pids = @()
        foreach ($line in $result) {
            $parts = ($line -split '\s+')
            $pid = $parts[-1]
            if ($pid -match '^\d+$' -and $pid -ne "0") {
                $pids += [int]$pid
            }
        }
        return $pids | Get-Unique
    }
    return @()
}

function Stop-ServiceOnPort {
    param([int]$Port, [string]$ServiceName)
    
    $pids = Get-PortProcess -Port $Port
    if ($pids.Count -gt 0) {
        foreach ($pid in $pids) {
            try {
                $proc = Get-Process -Id $pid -ErrorAction Stop
                Write-Status "  Stopping $ServiceName (PID: $pid, Process: $($proc.ProcessName))..." "Yellow"
                Stop-Process -Id $pid -Force -ErrorAction Stop
            } catch {
                # Try taskkill as fallback
                taskkill /PID $pid /F 2>$null | Out-Null
            }
        }
        Start-Sleep -Seconds 2
        
        # Verify stopped
        $remaining = Get-PortProcess -Port $Port
        if ($remaining.Count -gt 0) {
            Write-Status "  Force killing remaining processes on port $Port..." "Red"
            foreach ($pid in $remaining) {
                taskkill /PID $pid /F /T 2>$null | Out-Null
            }
            Start-Sleep -Seconds 1
        }
    }
}

function Stop-AllServices {
    Write-Status "`n[STOPPING SERVICES]" "Cyan"
    
    # Kill by PID files first (our tracked processes)
    if (Test-Path $BACKEND_PID_FILE) {
        $pid = Get-Content $BACKEND_PID_FILE -ErrorAction SilentlyContinue
        if ($pid) {
            try { Stop-Process -Id $pid -Force -ErrorAction Stop } catch {}
        }
        Remove-Item $BACKEND_PID_FILE -Force -ErrorAction SilentlyContinue
    }
    
    if (Test-Path $FRONTEND_PID_FILE) {
        $pid = Get-Content $FRONTEND_PID_FILE -ErrorAction SilentlyContinue
        if ($pid) {
            try { Stop-Process -Id $pid -Force -ErrorAction Stop } catch {}
        }
        Remove-Item $FRONTEND_PID_FILE -Force -ErrorAction SilentlyContinue
    }
    
    # Kill all processes on ports (catches orphaned processes)
    Stop-ServiceOnPort -Port $BACKEND_PORT -ServiceName "Backend"
    Stop-ServiceOnPort -Port $FRONTEND_PORT -ServiceName "Frontend"
    
    # Kill WSL Python/uvicorn processes for jarwis
    Write-Status "  Stopping WSL backend processes..." "Yellow"
    wsl -d Ubuntu -e bash -c "pkill -f 'uvicorn api.server:app' 2>/dev/null || true" 2>$null
    wsl -d Ubuntu -e bash -c "pkill -f 'python.*jarwis' 2>/dev/null || true" 2>$null
    
    # Kill any remaining Windows python/node processes from jarwis (aggressive cleanup)
    Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*jarwis*" -or $_.CommandLine -like "*jarwis*" -or $_.CommandLine -like "*uvicorn*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -like "*jarwis*"
    } | Stop-Process -Force -ErrorAction SilentlyContinue
    
    Start-Sleep -Seconds 2
    Write-Status "  Services stopped" "Green"
}

function Start-Backend {
    Write-Status "`n[STARTING BACKEND (WSL)]" "Cyan"
    
    # Check if already running
    $existing = Get-PortProcess -Port $BACKEND_PORT
    if ($existing.Count -gt 0) {
        Write-Status "  Backend already running on port $BACKEND_PORT (PID: $($existing -join ', '))" "Yellow"
        return
    }
    
    # Build uvicorn command - only use --reload in dev mode (causes restarts on file changes)
    $reloadFlag = ""
    if ($DevMode) {
        $reloadFlag = " --reload"
        Write-Status "  [DEV MODE] Auto-reload enabled - server will restart on file changes" "Yellow"
    }
    
    # Start backend in WSL Ubuntu with nohup for proper backgrounding
    # Logs go to logs/backend_wsl.log for debugging
    $logFile = "/mnt/d/jarwis-ai-pentest/logs/backend_wsl.log"
    $wslCmd = "wsl -d Ubuntu -e bash -c 'cd /mnt/d/jarwis-ai-pentest && source .venv-wsl/bin/activate && nohup python -m uvicorn api.server:app --host 0.0.0.0 --port $BACKEND_PORT$reloadFlag > $logFile 2>&1 & echo `$! && sleep 1'"
    $process = Start-Process powershell -ArgumentList "-Command", $wslCmd -WindowStyle Hidden -PassThru
    
    # Save PID
    $process.Id | Out-File -FilePath $BACKEND_PID_FILE -Force
    
    # Wait for startup
    Write-Status "  Waiting for backend to start..." "Gray"
    $maxWait = 20
    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$BACKEND_PORT/api/health" -UseBasicParsing -TimeoutSec 2
            Write-Status "  Backend started successfully (http://localhost:$BACKEND_PORT)" "Green"
            return
        } catch {}
    }
    Write-Status "  Backend may still be starting..." "Yellow"
}

function Start-Frontend {
    Write-Status "`n[STARTING FRONTEND]" "Cyan"
    
    # Check if already running
    $existing = Get-PortProcess -Port $FRONTEND_PORT
    if ($existing.Count -gt 0) {
        Write-Status "  Frontend already running on port $FRONTEND_PORT (PID: $($existing -join ', '))" "Yellow"
        return
    }
    
    # Start in new window
    $frontendCmd = "cd $PROJECT_ROOT\jarwisfrontend; `$env:BROWSER='none'; npm start"
    $process = Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -WindowStyle Normal -PassThru
    
    # Save PID
    $process.Id | Out-File -FilePath $FRONTEND_PID_FILE -Force
    
    # Wait for startup
    Write-Status "  Waiting for frontend to start..." "Gray"
    $maxWait = 30
    for ($i = 0; $i -lt $maxWait; $i++) {
        Start-Sleep -Seconds 1
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$FRONTEND_PORT" -UseBasicParsing -TimeoutSec 2
            Write-Status "  Frontend started successfully (http://localhost:$FRONTEND_PORT)" "Green"
            return
        } catch {}
    }
    Write-Status "  Frontend may still be starting..." "Yellow"
}

function Show-Status {
    Write-Status "`n[JARWIS STATUS]" "Cyan"
    
    # Backend
    $backendPids = Get-PortProcess -Port $BACKEND_PORT
    if ($backendPids.Count -gt 0) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$BACKEND_PORT/api/health" -UseBasicParsing -TimeoutSec 3
            Write-Status "  Backend:  RUNNING (http://localhost:$BACKEND_PORT) [PID: $($backendPids -join ', ')]" "Green"
        } catch {
            Write-Status "  Backend:  LISTENING but not responding [PID: $($backendPids -join ', ')]" "Yellow"
        }
    } else {
        Write-Status "  Backend:  NOT RUNNING" "Red"
    }
    
    # Frontend
    $frontendPids = Get-PortProcess -Port $FRONTEND_PORT
    if ($frontendPids.Count -gt 0) {
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$FRONTEND_PORT" -UseBasicParsing -TimeoutSec 3
            Write-Status "  Frontend: RUNNING (http://localhost:$FRONTEND_PORT) [PID: $($frontendPids -join ', ')]" "Green"
        } catch {
            Write-Status "  Frontend: LISTENING but not responding [PID: $($frontendPids -join ', ')]" "Yellow"
        }
    } else {
        Write-Status "  Frontend: NOT RUNNING" "Red"
    }
    
    Write-Status "`n  Login: http://localhost:3000/login" "Yellow"
    Write-Status "  Email: user2@jarwis.ai | Pass: 12341234" "Yellow"
}

# Main execution
Write-Status "`n========================================" "Cyan"
Write-Status "  JARWIS Service Manager" "Cyan"
Write-Status "========================================" "Cyan"

switch ($Action) {
    'start' {
        if (-not $FrontendOnly) { Start-Backend }
        if (-not $BackendOnly) { Start-Frontend }
        Show-Status
    }
    'stop' {
        Stop-AllServices
        Show-Status
    }
    'restart' {
        Stop-AllServices
        Start-Sleep -Seconds 2
        if (-not $FrontendOnly) { Start-Backend }
        if (-not $BackendOnly) { Start-Frontend }
        Show-Status
    }
    'status' {
        Show-Status
    }
}

Write-Status "`n========================================" "Green"
