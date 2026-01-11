# cleanup.ps1 - Force kill lingering Jarwis processes

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Jarwis Environment Cleanup Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Kill by Port (Most precise)
function Kill-Port($port) {
    $pids = netstat -ano | Select-String ":$port\s+.*LISTEN" | ForEach-Object {
        $parts = $_ -split '\s+'
        $parts[-1]
    } | Where-Object { $_ -match '^\d+$' } | Get-Unique

    foreach ($pid_val in $pids) {
        try {
            $proc = Get-Process -Id $pid_val -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "Killing process on port $port : $($proc.ProcessName) (PID: $pid_val)" -ForegroundColor Yellow
                Stop-Process -Id $pid_val -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "Could not kill PID $pid_val on port $port" -ForegroundColor Red
        }
    }
}

Kill-Port 8000
Kill-Port 3000

# 2. Kill all Python/Node processes (Brute force for workers/zombies)
Write-Host "Checking for lingering Python/Node processes..."
$procs = Get-Process -Name python, node, uvicorn -ErrorAction SilentlyContinue

if ($procs) {
    Write-Host "Found $($procs.Count) background processes. Stopping them..." -ForegroundColor Yellow
    $procs | ForEach-Object {
        Write-Host "  Stopping $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor DarkGray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue 
    }
} else {
    Write-Host "No background Python/Node processes found." -ForegroundColor Green
}

# 3. Check for locked files (Basic check)
if (Test-Path "core\__pycache__") {
    Write-Host "Clearing pycache..." -ForegroundColor Gray
    Get-ChildItem -Path . -Recurse -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nCleanup Complete! Environment is ready." -ForegroundColor Green
