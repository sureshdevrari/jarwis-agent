<#
.SYNOPSIS
    Start All Jarwis Services
.DESCRIPTION
    Starts all services required for mobile security testing
#>

# Configuration
$ANDROID_HOME = "C:\Android"
$ANDROID_SDK = "C:\Android\Sdk"
$ANDROID_AVD_HOME = "C:\Android\avd"
$PROJECT_DIR = "D:\jarwis-ai-pentest"
$BACKEND_PORT = 8000
$FRONTEND_PORT = 3000
$EMULATOR_ADB_PORT = 5554
$AVD_NAME = "jarwis_test_device"

# Set environment variables
$env:ANDROID_HOME = $ANDROID_HOME
$env:ANDROID_SDK_ROOT = $ANDROID_SDK
$env:ANDROID_AVD_HOME = $ANDROID_AVD_HOME
$env:PATH = "$env:PATH;$ANDROID_SDK\platform-tools;$ANDROID_SDK\emulator"

# Get paths
$adb = "$ANDROID_SDK\platform-tools\adb.exe"
$emulatorExe = "$ANDROID_SDK\emulator\emulator.exe"

Write-Host ""
Write-Host "  =======================================================" -ForegroundColor Magenta
Write-Host "         JARWIS - MOBILE SECURITY TESTING                " -ForegroundColor Magenta
Write-Host "              Starting All Services                      " -ForegroundColor Magenta
Write-Host "  =======================================================" -ForegroundColor Magenta
Write-Host ""

# Port allocation display
Write-Host "  PORT ALLOCATION:" -ForegroundColor Cyan
Write-Host "    Backend API:      Port $BACKEND_PORT" -ForegroundColor White
Write-Host "    Frontend:         Port $FRONTEND_PORT" -ForegroundColor White
Write-Host "    Emulator ADB:     Port $EMULATOR_ADB_PORT" -ForegroundColor White
Write-Host "    Frida Server:     Port 27042 (on emulator)" -ForegroundColor White
Write-Host ""

# Step 1: Check and clear ports
Write-Host "  [1/5] Checking Ports..." -ForegroundColor Yellow

$backendConn = Get-NetTCPConnection -LocalPort $BACKEND_PORT -ErrorAction SilentlyContinue
if ($backendConn) {
    Write-Host "    Stopping process on port $BACKEND_PORT..." -ForegroundColor Gray
    Stop-Process -Id $backendConn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
Write-Host "    [OK] Port $BACKEND_PORT available" -ForegroundColor Green

$frontendConn = Get-NetTCPConnection -LocalPort $FRONTEND_PORT -ErrorAction SilentlyContinue
if ($frontendConn) {
    Write-Host "    Stopping process on port $FRONTEND_PORT..." -ForegroundColor Gray
    Stop-Process -Id $frontendConn.OwningProcess -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}
Write-Host "    [OK] Port $FRONTEND_PORT available" -ForegroundColor Green

# Step 2: Start Android Emulator
Write-Host ""
Write-Host "  [2/5] Starting Android Emulator..." -ForegroundColor Yellow

$devices = & $adb devices 2>$null
if ($devices -match "emulator") {
    Write-Host "    [OK] Emulator already running" -ForegroundColor Green
    $emulatorRunning = $true
} else {
    if (Test-Path $emulatorExe) {
        Write-Host "    Starting emulator (this may take 1-2 minutes)..." -ForegroundColor Gray
        
        Start-Process -FilePath $emulatorExe -ArgumentList "-avd", $AVD_NAME, "-no-audio", "-gpu", "swiftshader_indirect", "-no-boot-anim", "-no-metrics" -WindowStyle Minimized
        
        Write-Host "    Waiting for device..." -ForegroundColor Gray
        & $adb wait-for-device
        
        $timeout = 120
        $elapsed = 0
        do {
            Start-Sleep -Seconds 5
            $elapsed += 5
            $bootComplete = & $adb shell getprop sys.boot_completed 2>$null
            Write-Host "    Booting... $elapsed seconds" -ForegroundColor Gray
        } while ($bootComplete -ne "1" -and $elapsed -lt $timeout)
        
        if ($bootComplete -eq "1") {
            Write-Host "    [OK] Emulator booted successfully" -ForegroundColor Green
            $emulatorRunning = $true
        } else {
            Write-Host "    [!!] Emulator boot timeout" -ForegroundColor Red
            $emulatorRunning = $false
        }
    } else {
        Write-Host "    [!!] Emulator not found" -ForegroundColor Red
        $emulatorRunning = $false
    }
}

# Step 3: Start Frida Server
Write-Host ""
Write-Host "  [3/5] Starting Frida Server..." -ForegroundColor Yellow

if ($emulatorRunning) {
    $fridaPid = & $adb shell "pidof frida-server" 2>$null
    
    if ($fridaPid) {
        Write-Host "    [OK] Frida already running (PID: $fridaPid)" -ForegroundColor Green
    } else {
        $fridaServer = "C:\Android\Sdk\frida\frida-server-x86_64"
        
        if (Test-Path $fridaServer) {
            Write-Host "    Pushing Frida to device..." -ForegroundColor Gray
            & $adb push $fridaServer /data/local/tmp/frida-server 2>$null
            & $adb shell "chmod 755 /data/local/tmp/frida-server" 2>$null
            
            Start-Process -FilePath $adb -ArgumentList "shell", "/data/local/tmp/frida-server", "-D" -WindowStyle Hidden
            Start-Sleep -Seconds 3
            
            $fridaPid = & $adb shell "pidof frida-server" 2>$null
            if ($fridaPid) {
                Write-Host "    [OK] Frida started (PID: $fridaPid)" -ForegroundColor Green
            } else {
                Write-Host "    [!!] Frida failed to start" -ForegroundColor Red
            }
        } else {
            Write-Host "    [!!] Frida server not found" -ForegroundColor Red
        }
    }
} else {
    Write-Host "    [--] Skipped (no emulator)" -ForegroundColor Gray
}

# Step 4: Start Backend API
Write-Host ""
Write-Host "  [4/5] Starting Backend API..." -ForegroundColor Yellow

$backendCmd = "cd '$PROJECT_DIR'; .\.venv\Scripts\Activate.ps1; `$env:ANDROID_HOME='$ANDROID_HOME'; `$env:ANDROID_SDK_ROOT='$ANDROID_SDK'; python -m api.server"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd -WindowStyle Normal

Write-Host "    Waiting for backend to start..." -ForegroundColor Gray
Start-Sleep -Seconds 8

$backendReady = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$BACKEND_PORT/api/health" -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $backendReady = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 2
    }
}

if ($backendReady) {
    Write-Host "    [OK] Backend running on port $BACKEND_PORT" -ForegroundColor Green
} else {
    Write-Host "    [..] Backend starting (check window)" -ForegroundColor Yellow
}

# Step 5: Start Frontend
Write-Host ""
Write-Host "  [5/5] Starting Frontend..." -ForegroundColor Yellow

$frontendCmd = "cd '$PROJECT_DIR\jarwisfrontend'; `$env:PORT='$FRONTEND_PORT'; `$env:BROWSER='none'; npm start"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -WindowStyle Normal

Write-Host "    Waiting for frontend to compile..." -ForegroundColor Gray
Start-Sleep -Seconds 15

$frontendReady = $false
for ($i = 0; $i -lt 20; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$FRONTEND_PORT" -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            $frontendReady = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 3
    }
}

if ($frontendReady) {
    Write-Host "    [OK] Frontend running on port $FRONTEND_PORT" -ForegroundColor Green
} else {
    Write-Host "    [..] Frontend compiling (check window)" -ForegroundColor Yellow
}

# Final Summary
Write-Host ""
Write-Host "  =======================================================" -ForegroundColor Green
Write-Host "              ALL SERVICES STARTED!                      " -ForegroundColor Green
Write-Host "  =======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service Status:" -ForegroundColor Cyan

# Check each service
$emulatorCheck = (& $adb devices 2>$null) -match "emulator"
if ($emulatorCheck) { Write-Host "    [OK] Emulator: emulator-$EMULATOR_ADB_PORT" -ForegroundColor Green }
else { Write-Host "    [!!] Emulator: Not running" -ForegroundColor Red }

$fridaCheck = & $adb shell "pidof frida-server" 2>$null
if ($fridaCheck) { Write-Host "    [OK] Frida: Port 27042 (PID: $fridaCheck)" -ForegroundColor Green }
else { Write-Host "    [!!] Frida: Not running" -ForegroundColor Red }

$backendCheck = Get-NetTCPConnection -LocalPort $BACKEND_PORT -ErrorAction SilentlyContinue
if ($backendCheck) { Write-Host "    [OK] Backend: http://localhost:$BACKEND_PORT" -ForegroundColor Green }
else { Write-Host "    [!!] Backend: Not running" -ForegroundColor Red }

$frontendCheck = Get-NetTCPConnection -LocalPort $FRONTEND_PORT -ErrorAction SilentlyContinue
if ($frontendCheck) { Write-Host "    [OK] Frontend: http://localhost:$FRONTEND_PORT" -ForegroundColor Green }
else { Write-Host "    [..] Frontend: Still compiling..." -ForegroundColor Yellow }

Write-Host ""
Write-Host "  Access:" -ForegroundColor Cyan
Write-Host "    Frontend:  http://localhost:$FRONTEND_PORT" -ForegroundColor White
Write-Host "    Backend:   http://localhost:$BACKEND_PORT" -ForegroundColor White
Write-Host ""
Write-Host "  Mobile Testing:" -ForegroundColor Cyan
Write-Host "    1. Go to Mobile Scan" -ForegroundColor White
Write-Host "    2. Upload APK/XAPK" -ForegroundColor White
Write-Host "    3. Select FULL mode" -ForegroundColor White
Write-Host "    4. Enable Auth: chaterva_ai / Urmines@1" -ForegroundColor White
Write-Host ""

# Open browser
Start-Process "http://localhost:$FRONTEND_PORT"
