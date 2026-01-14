# Start Jarwis Android Emulator
$env:ANDROID_HOME = "C:\Android\Sdk"
$env:ANDROID_SDK_ROOT = "C:\Android\Sdk"
$env:Path = "$env:Path;C:\Android\Sdk\emulator;C:\Android\Sdk\platform-tools"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  JARWIS ANDROID EMULATOR LAUNCHER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Starting Android Emulator (jarwis_test_device)..." -ForegroundColor Green

# Use ADB from the correct location
$adb = "C:\Android\platform-tools\adb.exe"
if (-not (Test-Path $adb)) {
    $adb = "C:\Android\Sdk\platform-tools\adb.exe"
}

# Start emulator
$emulator = "C:\Android\Sdk\emulator\emulator.exe"
Start-Process -FilePath $emulator -ArgumentList "-avd", "jarwis_test_device", "-gpu", "auto", "-no-snapshot-load", "-no-audio" -WindowStyle Minimized

Write-Host "Waiting for emulator to boot (this may take 1-2 minutes)..." -ForegroundColor Yellow

# Wait for device
& $adb wait-for-device
Write-Host "  [OK] Device detected" -ForegroundColor Green

# Wait for boot complete with timeout
$timeout = 180  # 3 minutes
$elapsed = 0
do {
    Start-Sleep -Seconds 3
    $elapsed += 3
    $bootComplete = & $adb shell getprop sys.boot_completed 2>$null
    Write-Host "  Booting... ($elapsed seconds)" -ForegroundColor Yellow
} while ($bootComplete -ne "1" -and $elapsed -lt $timeout)

if ($bootComplete -eq "1") {
    Write-Host "  [OK] Boot completed!" -ForegroundColor Green
} else {
    Write-Host "  [!] Boot timeout - emulator may still be starting" -ForegroundColor Red
}

# Push and start Frida server
$fridaServer = "C:\Android\Sdk\frida\frida-server-x86_64"
if (Test-Path $fridaServer) {
    Write-Host ""
    Write-Host "Installing Frida server for SSL pinning bypass..." -ForegroundColor Yellow
    & $adb push $fridaServer /data/local/tmp/frida-server 2>$null
    & $adb shell "chmod 755 /data/local/tmp/frida-server" 2>$null
    
    # Kill any existing Frida server
    & $adb shell "pkill frida-server" 2>$null
    
    # Start Frida in background
    Start-Process -FilePath $adb -ArgumentList "shell", "/data/local/tmp/frida-server", "-D" -WindowStyle Hidden
    Start-Sleep -Seconds 2
    
    # Verify Frida is running
    $fridaPid = & $adb shell "pidof frida-server" 2>$null
    if ($fridaPid) {
        Write-Host "  [OK] Frida server running (PID: $fridaPid)" -ForegroundColor Green
    } else {
        Write-Host "  [!] Frida server may not be running" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  EMULATOR READY FOR MOBILE TESTING!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open Jarwis at http://localhost:3000" -ForegroundColor White
Write-Host "  2. Go to Mobile Scan" -ForegroundColor White
Write-Host "  3. Upload your APK/XAPK file" -ForegroundColor White
Write-Host "  4. Select 'FULL' scan mode" -ForegroundColor White
Write-Host "  5. Enable Authentication and enter credentials" -ForegroundColor White
Write-Host "  6. Start the scan!" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
