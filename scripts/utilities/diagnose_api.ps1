# Jarwis API Diagnostics Script
# Checks if both backend and frontend are properly configured and running

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Jarwis API Gateway Diagnostics" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Check if backend is running
Write-Host "[1/5] Checking Backend Status..." -ForegroundColor Yellow
$backendPort = netstat -ano | Select-String ":8000.*LISTEN"
if ($backendPort) {
    Write-Host "  OK Backend is running on port 8000" -ForegroundColor Green
    $pid = ($backendPort -split '\s+')[-1]
    Write-Host "    PID: $pid" -ForegroundColor Gray
} else {
    Write-Host "  ERROR Backend is NOT running on port 8000" -ForegroundColor Red
    Write-Host "    Run: .\start_jarwis.ps1" -ForegroundColor Yellow
    exit 1
}

# Test 2: Check if frontend is running
Write-Host ""
Write-Host "[2/5] Checking Frontend Status..." -ForegroundColor Yellow
$frontendPort = netstat -ano | Select-String ":3000.*LISTEN"
if ($frontendPort) {
    Write-Host "  OK Frontend is running on port 3000" -ForegroundColor Green
    $pid = ($frontendPort -split '\s+')[-1]
    Write-Host "    PID: $pid" -ForegroundColor Gray
} else {
    Write-Host "  ERROR Frontend is NOT running on port 3000" -ForegroundColor Red
    Write-Host "    Run: .\start_jarwis.ps1" -ForegroundColor Yellow
    exit 1
}

# Test 3: Check backend health endpoint
Write-Host ""
Write-Host "[3/5] Testing Backend Health..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri 'http://localhost:8000/api/health' -Method Get -TimeoutSec 5
    if ($health.status -eq 'ok') {
        Write-Host "  OK Backend API is responding correctly" -ForegroundColor Green
        Write-Host "    Service: $($health.service)" -ForegroundColor Gray
        Write-Host "    Version: $($health.version)" -ForegroundColor Gray
    } else {
        Write-Host "  ERROR Backend health check failed" -ForegroundColor Red
    }
} catch {
    Write-Host "  ERROR Cannot reach backend API" -ForegroundColor Red
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Test 4: Check login endpoint
Write-Host ""
Write-Host "[4/5] Testing Login Endpoint..." -ForegroundColor Yellow
try {
    $body = @{email='admin@jarwis.ai'; password='admin123'} | ConvertTo-Json
    $login = Invoke-RestMethod -Uri 'http://localhost:8000/api/auth/login' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 5
    if ($login.access_token) {
        Write-Host "  OK Login endpoint is working" -ForegroundColor Green
        Write-Host "    User: $($login.user.email)" -ForegroundColor Gray
        Write-Host "    Plan: $($login.user.plan)" -ForegroundColor Gray
    } else {
        Write-Host "  ERROR Login failed - no access token received" -ForegroundColor Red
    }
} catch {
    Write-Host "  ERROR Login endpoint test failed" -ForegroundColor Red
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 5: Check CORS configuration
Write-Host ""
Write-Host "[5/5] Checking CORS Configuration..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri 'http://localhost:8000/api/health' -Method Options -Headers @{
        'Origin' = 'http://localhost:3000'
        'Access-Control-Request-Method' = 'GET'
    } -TimeoutSec 5 -UseBasicParsing
    
    $allowOrigin = $response.Headers['Access-Control-Allow-Origin']
    $allowCreds = $response.Headers['Access-Control-Allow-Credentials']
    
    Write-Host "  OK CORS is configured" -ForegroundColor Green
    Write-Host "    Allow-Origin: $allowOrigin" -ForegroundColor Gray
    Write-Host "    Allow-Credentials: $allowCreds" -ForegroundColor Gray
} catch {
    Write-Host "  WARNING CORS check inconclusive" -ForegroundColor Yellow
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Diagnostic Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Backend API:  http://localhost:8000" -ForegroundColor Green
Write-Host "  Frontend:     http://localhost:3000" -ForegroundColor Green
Write-Host ""
Write-Host "If you are seeing network errors:" -ForegroundColor Yellow
Write-Host "  1. Clear browser cache (Ctrl+Shift+Delete)" -ForegroundColor White
Write-Host "  2. Hard refresh the page (Ctrl+F5)" -ForegroundColor White
Write-Host "  3. Check browser console (F12) for details" -ForegroundColor White
Write-Host "  4. Restart both services with: .\start_jarwis.ps1" -ForegroundColor White
Write-Host ""
