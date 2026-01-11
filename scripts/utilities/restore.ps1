# ============================================================
# JARWIS AGI PEN TEST - Complete Restore Script for Windows
# ============================================================
# This script restores ALL dependencies, tools, and configurations
# Run this after cloning or restoring from backup
# ============================================================

param(
    [switch]$SkipSystemTools,
    [switch]$SkipPython,
    [switch]$SkipNode,
    [switch]$SkipPlaywright,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  JARWIS AGI PEN TEST - Full Restore" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# ============================================================
# STEP 1: Check System Prerequisites
# ============================================================
Write-Host "[1/6] Checking System Prerequisites..." -ForegroundColor Yellow

$missing = @()

# Check Python
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { 
    $missing += "Python 3.11+ (https://www.python.org/downloads/)"
} else {
    $pyVersion = python --version 2>&1
    Write-Host "  ✓ $pyVersion" -ForegroundColor Green
}

# Check Node.js
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { 
    $missing += "Node.js 18+ (https://nodejs.org/)"
} else {
    $nodeVersion = node --version
    Write-Host "  ✓ Node.js $nodeVersion" -ForegroundColor Green
}

# Check Git
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { 
    $missing += "Git (https://git-scm.com/)"
} else {
    Write-Host "  ✓ Git installed" -ForegroundColor Green
}

if ($missing.Count -gt 0 -and -not $SkipSystemTools) {
    Write-Host "`n  ✗ Missing required tools:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host "`nInstall these first, then run this script again." -ForegroundColor Yellow
    exit 1
}

# ============================================================
# STEP 2: Python Virtual Environment
# ============================================================
if (-not $SkipPython) {
    Write-Host "`n[2/6] Setting up Python environment..." -ForegroundColor Yellow
    
    $venvPath = Join-Path $ProjectRoot ".venv"
    
    if (Test-Path $venvPath) {
        if ($Force) {
            Write-Host "  Removing existing .venv..." -ForegroundColor Gray
            Remove-Item $venvPath -Recurse -Force
        } else {
            Write-Host "  ✓ Virtual environment already exists (use -Force to recreate)" -ForegroundColor Green
        }
    }
    
    if (-not (Test-Path $venvPath)) {
        Write-Host "  Creating virtual environment..." -ForegroundColor Gray
        python -m venv $venvPath
        Write-Host "  ✓ Virtual environment created" -ForegroundColor Green
    }
    
    # Activate and install packages
    $pipPath = Join-Path $venvPath "Scripts\pip.exe"
    $pythonPath = Join-Path $venvPath "Scripts\python.exe"
    
    Write-Host "  Installing Python packages (this may take 2-5 minutes)..." -ForegroundColor Gray
    & $pipPath install --upgrade pip -q
    & $pipPath install -r (Join-Path $ProjectRoot "requirements.txt") -q
    
    Write-Host "  ✓ Python packages installed" -ForegroundColor Green
} else {
    Write-Host "`n[2/6] Skipping Python setup..." -ForegroundColor Gray
}

# ============================================================
# STEP 3: Playwright Browsers
# ============================================================
if (-not $SkipPlaywright) {
    Write-Host "`n[3/6] Installing Playwright browsers..." -ForegroundColor Yellow
    
    $playwrightPath = Join-Path $ProjectRoot ".venv\Scripts\playwright.exe"
    
    if (Test-Path $playwrightPath) {
        Write-Host "  Downloading Chromium (required for PDF generation)..." -ForegroundColor Gray
        & $playwrightPath install chromium
        Write-Host "  ✓ Playwright browsers installed" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Playwright not found - run Python setup first" -ForegroundColor Red
    }
} else {
    Write-Host "`n[3/6] Skipping Playwright setup..." -ForegroundColor Gray
}

# ============================================================
# STEP 4: Node.js Dependencies
# ============================================================
if (-not $SkipNode) {
    Write-Host "`n[4/6] Installing Node.js dependencies..." -ForegroundColor Yellow
    
    $frontendPath = Join-Path $ProjectRoot "jarwisfrontend"
    
    if (Test-Path $frontendPath) {
        Push-Location $frontendPath
        
        if (Test-Path "node_modules" -and -not $Force) {
            Write-Host "  ✓ node_modules already exists (use -Force to reinstall)" -ForegroundColor Green
        } else {
            if ($Force -and (Test-Path "node_modules")) {
                Write-Host "  Removing existing node_modules..." -ForegroundColor Gray
                Remove-Item "node_modules" -Recurse -Force
            }
            Write-Host "  Installing npm packages (this may take 1-3 minutes)..." -ForegroundColor Gray
            npm install --silent 2>$null
            Write-Host "  ✓ Node packages installed" -ForegroundColor Green
        }
        
        Pop-Location
    } else {
        Write-Host "  ✗ Frontend folder not found at $frontendPath" -ForegroundColor Red
    }
} else {
    Write-Host "`n[4/6] Skipping Node.js setup..." -ForegroundColor Gray
}

# ============================================================
# STEP 5: Check Optional Tools
# ============================================================
Write-Host "`n[5/6] Checking optional tools..." -ForegroundColor Yellow

# Android SDK (for mobile security)
$adb = Get-Command adb -ErrorAction SilentlyContinue
if ($adb) {
    Write-Host "  ✓ Android ADB installed" -ForegroundColor Green
} else {
    Write-Host "  ○ Android SDK not installed (optional - for mobile testing)" -ForegroundColor Gray
}

# ============================================================
# STEP 6: Environment Configuration
# ============================================================
Write-Host "`n[6/6] Checking configuration..." -ForegroundColor Yellow

$envFile = Join-Path $ProjectRoot ".env"
$envExample = Join-Path $ProjectRoot ".env.example"

if (-not (Test-Path $envFile)) {
    if (Test-Path $envExample) {
        Copy-Item $envExample $envFile
        Write-Host "  ✓ Created .env from .env.example" -ForegroundColor Green
        Write-Host "    → Edit .env to add your API keys" -ForegroundColor Yellow
    } else {
        Write-Host "  ○ No .env file (create one with your API keys)" -ForegroundColor Gray
    }
} else {
    Write-Host "  ✓ .env file exists" -ForegroundColor Green
}

# ============================================================
# COMPLETE
# ============================================================
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "  ✓ RESTORE COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`nTo start the application:" -ForegroundColor Cyan
Write-Host "  Backend:  .\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor White
Write-Host "  Frontend: cd jarwisfrontend; npm start" -ForegroundColor White
Write-Host "`nOr use: .\start_dev.ps1" -ForegroundColor Cyan

Write-Host "`n"
