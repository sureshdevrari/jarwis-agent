# Jarwis Deployment Script (PowerShell)
# Unified deployment pipeline for Windows

param(
    [string]$Environment = "development",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Jarwis Deployment Pipeline" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Run deployment gateway
Write-Host "📋 Step 1: Validating system..." -ForegroundColor Yellow

$gatewayArgs = @("deploy_gateway.py", "--env", $Environment)
if ($SkipTests) {
    $gatewayArgs += "--skip-tests"
}

& .\.venv\Scripts\python.exe $gatewayArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Deployment validation failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "✅ Deployment validation passed!" -ForegroundColor Green
Write-Host ""

# Step 2: Display next steps based on environment
if ($Environment -eq "production") {
    Write-Host "🐳 Step 2: Building Docker images..." -ForegroundColor Yellow
    
    # Check if Docker is available
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        docker-compose build --no-cache
        
        if ($LASTEXITCODE -eq 0) {
            # Tag images with git SHA
            $gitSha = git rev-parse --short HEAD 2>$null
            if ($gitSha) {
                Write-Host "🏷️  Tagging images with SHA: $gitSha" -ForegroundColor Yellow
                docker tag jarwis-backend:latest "jarwis-backend:$gitSha"
                docker tag jarwis-frontend:latest "jarwis-frontend:$gitSha"
            }
            
            Write-Host ""
            Write-Host "🛑 Step 3: Stopping old containers..." -ForegroundColor Yellow
            docker-compose down
            
            Write-Host ""
            Write-Host "▶️  Step 4: Starting new containers..." -ForegroundColor Yellow
            docker-compose up -d
            
            Write-Host ""
            Write-Host "⏳ Waiting for services..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
            
            Write-Host ""
            Write-Host "🏥 Step 5: Health check..." -ForegroundColor Yellow
            
            try {
                $response = Invoke-WebRequest -Uri "http://localhost/api/health" -TimeoutSec 10
                if ($response.StatusCode -eq 200) {
                    Write-Host "✅ Deployment complete!" -ForegroundColor Green
                    Write-Host "🌐 Frontend: http://localhost" -ForegroundColor Cyan
                    Write-Host "🔌 Backend: http://localhost/api" -ForegroundColor Cyan
                } else {
                    Write-Host "⚠️  Health check returned status: $($response.StatusCode)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "❌ Health check failed: $_" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "❌ Docker build failed!" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "⚠️  Docker not found. Skipping container deployment." -ForegroundColor Yellow
        Write-Host "For production, install Docker and Docker Compose." -ForegroundColor Yellow
    }
} else {
    Write-Host "📋 Development Environment Ready!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To start services:" -ForegroundColor Cyan
    Write-Host "  1. Backend:  .\.venv\Scripts\python.exe -m uvicorn api.server:app --reload" -ForegroundColor White
    Write-Host "  2. Frontend: cd jarwisfrontend && npm start" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use: .\start_jarwis.ps1" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "✅ Deployment pipeline completed!" -ForegroundColor Green
