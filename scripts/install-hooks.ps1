# Pre-commit hook installer for Windows
# Copies the pre-commit hook to .git/hooks/

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$hookSource = Join-Path $scriptDir "pre-commit"
$hookDest = Join-Path $projectRoot ".git\hooks\pre-commit"

if (-not (Test-Path $hookSource)) {
    Write-Host "❌ Source hook not found: $hookSource" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $projectRoot ".git"))) {
    Write-Host "❌ Not a git repository" -ForegroundColor Red
    exit 1
}

# Create hooks directory if needed
$hooksDir = Join-Path $projectRoot ".git\hooks"
if (-not (Test-Path $hooksDir)) {
    New-Item -ItemType Directory -Path $hooksDir | Out-Null
}

# Copy hook
Copy-Item $hookSource $hookDest -Force

Write-Host "✅ Pre-commit hook installed!" -ForegroundColor Green
Write-Host "Hook location: $hookDest" -ForegroundColor Cyan
Write-Host ""
Write-Host "The hook will now automatically:" -ForegroundColor Yellow
Write-Host "  • Regenerate frontend contracts when Python contracts change" -ForegroundColor White
Write-Host "  • Check Python syntax before commits" -ForegroundColor White
