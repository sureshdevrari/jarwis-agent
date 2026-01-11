# Jarwis Cloud Security Scanner - Azure Service Principal Setup
# Run this script in Azure Cloud Shell or local PowerShell with Azure CLI installed

<#
.SYNOPSIS
    Creates an Azure Service Principal with Reader role for Jarwis security scanning.

.DESCRIPTION
    This script creates:
    1. An Azure AD App Registration
    2. A Service Principal
    3. Assigns Reader and Security Reader roles to selected subscriptions
    
    The credentials are displayed at the end - save them securely!

.PARAMETER AppName
    Name for the Azure AD Application (default: JarwisSecurityScanner)

.PARAMETER SubscriptionIds
    Array of subscription IDs to grant access to. If not specified, uses current subscription.

.EXAMPLE
    .\azure-service-principal-setup.ps1
    
.EXAMPLE
    .\azure-service-principal-setup.ps1 -SubscriptionIds @("sub-id-1", "sub-id-2")
#>

param(
    [string]$AppName = "JarwisSecurityScanner",
    [string[]]$SubscriptionIds = @()
)

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Jarwis Azure Service Principal Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if Azure CLI is installed
try {
    $azVersion = az version --output json | ConvertFrom-Json
    Write-Host "Azure CLI version: $($azVersion.'azure-cli')" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Azure CLI is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Install from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit 1
}

# Check if logged in
$account = az account show --output json 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "Not logged in. Running 'az login'..." -ForegroundColor Yellow
    az login
    $account = az account show --output json | ConvertFrom-Json
}

Write-Host ""
Write-Host "Current Azure Account:" -ForegroundColor Yellow
Write-Host "  User: $($account.user.name)"
Write-Host "  Tenant: $($account.tenantId)"
Write-Host "  Subscription: $($account.name) ($($account.id))"
Write-Host ""

# Get subscription IDs
if ($SubscriptionIds.Count -eq 0) {
    Write-Host "No subscription IDs specified. Using current subscription." -ForegroundColor Yellow
    $SubscriptionIds = @($account.id)
}

Write-Host "Subscriptions to configure: $($SubscriptionIds -join ', ')" -ForegroundColor Cyan
Write-Host ""

# Step 1: Create App Registration
Write-Host "[1/4] Creating Azure AD App Registration..." -ForegroundColor Yellow
$existingApp = az ad app list --display-name $AppName --output json | ConvertFrom-Json
if ($existingApp.Count -gt 0) {
    Write-Host "  App '$AppName' already exists. Using existing app." -ForegroundColor Yellow
    $appId = $existingApp[0].appId
} else {
    $app = az ad app create --display-name $AppName --output json | ConvertFrom-Json
    $appId = $app.appId
    Write-Host "  Created app with ID: $appId" -ForegroundColor Green
}

# Step 2: Create Service Principal
Write-Host "[2/4] Creating Service Principal..." -ForegroundColor Yellow
$existingSp = az ad sp list --filter "appId eq '$appId'" --output json | ConvertFrom-Json
if ($existingSp.Count -gt 0) {
    Write-Host "  Service Principal already exists." -ForegroundColor Yellow
    $spId = $existingSp[0].id
} else {
    $sp = az ad sp create --id $appId --output json | ConvertFrom-Json
    $spId = $sp.id
    Write-Host "  Created Service Principal with ID: $spId" -ForegroundColor Green
}

# Step 3: Create Client Secret
Write-Host "[3/4] Creating Client Secret..." -ForegroundColor Yellow
$secret = az ad app credential reset --id $appId --append --years 2 --output json | ConvertFrom-Json
$clientSecret = $secret.password
Write-Host "  Created client secret (expires in 2 years)" -ForegroundColor Green

# Step 4: Assign roles to subscriptions
Write-Host "[4/4] Assigning roles to subscriptions..." -ForegroundColor Yellow
foreach ($subId in $SubscriptionIds) {
    Write-Host "  Processing subscription: $subId" -ForegroundColor Cyan
    
    # Assign Reader role
    try {
        az role assignment create `
            --assignee $appId `
            --role "Reader" `
            --scope "/subscriptions/$subId" `
            --output none 2>$null
        Write-Host "    ✓ Reader role assigned" -ForegroundColor Green
    } catch {
        Write-Host "    Reader role may already exist or failed" -ForegroundColor Yellow
    }
    
    # Assign Security Reader role
    try {
        az role assignment create `
            --assignee $appId `
            --role "Security Reader" `
            --scope "/subscriptions/$subId" `
            --output none 2>$null
        Write-Host "    ✓ Security Reader role assigned" -ForegroundColor Green
    } catch {
        Write-Host "    Security Reader role may already exist or failed" -ForegroundColor Yellow
    }
}

# Output credentials
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  SETUP COMPLETE - SAVE THESE CREDENTIALS" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Copy these values into Jarwis Cloud Scan configuration:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Tenant ID:       $($account.tenantId)" -ForegroundColor White
Write-Host "  Client ID:       $appId" -ForegroundColor White
Write-Host "  Client Secret:   $clientSecret" -ForegroundColor White
Write-Host "  Subscription IDs: $($SubscriptionIds -join ', ')" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  IMPORTANT: Save the Client Secret now - it cannot be retrieved later!" -ForegroundColor Red
Write-Host ""

# Create JSON output for easy copying
$outputJson = @{
    tenant_id = $account.tenantId
    client_id = $appId
    client_secret = $clientSecret
    subscription_ids = $SubscriptionIds
} | ConvertTo-Json

Write-Host "JSON format for API:" -ForegroundColor Cyan
Write-Host $outputJson
Write-Host ""
