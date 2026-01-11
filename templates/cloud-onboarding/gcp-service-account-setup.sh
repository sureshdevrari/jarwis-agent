#!/bin/bash
# Jarwis Cloud Security Scanner - GCP Service Account Setup
# Run this script in Google Cloud Shell or locally with gcloud CLI installed

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
SA_NAME="${SA_NAME:-jarwis-scanner}"
SA_DISPLAY_NAME="${SA_DISPLAY_NAME:-Jarwis Security Scanner}"

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Jarwis GCP Service Account Setup${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}ERROR: gcloud CLI is not installed${NC}"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Get current project
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    echo -e "${YELLOW}No project set. Available projects:${NC}"
    gcloud projects list
    echo ""
    read -p "Enter Project ID: " PROJECT_ID
    gcloud config set project "$PROJECT_ID"
fi

echo -e "${GREEN}Using project: $PROJECT_ID${NC}"
echo ""

# Check authentication
ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
if [ -z "$ACCOUNT" ]; then
    echo -e "${YELLOW}Not authenticated. Running 'gcloud auth login'...${NC}"
    gcloud auth login
fi
echo -e "Authenticated as: ${GREEN}$ACCOUNT${NC}"
echo ""

# Step 1: Enable required APIs
echo -e "${YELLOW}[1/4] Enabling required APIs...${NC}"
APIS=(
    "compute.googleapis.com"
    "storage.googleapis.com"
    "iam.googleapis.com"
    "cloudresourcemanager.googleapis.com"
    "sqladmin.googleapis.com"
    "container.googleapis.com"
    "logging.googleapis.com"
)

for api in "${APIS[@]}"; do
    echo -n "  Enabling $api... "
    if gcloud services enable "$api" --project="$PROJECT_ID" 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}(may already be enabled)${NC}"
    fi
done
echo ""

# Step 2: Create Service Account
echo -e "${YELLOW}[2/4] Creating Service Account...${NC}"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &>/dev/null; then
    echo -e "  Service account ${GREEN}$SA_EMAIL${NC} already exists"
else
    gcloud iam service-accounts create "$SA_NAME" \
        --project="$PROJECT_ID" \
        --display-name="$SA_DISPLAY_NAME" \
        --description="Read-only access for Jarwis Cloud Security Scanner"
    echo -e "  Created service account: ${GREEN}$SA_EMAIL${NC}"
fi
echo ""

# Step 3: Assign IAM Roles
echo -e "${YELLOW}[3/4] Assigning IAM roles...${NC}"
ROLES=(
    "roles/viewer"
    "roles/iam.securityReviewer"
    "roles/compute.viewer"
    "roles/storage.objectViewer"
)

for role in "${ROLES[@]}"; do
    echo -n "  Assigning $role... "
    if gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="$role" \
        --condition=None \
        --quiet 2>/dev/null; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}(may already exist)${NC}"
    fi
done
echo ""

# Step 4: Create and download key (optional)
echo -e "${YELLOW}[4/4] Service Account Key Options${NC}"
echo ""
echo "Choose authentication method:"
echo "  1. Download JSON key file (legacy, less secure)"
echo "  2. Use Workload Identity Federation (recommended for production)"
echo "  3. Skip key creation (use for local testing with ADC)"
echo ""
read -p "Enter choice [1-3]: " CHOICE

case $CHOICE in
    1)
        KEY_FILE="${SA_NAME}-key.json"
        echo -e "${YELLOW}Creating service account key...${NC}"
        gcloud iam service-accounts keys create "$KEY_FILE" \
            --iam-account="$SA_EMAIL" \
            --project="$PROJECT_ID"
        echo -e "${GREEN}Key saved to: $KEY_FILE${NC}"
        echo ""
        echo -e "${RED}⚠️  IMPORTANT: Keep this file secure! Do not commit to git.${NC}"
        ;;
    2)
        echo -e "${CYAN}Workload Identity Federation setup:${NC}"
        echo ""
        echo "For Workload Identity Federation, you'll need to:"
        echo "1. Create a Workload Identity Pool"
        echo "2. Create a Provider (OIDC or AWS)"
        echo "3. Grant the pool access to the service account"
        echo ""
        echo "See: https://cloud.google.com/iam/docs/workload-identity-federation"
        ;;
    3)
        echo -e "${YELLOW}Skipping key creation.${NC}"
        echo "For local testing, run: gcloud auth application-default login"
        ;;
esac

# Output summary
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  SETUP COMPLETE${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "Copy these values into Jarwis Cloud Scan configuration:"
echo ""
echo -e "  ${CYAN}Project ID:${NC}            $PROJECT_ID"
echo -e "  ${CYAN}Service Account Email:${NC} $SA_EMAIL"
if [ "$CHOICE" = "1" ]; then
    echo -e "  ${CYAN}Key File:${NC}              $KEY_FILE"
    echo ""
    echo -e "JSON key contents (first 100 chars):"
    head -c 100 "$KEY_FILE"
    echo "..."
fi
echo ""
echo -e "${YELLOW}Permissions granted:${NC}"
echo "  - Viewer (read-only access to all resources)"
echo "  - Security Reviewer (view IAM policies)"
echo "  - Compute Viewer (view instances)"
echo "  - Storage Object Viewer (list buckets)"
echo ""
