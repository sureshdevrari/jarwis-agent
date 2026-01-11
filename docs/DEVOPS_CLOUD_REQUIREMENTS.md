# Jarwis Cloud Scanning - DevOps Requirements

## Overview

Jarwis supports security scanning for AWS, Azure, and GCP cloud environments. Each provider requires its own SDK to be installed.

## Cloud SDK Dependencies

### Minimum (AWS Only)
If you're only offering AWS scanning to customers:
```bash
pip install boto3
```

### Full Multi-Cloud Support
For all three cloud providers:
```bash
pip install -r requirements.txt
```

## SDK Requirements by Cloud Provider

| Provider | Required Packages | Approx Size |
|----------|------------------|-------------|
| **AWS** | `boto3` | ~100MB |
| **Azure** | `azure-identity`, `azure-mgmt-*` (12 packages) | ~200MB |
| **GCP** | `google-cloud-*` (8 packages) | ~150MB |

### AWS Packages
```
boto3>=1.34.0
botocore>=1.34.0
```

### Azure Packages
```
azure-identity>=1.15.0
azure-mgmt-resource>=23.0.0
azure-mgmt-storage>=21.0.0
azure-mgmt-compute>=30.0.0
azure-mgmt-network>=25.0.0
azure-mgmt-sql>=4.0.0
azure-mgmt-monitor>=6.0.0
azure-mgmt-keyvault>=10.0.0
azure-mgmt-containerservice>=29.0.0
azure-mgmt-web>=7.0.0
azure-mgmt-security>=5.0.0
azure-mgmt-subscription>=3.1.0
azure-storage-blob>=12.28.0
```

### GCP Packages
```
google-cloud-storage>=2.14.0
google-cloud-compute>=1.15.0
google-cloud-container>=2.35.0
google-cloud-iam>=2.14.0
google-auth>=2.22.0
google-api-python-client>=2.110.0
```

## Environment Variables

### Option 1: Jarwis Server Credentials (For Cross-Account Role Assumption)
If Jarwis uses its own AWS credentials to assume customer roles:
```bash
export JARWIS_AWS_ACCESS_KEY=AKIA...
export JARWIS_AWS_SECRET_KEY=...
```

### Option 2: IAM Instance Profile (Recommended for EC2)
When running Jarwis on EC2, use an IAM instance profile with permission to assume customer roles.
No environment variables needed - boto3 automatically detects instance profile.

### Required IAM Permission for Jarwis
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "arn:aws:iam::*:role/JarwisSecurityAudit"
        }
    ]
}
```

## Customer Onboarding Templates

Templates are provided for customers to set up access:

| Provider | Template Location | How Customer Uses It |
|----------|------------------|---------------------|
| AWS | `templates/cloud-onboarding/aws-trust-role.yaml` | Deploy as CloudFormation stack |
| Azure | `templates/cloud-onboarding/azure-service-principal-setup.ps1` | Run in PowerShell |
| GCP | `templates/cloud-onboarding/gcp-service-account-setup.sh` | Run in Cloud Shell |

## Authentication Modes

### AWS
1. **Enterprise (Recommended)**: Cross-account IAM role with External ID
   - Customer deploys CloudFormation template
   - Jarwis assumes role using `sts:AssumeRole`
   
2. **Legacy**: Direct access keys
   - Customer provides Access Key ID + Secret Key
   - Not recommended for production

### Azure
- **Service Principal**: Customer creates App Registration with Reader + Security Reader roles
- Supports scanning multiple subscriptions in one scan

### GCP
1. **Enterprise (Recommended)**: Workload Identity Federation
   - No long-lived keys
   - Uses OIDC tokens
   
2. **Legacy**: Service Account JSON key
   - Customer provides JSON key file content

## Verification Commands

After deployment, verify SDKs are installed:

```bash
# Verify AWS SDK
python -c "import boto3; print(f'boto3: {boto3.__version__}')"

# Verify Azure SDK
python -c "from azure.identity import ClientSecretCredential; print('Azure SDK: OK')"

# Verify GCP SDK
python -c "from google.cloud import storage; print('GCP SDK: OK')"

# Verify all scanners load
python -c "
from attacks.cloud.aws_scanner import AWSSecurityScanner
from attacks.cloud.azure_scanner_complete import AzureSecurityScanner
from attacks.cloud.gcp_scanner import GCPSecurityScanner
print('All cloud scanners: OK')
"
```

## API Endpoints for Cloud Scanning

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/scan/cloud/services/{provider}` | GET | List scannable services |
| `/api/scan/cloud/onboarding-template/{provider}` | GET | Get setup template |
| `/api/scan/cloud/generate-external-id` | POST | Generate AWS External ID |
| `/api/scan/cloud/validate-credentials` | POST | Validate credentials |
| `/api/scan/cloud/start` | POST | Start cloud scan |
| `/api/scan/cloud/{scan_id}/status` | GET | Get scan status |

## Docker Considerations

When running in Docker, ensure the container has:
1. Network access to cloud provider APIs
2. Environment variables for Jarwis credentials (if using Option 1)
3. Sufficient memory (~2GB recommended for large scans)

```dockerfile
# Example Dockerfile additions
ENV JARWIS_AWS_ACCESS_KEY=${AWS_ACCESS_KEY}
ENV JARWIS_AWS_SECRET_KEY=${AWS_SECRET_KEY}
```
