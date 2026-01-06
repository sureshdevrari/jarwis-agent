# JARWIS AGI PENTEST - AWS DEPLOYMENT PLAN

## Document Information
- **Version:** 1.0
- **Date:** January 4, 2026
- **Project:** JARWIS AGI Penetration Testing Framework
- **Target Platform:** Amazon Web Services (AWS)

---

# EXECUTIVE SUMMARY

This document provides a comprehensive step-by-step guide to deploy the JARWIS AGI Penetration Testing Framework on AWS infrastructure. The deployment includes:

- **Backend API** (FastAPI/Python) on EC2/ECS
- **Frontend** (React) on S3 + CloudFront
- **Database** (PostgreSQL) on RDS
- **AI/LLM** via Amazon Bedrock (replacing Ollama)
- **Security scanning infrastructure** with proper isolation

---

# HIGH-LEVEL ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AWS CLOUD INFRASTRUCTURE                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌─────────────────────────────────────────────────────┐  │
│  │   ROUTE 53   │────▶│              CLOUDFRONT CDN                          │  │
│  │  DNS/Domain  │     │  (jarwis.yourdomain.com)                            │  │
│  └──────────────┘     └────────────────────┬────────────────────────────────┘  │
│                                             │                                    │
│         ┌───────────────────────────────────┼─────────────────────────┐         │
│         │                                   ▼                         │         │
│         │                    ┌──────────────────────────┐            │         │
│         │                    │        S3 BUCKET          │            │         │
│         │                    │    React Frontend Build   │            │         │
│         │                    │   (jarwis-frontend-prod)  │            │         │
│         │                    └──────────────────────────┘            │         │
│         │                                                             │         │
│         │              ┌──────────────────────────────────┐          │         │
│         │              │   APPLICATION LOAD BALANCER      │          │         │
│         │              │   (api.jarwis.yourdomain.com)   │          │         │
│         │              └───────────────┬──────────────────┘          │         │
│         │                              │                              │         │
│         │           ┌─────────VPC (10.0.0.0/16)──────────┐          │         │
│         │           │                  │                  │          │         │
│         │           │    ┌─────────────▼─────────────┐   │          │         │
│         │           │    │   PUBLIC SUBNET (10.0.1.0) │   │          │         │
│         │           │    │   ┌──────────────────────┐│   │          │         │
│         │           │    │   │     NAT GATEWAY      ││   │          │         │
│         │           │    │   └──────────────────────┘│   │          │         │
│         │           │    └───────────────────────────┘   │          │         │
│         │           │                                     │          │         │
│         │           │    ┌─────────────────────────────┐ │          │         │
│         │           │    │ PRIVATE SUBNET (10.0.2.0)   │ │          │         │
│         │           │    │                             │ │          │         │
│         │           │    │  ┌────────────────────────┐ │ │          │         │
│         │           │    │  │    ECS FARGATE CLUSTER │ │ │          │         │
│         │           │    │  │  ┌──────────────────┐  │ │ │          │         │
│         │           │    │  │  │ JARWIS API       │  │ │ │          │         │
│         │           │    │  │  │ (FastAPI)        │  │ │ │          │         │
│         │           │    │  │  │ Port: 8000       │  │ │ │          │         │
│         │           │    │  │  └──────────────────┘  │ │ │          │         │
│         │           │    │  │  ┌──────────────────┐  │ │ │          │         │
│         │           │    │  │  │ SCAN WORKER      │  │ │ │          │         │
│         │           │    │  │  │ (Playwright)     │  │ │ │          │         │
│         │           │    │  │  └──────────────────┘  │ │ │          │         │
│         │           │    │  └────────────────────────┘ │ │          │         │
│         │           │    │                             │ │          │         │
│         │           │    └─────────────────────────────┘ │          │         │
│         │           │                                     │          │         │
│         │           │    ┌─────────────────────────────┐ │          │         │
│         │           │    │ DATABASE SUBNET (10.0.3.0)  │ │          │         │
│         │           │    │  ┌────────────────────────┐ │ │          │         │
│         │           │    │  │    RDS PostgreSQL      │ │ │          │         │
│         │           │    │  │    (db.t3.medium)      │ │ │          │         │
│         │           │    │  │    jarwis_db           │ │ │          │         │
│         │           │    │  └────────────────────────┘ │ │          │         │
│         │           │    └─────────────────────────────┘ │          │         │
│         │           │                                     │          │         │
│         │           └─────────────────────────────────────┘          │         │
│         │                                                             │         │
│         └─────────────────────────────────────────────────────────────┘         │
│                                                                                  │
│  ┌────────────────────────────────────────────────────────────────────────────┐ │
│  │                        AWS MANAGED SERVICES                                 │ │
│  │                                                                            │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐│ │
│  │  │  AMAZON BEDROCK │  │ SECRETS MANAGER │  │      CLOUDWATCH            ││ │
│  │  │  Claude 3.5     │  │  DB Credentials │  │  Logs, Metrics, Alarms     ││ │
│  │  │  Sonnet Model   │  │  API Keys       │  │                            ││ │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘│ │
│  │                                                                            │ │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐│ │
│  │  │      ECR        │  │       SQS       │  │       ELASTICACHE         ││ │
│  │  │ Docker Images   │  │   Scan Queue    │  │   Redis (Session Cache)   ││ │
│  │  └─────────────────┘  └─────────────────┘  └─────────────────────────────┘│ │
│  │                                                                            │ │
│  └────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

# PHASE 1: AWS ACCOUNT SETUP & PREREQUISITES

## 1.1 AWS Account Configuration

### Step 1: Create/Configure AWS Account
```bash
# Install AWS CLI v2
# Windows: Download from https://aws.amazon.com/cli/
# Verify installation
aws --version

# Configure credentials
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-east-1), Output (json)
```

### Step 2: Enable Required Services
- Navigate to AWS Console → Services
- Enable: EC2, RDS, S3, CloudFront, ECR, ECS, Bedrock, Secrets Manager, VPC

### Step 3: Request Bedrock Model Access
```
1. Go to AWS Console → Amazon Bedrock → Model access
2. Request access to:
   - Anthropic Claude 3.5 Sonnet (recommended for Jarwis)
   - Amazon Titan Text (backup option)
3. Wait for approval (usually instant for Claude)
```

## 1.2 Required IAM Roles & Policies

### Create IAM User for Deployment
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*",
                "rds:*",
                "s3:*",
                "cloudfront:*",
                "ecr:*",
                "ecs:*",
                "elasticloadbalancing:*",
                "bedrock:*",
                "secretsmanager:*",
                "logs:*",
                "sqs:*",
                "elasticache:*",
                "route53:*",
                "iam:PassRole"
            ],
            "Resource": "*"
        }
    ]
}
```

---

# PHASE 2: INFRASTRUCTURE SETUP

## 2.1 VPC & Networking

### Step 1: Create VPC
```bash
# Create VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=jarwis-vpc}]'

# Note the VPC ID returned (vpc-xxxxxxxxx)
```

### Step 2: Create Subnets
```bash
# Public Subnet (for ALB, NAT Gateway)
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.1.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarwis-public-1a}]'

# Public Subnet 2 (ALB requires 2 AZs)
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.4.0/24 --availability-zone us-east-1b --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarwis-public-1b}]'

# Private Subnet (for ECS tasks)
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.2.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarwis-private-1a}]'

# Database Subnet
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.3.0/24 --availability-zone us-east-1a --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarwis-db-1a}]'

# Database Subnet 2 (RDS requires 2 AZs)
aws ec2 create-subnet --vpc-id vpc-xxxxxxxxx --cidr-block 10.0.5.0/24 --availability-zone us-east-1b --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=jarwis-db-1b}]'
```

### Step 3: Internet Gateway & NAT Gateway
```bash
# Create Internet Gateway
aws ec2 create-internet-gateway --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=jarwis-igw}]'
aws ec2 attach-internet-gateway --internet-gateway-id igw-xxxxxxxxx --vpc-id vpc-xxxxxxxxx

# Allocate Elastic IP for NAT Gateway
aws ec2 allocate-address --domain vpc

# Create NAT Gateway in public subnet
aws ec2 create-nat-gateway --subnet-id subnet-public --allocation-id eipalloc-xxxxxxxxx
```

### Step 4: Route Tables
```bash
# Public route table (routes to Internet Gateway)
aws ec2 create-route-table --vpc-id vpc-xxxxxxxxx
aws ec2 create-route --route-table-id rtb-public --destination-cidr-block 0.0.0.0/0 --gateway-id igw-xxxxxxxxx
aws ec2 associate-route-table --route-table-id rtb-public --subnet-id subnet-public-1a
aws ec2 associate-route-table --route-table-id rtb-public --subnet-id subnet-public-1b

# Private route table (routes to NAT Gateway)
aws ec2 create-route-table --vpc-id vpc-xxxxxxxxx
aws ec2 create-route --route-table-id rtb-private --destination-cidr-block 0.0.0.0/0 --nat-gateway-id nat-xxxxxxxxx
aws ec2 associate-route-table --route-table-id rtb-private --subnet-id subnet-private
```

## 2.2 Security Groups

### API Server Security Group
```bash
aws ec2 create-security-group --group-name jarwis-api-sg --description "Jarwis API Security Group" --vpc-id vpc-xxxxxxxxx

# Allow inbound from ALB only (port 8000)
aws ec2 authorize-security-group-ingress --group-id sg-api --protocol tcp --port 8000 --source-group sg-alb

# Allow outbound all (for Bedrock, external scanning)
aws ec2 authorize-security-group-egress --group-id sg-api --protocol all --port all --cidr 0.0.0.0/0
```

### ALB Security Group
```bash
aws ec2 create-security-group --group-name jarwis-alb-sg --description "Jarwis ALB Security Group" --vpc-id vpc-xxxxxxxxx

# Allow HTTPS from anywhere
aws ec2 authorize-security-group-ingress --group-id sg-alb --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-alb --protocol tcp --port 80 --cidr 0.0.0.0/0
```

### RDS Security Group
```bash
aws ec2 create-security-group --group-name jarwis-rds-sg --description "Jarwis RDS Security Group" --vpc-id vpc-xxxxxxxxx

# Allow PostgreSQL from API security group only
aws ec2 authorize-security-group-ingress --group-id sg-rds --protocol tcp --port 5432 --source-group sg-api
```

---

# PHASE 3: DATABASE SETUP (RDS PostgreSQL)

## 3.1 Create RDS Instance

### Step 1: Create DB Subnet Group
```bash
aws rds create-db-subnet-group \
    --db-subnet-group-name jarwis-db-subnet-group \
    --db-subnet-group-description "Jarwis DB Subnet Group" \
    --subnet-ids subnet-db-1a subnet-db-1b
```

### Step 2: Store Credentials in Secrets Manager
```bash
aws secretsmanager create-secret \
    --name jarwis/database/credentials \
    --description "Jarwis RDS PostgreSQL Credentials" \
    --secret-string '{"username":"jarwis_admin","password":"YOUR_SECURE_PASSWORD_HERE"}'
```

### Step 3: Create RDS Instance
```bash
aws rds create-db-instance \
    --db-instance-identifier jarwis-db \
    --db-instance-class db.t3.medium \
    --engine postgres \
    --engine-version 15.4 \
    --master-username jarwis_admin \
    --master-user-password YOUR_SECURE_PASSWORD \
    --allocated-storage 100 \
    --storage-type gp3 \
    --db-subnet-group-name jarwis-db-subnet-group \
    --vpc-security-group-ids sg-rds \
    --db-name jarwis_db \
    --backup-retention-period 7 \
    --multi-az \
    --storage-encrypted \
    --no-publicly-accessible
```

### Server Configuration: RDS
| Setting | Value | Reason |
|---------|-------|--------|
| Instance Class | db.t3.medium | 2 vCPU, 4GB RAM - suitable for medium workloads |
| Storage | 100GB gp3 | Fast SSD with baseline 3000 IOPS |
| Multi-AZ | Yes | High availability |
| Encryption | Yes | Security compliance |

---

# PHASE 4: CONTAINER REGISTRY & DOCKER SETUP

## 4.1 Create ECR Repositories

```bash
# Create repository for API
aws ecr create-repository --repository-name jarwis-api --image-scanning-configuration scanOnPush=true

# Create repository for scan worker
aws ecr create-repository --repository-name jarwis-worker --image-scanning-configuration scanOnPush=true
```

## 4.2 Create Dockerfiles

### Backend API Dockerfile
Create file: `Dockerfile.api`
```dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for Playwright and security tools
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    curl \
    git \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers
RUN playwright install chromium
RUN playwright install-deps chromium

# Copy application code
COPY api/ ./api/
COPY core/ ./core/
COPY attacks/ ./attacks/
COPY database/ ./database/
COPY config/ ./config/
COPY templates/ ./templates/
COPY reports/ ./reports/

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV DB_TYPE=postgresql

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Run the application
CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Scan Worker Dockerfile
Create file: `Dockerfile.worker`
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install security tools
RUN apt-get update && apt-get install -y \
    wget gnupg curl git nmap sqlmap nikto \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium && playwright install-deps chromium

COPY . .

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

CMD ["python", "-m", "core.runner"]
```

## 4.3 Build and Push Images

```bash
# Login to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Build and push API image
docker build -f Dockerfile.api -t jarwis-api:latest .
docker tag jarwis-api:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-api:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-api:latest

# Build and push worker image
docker build -f Dockerfile.worker -t jarwis-worker:latest .
docker tag jarwis-worker:latest YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-worker:latest
docker push YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-worker:latest
```

---

# PHASE 5: AMAZON BEDROCK INTEGRATION (REPLACING OLLAMA)

## 5.1 Code Changes Required

### Update `core/ai_planner.py` - Add Bedrock Provider

Replace the Ollama client initialization with Bedrock support:

```python
# Add to imports
import boto3
from botocore.config import Config

# In AIPlanner.__init__, add Bedrock provider option
def __init__(
    self,
    provider: str = "bedrock",  # Changed default from "ollama" to "bedrock"
    model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",  # Bedrock model ID
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    aws_region: str = "us-east-1"
):
    self.provider = provider
    self.model = model
    self.api_key = api_key
    self.base_url = base_url
    self.aws_region = aws_region
    self._client = None
    self._init_client()

def _init_client(self):
    """Initialize the Jarwis intelligence engine"""
    if self.provider == "bedrock":
        try:
            # Configure boto3 for Bedrock
            config = Config(
                region_name=self.aws_region,
                retries={'max_attempts': 3, 'mode': 'adaptive'}
            )
            self._client = boto3.client(
                'bedrock-runtime',
                config=config
            )
            logger.info(f"Jarwis Bedrock client initialized with model: {self.model}")
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            self._client = None
    elif self.provider == "ollama":
        # ... existing Ollama code ...
```

### Add Bedrock Chat Method

```python
async def _bedrock_chat(self, messages: List[Dict]) -> str:
    """Send chat request to Amazon Bedrock"""
    import json
    
    # Format messages for Claude on Bedrock
    system_message = ""
    formatted_messages = []
    
    for msg in messages:
        if msg["role"] == "system":
            system_message = msg["content"]
        else:
            formatted_messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })
    
    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "system": system_message,
        "messages": formatted_messages
    }
    
    try:
        response = self._client.invoke_model(
            modelId=self.model,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body)
        )
        
        response_body = json.loads(response['body'].read())
        return response_body['content'][0]['text']
        
    except Exception as e:
        logger.error(f"Bedrock API error: {e}")
        raise
```

## 5.2 Environment Variables for Bedrock

```bash
# Set in ECS Task Definition or .env file
AI_PROVIDER=bedrock
AI_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION=us-east-1
# AWS credentials are handled by IAM role (no keys needed in ECS)
```

## 5.3 IAM Policy for Bedrock Access

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel",
                "bedrock:InvokeModelWithResponseStream"
            ],
            "Resource": [
                "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
                "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet*"
            ]
        }
    ]
}
```

## 5.4 Bedrock Model Options

| Model ID | Use Case | Cost (per 1K tokens) |
|----------|----------|---------------------|
| `anthropic.claude-3-5-sonnet-20241022-v2:0` | **Recommended** - Best for security analysis | $0.003 input / $0.015 output |
| `anthropic.claude-3-haiku-20240307-v1:0` | Fast, cheaper alternative | $0.00025 input / $0.00125 output |
| `amazon.titan-text-premier-v1:0` | AWS native option | $0.0005 input / $0.0015 output |

---

# PHASE 6: ECS FARGATE DEPLOYMENT

## 6.1 Create ECS Cluster

```bash
aws ecs create-cluster --cluster-name jarwis-cluster --capacity-providers FARGATE FARGATE_SPOT
```

## 6.2 Create Task Execution Role

```bash
# Create role
aws iam create-role --role-name jarwis-ecs-execution-role --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# Attach policies
aws iam attach-role-policy --role-name jarwis-ecs-execution-role --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
```

## 6.3 Create Task Role (for Bedrock access)

```bash
aws iam create-role --role-name jarwis-task-role --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# Attach Bedrock policy (create custom policy from 5.3)
aws iam put-role-policy --role-name jarwis-task-role --policy-name BedrockAccess --policy-document file://bedrock-policy.json

# Attach Secrets Manager access
aws iam attach-role-policy --role-name jarwis-task-role --policy-arn arn:aws:iam::aws:policy/SecretsManagerReadWrite
```

## 6.4 Task Definition

Create file: `ecs-task-definition.json`
```json
{
    "family": "jarwis-api",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "1024",
    "memory": "2048",
    "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT:role/jarwis-ecs-execution-role",
    "taskRoleArn": "arn:aws:iam::YOUR_ACCOUNT:role/jarwis-task-role",
    "containerDefinitions": [
        {
            "name": "jarwis-api",
            "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/jarwis-api:latest",
            "essential": true,
            "portMappings": [
                {
                    "containerPort": 8000,
                    "protocol": "tcp"
                }
            ],
            "environment": [
                {"name": "DB_TYPE", "value": "postgresql"},
                {"name": "POSTGRES_HOST", "value": "jarwis-db.xxxxxxxxx.us-east-1.rds.amazonaws.com"},
                {"name": "POSTGRES_PORT", "value": "5432"},
                {"name": "POSTGRES_DB", "value": "jarwis_db"},
                {"name": "AI_PROVIDER", "value": "bedrock"},
                {"name": "AI_MODEL", "value": "anthropic.claude-3-5-sonnet-20241022-v2:0"},
                {"name": "AWS_REGION", "value": "us-east-1"}
            ],
            "secrets": [
                {
                    "name": "POSTGRES_USER",
                    "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret:jarwis/database/credentials:username::"
                },
                {
                    "name": "POSTGRES_PASSWORD",
                    "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret:jarwis/database/credentials:password::"
                }
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/jarwis-api",
                    "awslogs-region": "us-east-1",
                    "awslogs-stream-prefix": "ecs"
                }
            },
            "healthCheck": {
                "command": ["CMD-SHELL", "curl -f http://localhost:8000/api/health || exit 1"],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60
            }
        }
    ]
}
```

```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://ecs-task-definition.json
```

## 6.5 Application Load Balancer

```bash
# Create ALB
aws elbv2 create-load-balancer \
    --name jarwis-alb \
    --subnets subnet-public-1a subnet-public-1b \
    --security-groups sg-alb \
    --scheme internet-facing \
    --type application

# Create target group
aws elbv2 create-target-group \
    --name jarwis-api-tg \
    --protocol HTTP \
    --port 8000 \
    --vpc-id vpc-xxxxxxxxx \
    --target-type ip \
    --health-check-path /api/health \
    --health-check-interval-seconds 30

# Create HTTPS listener (requires SSL certificate from ACM)
aws elbv2 create-listener \
    --load-balancer-arn arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT:loadbalancer/app/jarwis-alb/xxxxxxxxx \
    --protocol HTTPS \
    --port 443 \
    --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
    --certificates CertificateArn=arn:aws:acm:us-east-1:YOUR_ACCOUNT:certificate/xxxxxxxxx \
    --default-actions Type=forward,TargetGroupArn=arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT:targetgroup/jarwis-api-tg/xxxxxxxxx
```

## 6.6 Create ECS Service

```bash
aws ecs create-service \
    --cluster jarwis-cluster \
    --service-name jarwis-api-service \
    --task-definition jarwis-api \
    --desired-count 2 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[subnet-private],securityGroups=[sg-api],assignPublicIp=DISABLED}" \
    --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:us-east-1:YOUR_ACCOUNT:targetgroup/jarwis-api-tg/xxxxxxxxx,containerName=jarwis-api,containerPort=8000"
```

### Server Configuration: ECS Fargate
| Setting | Value | Reason |
|---------|-------|--------|
| CPU | 1024 (1 vCPU) | Sufficient for API + light scanning |
| Memory | 2048 MB | Playwright needs ~1GB, plus app overhead |
| Desired Count | 2 | High availability |
| Max Count | 10 | Auto-scaling for heavy scan loads |

---

# PHASE 7: FRONTEND DEPLOYMENT (S3 + CLOUDFRONT)

## 7.1 Update Frontend API Configuration

Update `jarwisfrontend/src/api.js`:
```javascript
// Change from:
const BASE_URL = "https://jarwis-api.onrender.com/api";

// To:
const BASE_URL = process.env.REACT_APP_API_URL || "https://api.jarwis.yourdomain.com/api";
```

Create `jarwisfrontend/.env.production`:
```
REACT_APP_API_URL=https://api.jarwis.yourdomain.com
```

## 7.2 Build Frontend

```bash
cd jarwisfrontend
npm install
npm run build
```

## 7.3 Create S3 Bucket

```bash
# Create bucket
aws s3 mb s3://jarwis-frontend-prod --region us-east-1

# Enable static website hosting
aws s3 website s3://jarwis-frontend-prod --index-document index.html --error-document index.html

# Upload build files
aws s3 sync build/ s3://jarwis-frontend-prod --delete

# Set bucket policy for CloudFront
aws s3api put-bucket-policy --bucket jarwis-frontend-prod --policy '{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "CloudFrontAccess",
        "Effect": "Allow",
        "Principal": {"Service": "cloudfront.amazonaws.com"},
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::jarwis-frontend-prod/*",
        "Condition": {
            "StringEquals": {
                "AWS:SourceArn": "arn:aws:cloudfront::YOUR_ACCOUNT:distribution/XXXXXXXXX"
            }
        }
    }]
}'
```

## 7.4 Create CloudFront Distribution

```bash
aws cloudfront create-distribution --distribution-config '{
    "CallerReference": "jarwis-frontend-'$(date +%s)'",
    "Comment": "Jarwis Frontend",
    "DefaultCacheBehavior": {
        "TargetOriginId": "jarwis-s3",
        "ViewerProtocolPolicy": "redirect-to-https",
        "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
        "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
        "ForwardedValues": {"QueryString": false, "Cookies": {"Forward": "none"}},
        "MinTTL": 0,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "Compress": true
    },
    "Origins": {
        "Quantity": 1,
        "Items": [{
            "Id": "jarwis-s3",
            "DomainName": "jarwis-frontend-prod.s3.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}
        }]
    },
    "Enabled": true,
    "DefaultRootObject": "index.html",
    "CustomErrorResponses": {
        "Quantity": 1,
        "Items": [{
            "ErrorCode": 404,
            "ResponsePagePath": "/index.html",
            "ResponseCode": "200",
            "ErrorCachingMinTTL": 300
        }]
    },
    "Aliases": {"Quantity": 1, "Items": ["jarwis.yourdomain.com"]},
    "ViewerCertificate": {
        "ACMCertificateArn": "arn:aws:acm:us-east-1:YOUR_ACCOUNT:certificate/xxxxxxxxx",
        "SSLSupportMethod": "sni-only",
        "MinimumProtocolVersion": "TLSv1.2_2021"
    }
}'
```

---

# PHASE 8: DNS & SSL SETUP (ROUTE 53)

## 8.1 Request SSL Certificates (ACM)

```bash
# Certificate for frontend (must be in us-east-1 for CloudFront)
aws acm request-certificate \
    --domain-name jarwis.yourdomain.com \
    --validation-method DNS \
    --region us-east-1

# Certificate for API (can be in your preferred region)
aws acm request-certificate \
    --domain-name api.jarwis.yourdomain.com \
    --validation-method DNS \
    --region us-east-1
```

## 8.2 Create DNS Records

```bash
# Create hosted zone (if not exists)
aws route53 create-hosted-zone --name yourdomain.com --caller-reference $(date +%s)

# Add A record for frontend (CloudFront)
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXXXXXXX --change-batch '{
    "Changes": [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": "jarwis.yourdomain.com",
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "Z2FDTNDATAQYW2",
                "DNSName": "dxxxxxxxxxxxxxx.cloudfront.net",
                "EvaluateTargetHealth": false
            }
        }
    }]
}'

# Add A record for API (ALB)
aws route53 change-resource-record-sets --hosted-zone-id ZXXXXXXXXXXXXX --change-batch '{
    "Changes": [{
        "Action": "CREATE",
        "ResourceRecordSet": {
            "Name": "api.jarwis.yourdomain.com",
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "ZXXXXXXXXXXXXXXX",
                "DNSName": "jarwis-alb-xxxxxxxxx.us-east-1.elb.amazonaws.com",
                "EvaluateTargetHealth": true
            }
        }
    }]
}'
```

---

# PHASE 9: MONITORING & LOGGING

## 9.1 CloudWatch Log Groups

```bash
# Create log groups
aws logs create-log-group --log-group-name /ecs/jarwis-api
aws logs create-log-group --log-group-name /ecs/jarwis-worker

# Set retention
aws logs put-retention-policy --log-group-name /ecs/jarwis-api --retention-in-days 30
aws logs put-retention-policy --log-group-name /ecs/jarwis-worker --retention-in-days 30
```

## 9.2 CloudWatch Alarms

```bash
# API health alarm
aws cloudwatch put-metric-alarm \
    --alarm-name jarwis-api-unhealthy \
    --metric-name UnHealthyHostCount \
    --namespace AWS/ApplicationELB \
    --statistic Average \
    --period 60 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 2 \
    --dimensions Name=TargetGroup,Value=targetgroup/jarwis-api-tg/xxxxxxxxx Name=LoadBalancer,Value=app/jarwis-alb/xxxxxxxxx \
    --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT:jarwis-alerts

# High CPU alarm
aws cloudwatch put-metric-alarm \
    --alarm-name jarwis-high-cpu \
    --metric-name CPUUtilization \
    --namespace AWS/ECS \
    --statistic Average \
    --period 300 \
    --threshold 80 \
    --comparison-operator GreaterThanThreshold \
    --evaluation-periods 2 \
    --dimensions Name=ClusterName,Value=jarwis-cluster Name=ServiceName,Value=jarwis-api-service \
    --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT:jarwis-alerts
```

---

# PHASE 10: CI/CD PIPELINE (OPTIONAL BUT RECOMMENDED)

## 10.1 GitHub Actions Workflow

Create `.github/workflows/deploy.yml`:
```yaml
name: Deploy to AWS

on:
  push:
    branches: [main]

env:
  AWS_REGION: us-east-1
  ECR_REPOSITORY: jarwis-api
  ECS_SERVICE: jarwis-api-service
  ECS_CLUSTER: jarwis-cluster

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4

    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: ${{ env.AWS_REGION }}

    - name: Login to Amazon ECR
      id: login-ecr
      uses: aws-actions/amazon-ecr-login@v2

    - name: Build, tag, and push image
      env:
        ECR_REGISTRY: ${{ steps.login-ecr.outputs.registry }}
        IMAGE_TAG: ${{ github.sha }}
      run: |
        docker build -f Dockerfile.api -t $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG .
        docker push $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG
        docker tag $ECR_REGISTRY/$ECR_REPOSITORY:$IMAGE_TAG $ECR_REGISTRY/$ECR_REPOSITORY:latest
        docker push $ECR_REGISTRY/$ECR_REPOSITORY:latest

    - name: Deploy to ECS
      run: |
        aws ecs update-service --cluster $ECS_CLUSTER --service $ECS_SERVICE --force-new-deployment

    - name: Build and Deploy Frontend
      run: |
        cd jarwisfrontend
        npm ci
        npm run build
        aws s3 sync build/ s3://jarwis-frontend-prod --delete
        aws cloudfront create-invalidation --distribution-id ${{ secrets.CLOUDFRONT_DISTRIBUTION_ID }} --paths "/*"
```

---

# DEPLOYMENT CHECKLIST

## Pre-Deployment
- [ ] AWS Account created and configured
- [ ] Bedrock model access approved (Claude 3.5 Sonnet)
- [ ] Domain name registered/available
- [ ] SSL certificates requested in ACM

## Infrastructure
- [ ] VPC and subnets created
- [ ] Security groups configured
- [ ] RDS PostgreSQL instance running
- [ ] ECR repositories created
- [ ] ECS cluster created

## Application
- [ ] Dockerfiles created and tested locally
- [ ] Docker images built and pushed to ECR
- [ ] Task definitions registered
- [ ] ECS services running
- [ ] ALB configured with HTTPS

## Frontend
- [ ] Frontend built with production API URL
- [ ] S3 bucket created and configured
- [ ] CloudFront distribution created
- [ ] DNS records configured

## Post-Deployment
- [ ] Health checks passing
- [ ] Database migrations run
- [ ] Bedrock integration tested
- [ ] End-to-end scan test completed
- [ ] Monitoring alarms configured

---

# ESTIMATED MONTHLY COSTS

| Service | Configuration | Est. Monthly Cost |
|---------|--------------|-------------------|
| ECS Fargate | 2 tasks × 1 vCPU × 2GB | $70 |
| RDS PostgreSQL | db.t3.medium, Multi-AZ | $120 |
| Application Load Balancer | Per hour + LCU | $25 |
| NAT Gateway | Per hour + data | $45 |
| S3 + CloudFront | 10GB storage, 100GB transfer | $15 |
| Amazon Bedrock | ~500K tokens/month | $10 |
| Secrets Manager | 2 secrets | $1 |
| CloudWatch | Logs + alarms | $10 |
| Route 53 | Hosted zone + queries | $2 |
| **TOTAL** | | **~$300/month** |

### Cost Optimization Tips
1. Use FARGATE_SPOT for scan workers (up to 70% savings)
2. Use Reserved Capacity for RDS (up to 60% savings for 1-year)
3. Enable S3 Intelligent-Tiering for reports
4. Use CloudFront caching to reduce origin requests
5. Consider single-AZ RDS for non-production

---

# TROUBLESHOOTING

## Common Issues

### 1. ECS Task Fails to Start
```bash
# Check logs
aws logs get-log-events --log-group-name /ecs/jarwis-api --log-stream-name ecs/jarwis-api/TASK_ID

# Common causes:
# - Database connection refused: Check security group rules
# - Image pull failed: Check ECR permissions
# - Memory exceeded: Increase task memory
```

### 2. Bedrock Access Denied
```bash
# Verify IAM role has Bedrock permissions
aws iam get-role-policy --role-name jarwis-task-role --policy-name BedrockAccess

# Ensure model is enabled in Bedrock console
```

### 3. Database Connection Issues
```bash
# Test from ECS task
aws ecs execute-command --cluster jarwis-cluster --task TASK_ID --container jarwis-api --interactive --command "/bin/sh"
# Then: nc -zv jarwis-db.xxx.rds.amazonaws.com 5432
```

### 4. Frontend CORS Errors
- Ensure ALB has correct CORS headers
- Verify API URL in frontend matches ALB domain
- Check CloudFront behavior settings

---

# FILE ORGANIZATION FOR DEPLOYMENT

```
jarwis-ai-pentest/
├── Dockerfile.api           # API container
├── Dockerfile.worker        # Scan worker container
├── docker-compose.yml       # Local testing
├── .github/
│   └── workflows/
│       └── deploy.yml       # CI/CD pipeline
├── infrastructure/
│   ├── cloudformation/      # (Optional) IaC templates
│   │   ├── vpc.yaml
│   │   ├── rds.yaml
│   │   ├── ecs.yaml
│   │   └── frontend.yaml
│   ├── ecs-task-definition.json
│   └── bedrock-policy.json
├── api/                     # → Deployed in ECS
├── core/                    # → Deployed in ECS
├── attacks/                 # → Deployed in ECS
├── database/                # → Deployed in ECS
├── config/                  # → Deployed in ECS
├── jarwisfrontend/
│   └── build/              # → Deployed to S3
└── docs/
    └── deployplan.pdf      # This document
```

---

# CONCLUSION

This deployment plan provides a complete, production-ready AWS infrastructure for JARWIS AGI Penetration Testing Framework. The architecture ensures:

1. **High Availability**: Multi-AZ deployment, auto-scaling ECS
2. **Security**: Private subnets, encrypted database, IAM roles
3. **Performance**: CloudFront CDN, Bedrock for fast AI inference
4. **Cost Efficiency**: Fargate Spot, proper sizing recommendations
5. **Observability**: CloudWatch logs, metrics, and alarms

Follow the phases in order for a successful deployment. Each phase builds upon the previous one, ensuring a stable and secure infrastructure.

---

*Document generated for JARWIS AGI Pentest v1.0 - AWS Deployment*
*Date: January 4, 2026*
