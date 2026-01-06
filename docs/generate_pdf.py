"""
Generate PDF from deployment plan markdown
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Preformatted, Image
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import re
import os

def create_deployment_plan_pdf():
    """Generate the deployment plan PDF"""
    
    # Output path
    output_path = os.path.join(os.path.dirname(__file__), 'deployplan.pdf')
    
    # Create document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=0.75*inch,
        leftMargin=0.75*inch,
        topMargin=0.75*inch,
        bottomMargin=0.75*inch
    )
    
    # Styles
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=20,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#1a365d')
    )
    
    h1_style = ParagraphStyle(
        'H1',
        parent=styles['Heading1'],
        fontSize=18,
        spaceBefore=20,
        spaceAfter=10,
        textColor=colors.HexColor('#2c5282')
    )
    
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=8,
        textColor=colors.HexColor('#2b6cb0')
    )
    
    h3_style = ParagraphStyle(
        'H3',
        parent=styles['Heading3'],
        fontSize=12,
        spaceBefore=10,
        spaceAfter=6,
        textColor=colors.HexColor('#3182ce')
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontSize=10,
        spaceBefore=4,
        spaceAfter=4,
        alignment=TA_JUSTIFY
    )
    
    code_style = ParagraphStyle(
        'Code',
        parent=styles['Code'],
        fontSize=8,
        fontName='Courier',
        backColor=colors.HexColor('#f7fafc'),
        borderColor=colors.HexColor('#e2e8f0'),
        borderWidth=1,
        borderPadding=5,
        spaceBefore=5,
        spaceAfter=5
    )
    
    bullet_style = ParagraphStyle(
        'Bullet',
        parent=styles['Normal'],
        fontSize=10,
        leftIndent=20,
        spaceBefore=2,
        spaceAfter=2
    )
    
    # Build document content
    story = []
    
    # Title Page
    story.append(Spacer(1, 2*inch))
    story.append(Paragraph("JARWIS AI PENTEST", title_style))
    story.append(Paragraph("AWS Deployment Plan", ParagraphStyle(
        'Subtitle',
        parent=styles['Heading2'],
        fontSize=16,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#4a5568')
    )))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("Comprehensive Step-by-Step Guide", ParagraphStyle(
        'SubSubtitle',
        parent=styles['Normal'],
        fontSize=12,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#718096')
    )))
    story.append(Spacer(1, 1*inch))
    
    # Document info table
    doc_info = [
        ['Version:', '1.0'],
        ['Date:', 'January 4, 2026'],
        ['Project:', 'Jarwis AI Penetration Testing Framework'],
        ['Platform:', 'Amazon Web Services (AWS)'],
    ]
    doc_table = Table(doc_info, colWidths=[1.5*inch, 3*inch])
    doc_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(doc_table)
    story.append(PageBreak())
    
    # Table of Contents
    story.append(Paragraph("TABLE OF CONTENTS", h1_style))
    story.append(Spacer(1, 0.25*inch))
    
    toc_items = [
        "1. Executive Summary",
        "2. High-Level Architecture",
        "3. Phase 1: AWS Account Setup & Prerequisites",
        "4. Phase 2: Infrastructure Setup (VPC, Subnets, Security Groups)",
        "5. Phase 3: Database Setup (RDS PostgreSQL)",
        "6. Phase 4: Container Registry & Docker Setup",
        "7. Phase 5: Amazon Bedrock Integration",
        "8. Phase 6: ECS Fargate Deployment",
        "9. Phase 7: Frontend Deployment (S3 + CloudFront)",
        "10. Phase 8: DNS & SSL Setup",
        "11. Phase 9: Monitoring & Logging",
        "12. Phase 10: CI/CD Pipeline",
        "13. Deployment Checklist",
        "14. Estimated Monthly Costs",
        "15. Troubleshooting Guide",
    ]
    
    for item in toc_items:
        story.append(Paragraph(f"• {item}", bullet_style))
    
    story.append(PageBreak())
    
    # Executive Summary
    story.append(Paragraph("1. EXECUTIVE SUMMARY", h1_style))
    story.append(Paragraph(
        "This document provides a comprehensive step-by-step guide to deploy the Jarwis AI Penetration Testing Framework on AWS infrastructure. The deployment architecture includes:",
        body_style
    ))
    story.append(Spacer(1, 0.1*inch))
    
    summary_items = [
        "• <b>Backend API</b> (FastAPI/Python) deployed on ECS Fargate",
        "• <b>Frontend</b> (React) hosted on S3 with CloudFront CDN",
        "• <b>Database</b> (PostgreSQL) on Amazon RDS with Multi-AZ",
        "• <b>AI/LLM</b> powered by Amazon Bedrock (replacing Ollama)",
        "• <b>Security scanning infrastructure</b> with proper network isolation",
    ]
    for item in summary_items:
        story.append(Paragraph(item, bullet_style))
    
    story.append(Spacer(1, 0.25*inch))
    
    # High-Level Architecture
    story.append(Paragraph("2. HIGH-LEVEL ARCHITECTURE", h1_style))
    story.append(Paragraph(
        "The following diagram illustrates the complete AWS infrastructure for Jarwis:",
        body_style
    ))
    story.append(Spacer(1, 0.1*inch))
    
    # Architecture as table representation
    arch_data = [
        ['Component', 'AWS Service', 'Configuration'],
        ['Frontend', 'S3 + CloudFront', 'Static React build with global CDN'],
        ['API Gateway', 'Application Load Balancer', 'HTTPS termination, health checks'],
        ['Backend API', 'ECS Fargate', '2 tasks, 1 vCPU, 2GB RAM each'],
        ['AI Engine', 'Amazon Bedrock', 'Claude 3.5 Sonnet model'],
        ['Database', 'RDS PostgreSQL', 'db.t3.medium, Multi-AZ, encrypted'],
        ['Secrets', 'Secrets Manager', 'Database credentials, API keys'],
        ['Monitoring', 'CloudWatch', 'Logs, metrics, alarms'],
        ['DNS', 'Route 53', 'Domain routing'],
    ]
    
    arch_table = Table(arch_data, colWidths=[1.5*inch, 1.8*inch, 3*inch])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(arch_table)
    story.append(PageBreak())
    
    # Network Architecture
    story.append(Paragraph("Network Architecture", h2_style))
    
    network_data = [
        ['Subnet', 'CIDR Block', 'Purpose'],
        ['VPC', '10.0.0.0/16', 'Main virtual private cloud'],
        ['Public Subnet 1a', '10.0.1.0/24', 'ALB, NAT Gateway'],
        ['Public Subnet 1b', '10.0.4.0/24', 'ALB (Multi-AZ)'],
        ['Private Subnet', '10.0.2.0/24', 'ECS Fargate tasks'],
        ['Database Subnet 1a', '10.0.3.0/24', 'RDS Primary'],
        ['Database Subnet 1b', '10.0.5.0/24', 'RDS Standby (Multi-AZ)'],
    ]
    
    network_table = Table(network_data, colWidths=[1.8*inch, 1.5*inch, 3*inch])
    network_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(network_table)
    story.append(Spacer(1, 0.25*inch))
    
    # Phase 1
    story.append(Paragraph("3. PHASE 1: AWS ACCOUNT SETUP", h1_style))
    
    story.append(Paragraph("3.1 Prerequisites", h2_style))
    prereq_items = [
        "• AWS Account with billing enabled",
        "• AWS CLI v2 installed and configured",
        "• Docker Desktop installed",
        "• Node.js 18+ for frontend build",
        "• Domain name (optional but recommended)",
    ]
    for item in prereq_items:
        story.append(Paragraph(item, bullet_style))
    
    story.append(Paragraph("3.2 Enable Required AWS Services", h2_style))
    story.append(Paragraph("Navigate to AWS Console and enable:", body_style))
    services = ["EC2", "VPC", "RDS", "S3", "CloudFront", "ECR", "ECS", "Amazon Bedrock", "Secrets Manager", "CloudWatch", "Route 53", "ACM (Certificate Manager)"]
    story.append(Paragraph(", ".join(services), bullet_style))
    
    story.append(Paragraph("3.3 Request Bedrock Model Access", h2_style))
    story.append(Paragraph(
        "Important: Amazon Bedrock requires explicit model access approval. Navigate to Amazon Bedrock → Model access → Request access to 'Anthropic Claude 3.5 Sonnet'. Approval is typically instant.",
        body_style
    ))
    
    story.append(PageBreak())
    
    # Phase 2
    story.append(Paragraph("4. PHASE 2: INFRASTRUCTURE SETUP", h1_style))
    
    story.append(Paragraph("4.1 Create VPC", h2_style))
    story.append(Paragraph("Command:", body_style))
    story.append(Preformatted(
        "aws ec2 create-vpc --cidr-block 10.0.0.0/16 \\\n    --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=jarwis-vpc}]'",
        code_style
    ))
    
    story.append(Paragraph("4.2 Create Subnets", h2_style))
    story.append(Paragraph(
        "Create 5 subnets across 2 availability zones for high availability:",
        body_style
    ))
    story.append(Preformatted(
        "# Public Subnet 1a\naws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.1.0/24 \\\n    --availability-zone us-east-1a\n\n# Private Subnet\naws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.2.0/24 \\\n    --availability-zone us-east-1a\n\n# Database Subnets (2 required for RDS)\naws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.3.0/24 \\\n    --availability-zone us-east-1a\naws ec2 create-subnet --vpc-id vpc-xxx --cidr-block 10.0.5.0/24 \\\n    --availability-zone us-east-1b",
        code_style
    ))
    
    story.append(Paragraph("4.3 Security Groups", h2_style))
    
    sg_data = [
        ['Security Group', 'Inbound Rules', 'Purpose'],
        ['jarwis-alb-sg', 'TCP 443, 80 from 0.0.0.0/0', 'Allow HTTPS/HTTP to load balancer'],
        ['jarwis-api-sg', 'TCP 8000 from ALB SG only', 'API access from load balancer'],
        ['jarwis-rds-sg', 'TCP 5432 from API SG only', 'Database from API only'],
    ]
    
    sg_table = Table(sg_data, colWidths=[1.5*inch, 2.5*inch, 2.3*inch])
    sg_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(sg_table)
    
    story.append(PageBreak())
    
    # Phase 3 - Database
    story.append(Paragraph("5. PHASE 3: DATABASE SETUP (RDS)", h1_style))
    
    story.append(Paragraph("5.1 Store Credentials in Secrets Manager", h2_style))
    story.append(Preformatted(
        'aws secretsmanager create-secret \\\n    --name jarwis/database/credentials \\\n    --secret-string \'{"username":"jarwis_admin","password":"YOUR_SECURE_PASSWORD"}\'',
        code_style
    ))
    
    story.append(Paragraph("5.2 Create RDS Instance", h2_style))
    story.append(Preformatted(
        "aws rds create-db-instance \\\n    --db-instance-identifier jarwis-db \\\n    --db-instance-class db.t3.medium \\\n    --engine postgres \\\n    --engine-version 15.4 \\\n    --allocated-storage 100 \\\n    --storage-type gp3 \\\n    --multi-az \\\n    --storage-encrypted \\\n    --no-publicly-accessible",
        code_style
    ))
    
    story.append(Paragraph("5.3 RDS Configuration", h2_style))
    rds_config = [
        ['Setting', 'Value', 'Reason'],
        ['Instance Class', 'db.t3.medium', '2 vCPU, 4GB RAM - suitable for medium workloads'],
        ['Storage', '100GB gp3', 'Fast SSD with baseline 3000 IOPS'],
        ['Multi-AZ', 'Yes', 'High availability with automatic failover'],
        ['Encryption', 'Yes', 'Security compliance requirement'],
        ['Backup Retention', '7 days', 'Point-in-time recovery'],
    ]
    
    rds_table = Table(rds_config, colWidths=[1.5*inch, 1.5*inch, 3.3*inch])
    rds_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(rds_table)
    
    story.append(PageBreak())
    
    # Phase 4 - Docker
    story.append(Paragraph("6. PHASE 4: DOCKER & ECR SETUP", h1_style))
    
    story.append(Paragraph("6.1 Create ECR Repositories", h2_style))
    story.append(Preformatted(
        "aws ecr create-repository --repository-name jarwis-api \\\n    --image-scanning-configuration scanOnPush=true\n\naws ecr create-repository --repository-name jarwis-worker \\\n    --image-scanning-configuration scanOnPush=true",
        code_style
    ))
    
    story.append(Paragraph("6.2 Dockerfile.api (Backend)", h2_style))
    story.append(Preformatted(
        "FROM python:3.11-slim\nWORKDIR /app\n\n# Install system dependencies\nRUN apt-get update && apt-get install -y wget curl nmap\n\n# Install Python dependencies\nCOPY requirements.txt .\nRUN pip install --no-cache-dir -r requirements.txt\n\n# Install Playwright\nRUN playwright install chromium\nRUN playwright install-deps chromium\n\n# Copy application\nCOPY api/ ./api/\nCOPY core/ ./core/\nCOPY attacks/ ./attacks/\nCOPY database/ ./database/\n\nEXPOSE 8000\nCMD [\"uvicorn\", \"api.app:app\", \"--host\", \"0.0.0.0\", \"--port\", \"8000\"]",
        code_style
    ))
    
    story.append(Paragraph("6.3 Build and Push", h2_style))
    story.append(Preformatted(
        "# Login to ECR\naws ecr get-login-password --region us-east-1 | docker login --username AWS \\\n    --password-stdin ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com\n\n# Build and push\ndocker build -f Dockerfile.api -t jarwis-api:latest .\ndocker tag jarwis-api:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-api:latest\ndocker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/jarwis-api:latest",
        code_style
    ))
    
    story.append(PageBreak())
    
    # Phase 5 - Bedrock
    story.append(Paragraph("7. PHASE 5: AMAZON BEDROCK INTEGRATION", h1_style))
    story.append(Paragraph(
        "This section explains how to replace Ollama with Amazon Bedrock for AI-powered security analysis.",
        body_style
    ))
    
    story.append(Paragraph("7.1 Bedrock Model Selection", h2_style))
    
    bedrock_models = [
        ['Model ID', 'Use Case', 'Cost (per 1K tokens)'],
        ['anthropic.claude-3-5-sonnet-20241022-v2:0', 'RECOMMENDED - Best for security analysis', '$0.003 / $0.015'],
        ['anthropic.claude-3-haiku-20240307-v1:0', 'Fast, cheaper alternative', '$0.00025 / $0.00125'],
        ['amazon.titan-text-premier-v1:0', 'AWS native option', '$0.0005 / $0.0015'],
    ]
    
    bedrock_table = Table(bedrock_models, colWidths=[3*inch, 2*inch, 1.3*inch])
    bedrock_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#c6f6d5')),
        ('ROWBACKGROUNDS', (0, 2), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(bedrock_table)
    
    story.append(Paragraph("7.2 Code Changes to ai_planner.py", h2_style))
    story.append(Preformatted(
        '# Add to imports\nimport boto3\nfrom botocore.config import Config\n\n# Initialize Bedrock client\nconfig = Config(region_name="us-east-1")\nclient = boto3.client("bedrock-runtime", config=config)\n\n# Invoke model\nresponse = client.invoke_model(\n    modelId="anthropic.claude-3-5-sonnet-20241022-v2:0",\n    contentType="application/json",\n    body=json.dumps({\n        "anthropic_version": "bedrock-2023-05-31",\n        "max_tokens": 4096,\n        "messages": messages\n    })\n)',
        code_style
    ))
    
    story.append(Paragraph("7.3 IAM Policy for Bedrock", h2_style))
    story.append(Preformatted(
        '{\n    "Version": "2012-10-17",\n    "Statement": [{\n        "Effect": "Allow",\n        "Action": [\n            "bedrock:InvokeModel",\n            "bedrock:InvokeModelWithResponseStream"\n        ],\n        "Resource": [\n            "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-*"\n        ]\n    }]\n}',
        code_style
    ))
    
    story.append(PageBreak())
    
    # Phase 6 - ECS
    story.append(Paragraph("8. PHASE 6: ECS FARGATE DEPLOYMENT", h1_style))
    
    story.append(Paragraph("8.1 Create ECS Cluster", h2_style))
    story.append(Preformatted(
        "aws ecs create-cluster --cluster-name jarwis-cluster \\\n    --capacity-providers FARGATE FARGATE_SPOT",
        code_style
    ))
    
    story.append(Paragraph("8.2 Task Definition Configuration", h2_style))
    
    ecs_config = [
        ['Setting', 'Value', 'Reason'],
        ['CPU', '1024 (1 vCPU)', 'Sufficient for API + light scanning'],
        ['Memory', '2048 MB', 'Playwright needs ~1GB + app overhead'],
        ['Desired Count', '2', 'High availability'],
        ['Max Count', '10', 'Auto-scaling for heavy scan loads'],
        ['Launch Type', 'FARGATE', 'Serverless, no EC2 management'],
    ]
    
    ecs_table = Table(ecs_config, colWidths=[1.5*inch, 1.5*inch, 3.3*inch])
    ecs_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(ecs_table)
    
    story.append(Paragraph("8.3 Environment Variables", h2_style))
    env_vars = [
        ['Variable', 'Value'],
        ['DB_TYPE', 'postgresql'],
        ['POSTGRES_HOST', 'jarwis-db.xxx.rds.amazonaws.com'],
        ['AI_PROVIDER', 'bedrock'],
        ['AI_MODEL', 'anthropic.claude-3-5-sonnet-20241022-v2:0'],
        ['AWS_REGION', 'us-east-1'],
    ]
    
    env_table = Table(env_vars, colWidths=[2*inch, 4.3*inch])
    env_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#553c9a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(env_table)
    
    story.append(PageBreak())
    
    # Phase 7 - Frontend
    story.append(Paragraph("9. PHASE 7: FRONTEND DEPLOYMENT", h1_style))
    
    story.append(Paragraph("9.1 Update API Configuration", h2_style))
    story.append(Paragraph("Modify jarwisfrontend/src/api.js:", body_style))
    story.append(Preformatted(
        '// Change from:\nconst BASE_URL = "https://jarwis-api.onrender.com/api";\n\n// To:\nconst BASE_URL = process.env.REACT_APP_API_URL || "https://api.jarwis.yourdomain.com/api";',
        code_style
    ))
    
    story.append(Paragraph("9.2 Build and Deploy to S3", h2_style))
    story.append(Preformatted(
        "cd jarwisfrontend\nnpm install\nnpm run build\n\n# Create S3 bucket\naws s3 mb s3://jarwis-frontend-prod\n\n# Upload build\naws s3 sync build/ s3://jarwis-frontend-prod --delete",
        code_style
    ))
    
    story.append(Paragraph("9.3 CloudFront Distribution", h2_style))
    story.append(Paragraph(
        "Create CloudFront distribution pointing to S3 bucket with:",
        body_style
    ))
    cf_items = [
        "• HTTPS only (redirect HTTP to HTTPS)",
        "• Custom SSL certificate from ACM",
        "• Error page redirect to index.html for SPA routing",
        "• Gzip compression enabled",
        "• Cache TTL: 86400 seconds (1 day)",
    ]
    for item in cf_items:
        story.append(Paragraph(item, bullet_style))
    
    story.append(PageBreak())
    
    # Phase 8 - DNS
    story.append(Paragraph("10. PHASE 8: DNS & SSL SETUP", h1_style))
    
    story.append(Paragraph("10.1 Request SSL Certificates", h2_style))
    story.append(Preformatted(
        "# Frontend certificate (MUST be in us-east-1 for CloudFront)\naws acm request-certificate --domain-name jarwis.yourdomain.com \\\n    --validation-method DNS --region us-east-1\n\n# API certificate\naws acm request-certificate --domain-name api.jarwis.yourdomain.com \\\n    --validation-method DNS --region us-east-1",
        code_style
    ))
    
    story.append(Paragraph("10.2 DNS Records (Route 53)", h2_style))
    dns_records = [
        ['Record', 'Type', 'Target'],
        ['jarwis.yourdomain.com', 'A (Alias)', 'CloudFront distribution'],
        ['api.jarwis.yourdomain.com', 'A (Alias)', 'Application Load Balancer'],
    ]
    
    dns_table = Table(dns_records, colWidths=[2.5*inch, 1.2*inch, 2.6*inch])
    dns_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(dns_table)
    
    story.append(PageBreak())
    
    # Deployment Checklist
    story.append(Paragraph("13. DEPLOYMENT CHECKLIST", h1_style))
    
    checklist_data = [
        ['Phase', 'Task', 'Status'],
        ['Pre-Deploy', 'AWS Account configured', '☐'],
        ['Pre-Deploy', 'Bedrock model access approved', '☐'],
        ['Pre-Deploy', 'Domain name available', '☐'],
        ['Infrastructure', 'VPC and subnets created', '☐'],
        ['Infrastructure', 'Security groups configured', '☐'],
        ['Database', 'RDS instance running', '☐'],
        ['Database', 'Credentials in Secrets Manager', '☐'],
        ['Containers', 'ECR repositories created', '☐'],
        ['Containers', 'Docker images pushed', '☐'],
        ['ECS', 'Cluster created', '☐'],
        ['ECS', 'Task definitions registered', '☐'],
        ['ECS', 'Services running', '☐'],
        ['Frontend', 'S3 bucket created', '☐'],
        ['Frontend', 'CloudFront distribution active', '☐'],
        ['DNS/SSL', 'Certificates issued', '☐'],
        ['DNS/SSL', 'DNS records configured', '☐'],
        ['Testing', 'Health checks passing', '☐'],
        ['Testing', 'End-to-end scan completed', '☐'],
    ]
    
    checklist_table = Table(checklist_data, colWidths=[1.5*inch, 3.5*inch, 1.3*inch])
    checklist_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('ALIGN', (2, 0), (2, -1), 'CENTER'),
    ]))
    story.append(checklist_table)
    
    story.append(PageBreak())
    
    # Cost Estimation
    story.append(Paragraph("14. ESTIMATED MONTHLY COSTS", h1_style))
    
    cost_data = [
        ['Service', 'Configuration', 'Est. Monthly Cost'],
        ['ECS Fargate', '2 tasks × 1 vCPU × 2GB', '$70'],
        ['RDS PostgreSQL', 'db.t3.medium, Multi-AZ', '$120'],
        ['Application Load Balancer', 'Per hour + LCU', '$25'],
        ['NAT Gateway', 'Per hour + data transfer', '$45'],
        ['S3 + CloudFront', '10GB storage, 100GB transfer', '$15'],
        ['Amazon Bedrock', '~500K tokens/month', '$10'],
        ['Secrets Manager', '2 secrets', '$1'],
        ['CloudWatch', 'Logs + alarms', '$10'],
        ['Route 53', 'Hosted zone + queries', '$2'],
        ['TOTAL', '', '$298/month'],
    ]
    
    cost_table = Table(cost_data, colWidths=[2.2*inch, 2.5*inch, 1.6*inch])
    cost_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5282')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, colors.HexColor('#f7fafc')]),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#c6f6d5')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
    ]))
    story.append(cost_table)
    
    story.append(Spacer(1, 0.25*inch))
    story.append(Paragraph("Cost Optimization Tips", h2_style))
    tips = [
        "• Use FARGATE_SPOT for scan workers (up to 70% savings)",
        "• Use Reserved Capacity for RDS (up to 60% savings for 1-year commitment)",
        "• Enable S3 Intelligent-Tiering for reports storage",
        "• Use CloudFront caching to reduce origin requests",
        "• Consider single-AZ RDS for development/staging environments",
    ]
    for tip in tips:
        story.append(Paragraph(tip, bullet_style))
    
    story.append(PageBreak())
    
    # Troubleshooting
    story.append(Paragraph("15. TROUBLESHOOTING GUIDE", h1_style))
    
    story.append(Paragraph("15.1 ECS Task Fails to Start", h2_style))
    story.append(Paragraph("Check CloudWatch logs:", body_style))
    story.append(Preformatted(
        "aws logs get-log-events --log-group-name /ecs/jarwis-api \\\n    --log-stream-name ecs/jarwis-api/TASK_ID",
        code_style
    ))
    story.append(Paragraph("Common causes:", body_style))
    story.append(Paragraph("• Database connection refused → Check security group rules", bullet_style))
    story.append(Paragraph("• Image pull failed → Verify ECR permissions", bullet_style))
    story.append(Paragraph("• Memory exceeded → Increase task memory in task definition", bullet_style))
    
    story.append(Paragraph("15.2 Bedrock Access Denied", h2_style))
    story.append(Paragraph("Verify IAM role has Bedrock permissions:", body_style))
    story.append(Preformatted(
        "aws iam get-role-policy --role-name jarwis-task-role \\\n    --policy-name BedrockAccess",
        code_style
    ))
    story.append(Paragraph("Ensure model is enabled in Bedrock console under Model Access.", body_style))
    
    story.append(Paragraph("15.3 Frontend CORS Errors", h2_style))
    story.append(Paragraph("Checklist:", body_style))
    story.append(Paragraph("• Ensure ALB has correct CORS headers configured", bullet_style))
    story.append(Paragraph("• Verify API URL in frontend matches ALB domain exactly", bullet_style))
    story.append(Paragraph("• Check CloudFront behavior settings allow OPTIONS method", bullet_style))
    
    story.append(Spacer(1, 0.5*inch))
    
    # Footer
    story.append(Paragraph("—" * 60, ParagraphStyle('Line', alignment=TA_CENTER)))
    story.append(Spacer(1, 0.25*inch))
    story.append(Paragraph(
        "Document generated for Jarwis AI Pentest v1.0 - AWS Deployment",
        ParagraphStyle('Footer', fontSize=9, alignment=TA_CENTER, textColor=colors.gray)
    ))
    story.append(Paragraph(
        "Date: January 4, 2026",
        ParagraphStyle('Footer', fontSize=9, alignment=TA_CENTER, textColor=colors.gray)
    ))
    
    # Build PDF
    doc.build(story)
    print(f"✅ PDF generated successfully: {output_path}")
    return output_path


if __name__ == "__main__":
    create_deployment_plan_pdf()
