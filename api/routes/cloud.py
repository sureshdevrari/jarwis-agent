"""
Jarwis AGI - Cloud Scan API Routes
Start cloud security scans, get results, manage scan lifecycle
"""

import uuid as uuid_lib
import logging
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from database.subscription import (
    enforce_subscription_limit,
    SubscriptionAction,
    increment_usage_counter,
    decrement_usage_counter,
    has_feature
)
from database import crud

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/cloud", tags=["Cloud Security Scans"])

# In-memory store for cloud scan jobs
cloud_scan_jobs: dict = {}
cloud_scan_logs: dict = {}


# ========== Pydantic Models ==========

class AWSCredentials(BaseModel):
    """AWS credentials for scanning - supports both legacy and enterprise modes"""
    # Enterprise mode (recommended) - Cross-account role
    role_arn: Optional[str] = None
    external_id: Optional[str] = None
    
    # Legacy mode - Direct credentials
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    
    # Common
    region: str = "us-east-1"


class AzureCredentials(BaseModel):
    """Azure credentials for scanning - supports multi-subscription"""
    subscription_id: Optional[str] = None  # Single subscription (legacy)
    subscription_ids: Optional[List[str]] = None  # Multiple subscriptions
    tenant_id: str
    client_id: str
    client_secret: str


class GCPCredentials(BaseModel):
    """GCP credentials for scanning - supports multiple auth modes"""
    project_id: Optional[str] = None  # Single project (legacy)
    project_ids: Optional[List[str]] = None  # Multiple projects
    
    # Legacy mode - Service account JSON
    service_account_key: Optional[str] = None
    
    # Enterprise mode - Workload Identity Federation
    workload_identity_pool: Optional[str] = None
    workload_identity_provider: Optional[str] = None
    service_account_email: Optional[str] = None


class CloudScanRequest(BaseModel):
    """Cloud scan request with service selection"""
    provider: str = Field(..., pattern="^(aws|azure|gcp)$")
    credentials: dict = Field(...)
    regions: Optional[List[str]] = None
    services: Optional[List[str]] = None  # Specific services to scan
    notes: Optional[str] = None


class CloudScanResponse(BaseModel):
    """Cloud scan response"""
    scan_id: str
    status: str
    message: str
    provider: str
    auth_mode: Optional[str] = None  # 'direct', 'assume_role', 'service_principal', etc.
    services: Optional[List[str]] = None  # Services being scanned
    external_id: Optional[str] = None  # For AWS role assumption


class CloudScanStatusResponse(BaseModel):
    """Cloud scan status response"""
    scan_id: str
    status: str
    progress: int
    phase: str
    provider: str
    account_id: str
    findings_count: int
    started_at: str
    completed_at: Optional[str] = None


class CloudServiceInfo(BaseModel):
    """Information about an available cloud service"""
    id: str
    name: str
    description: str
    is_global: bool = False


class AvailableServicesResponse(BaseModel):
    """Response with available services per provider"""
    provider: str
    services: List[CloudServiceInfo]


class OnboardingTemplateResponse(BaseModel):
    """Response with onboarding template"""
    provider: str
    template_type: str
    template_name: str
    template_content: str
    instructions: str
    external_id: Optional[str] = None  # Generated for AWS


# ========== Service & Template Endpoints ==========

@router.get("/services/{provider}", response_model=AvailableServicesResponse)
async def get_available_services(
    provider: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get available services for a cloud provider that can be scanned"""
    provider = provider.lower()
    
    if provider == "aws":
        from attacks.cloud.aws_scanner import AWSSecurityScanner
        services_dict = AWSSecurityScanner.get_available_services()
    elif provider == "azure":
        from attacks.cloud.azure_scanner_complete import AzureSecurityScanner
        services_dict = AzureSecurityScanner.get_available_services()
    elif provider == "gcp":
        from attacks.cloud.gcp_scanner import GCPSecurityScanner
        services_dict = GCPSecurityScanner.get_available_services()
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}"
        )
    
    services = [
        CloudServiceInfo(
            id=svc_id,
            name=svc_info['name'],
            description=svc_info['description'],
            is_global=svc_info.get('global', False)
        )
        for svc_id, svc_info in services_dict.items()
    ]
    
    return AvailableServicesResponse(provider=provider, services=services)


@router.get("/onboarding-template/{provider}", response_model=OnboardingTemplateResponse)
async def get_onboarding_template(
    provider: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get onboarding template for a cloud provider"""
    import uuid
    provider = provider.lower()
    templates_dir = Path(__file__).parent.parent.parent / "templates" / "cloud-onboarding"
    
    # Generate external ID for AWS
    external_id = f"jarwis-{uuid.uuid4().hex[:16]}" if provider == "aws" else None
    
    if provider == "aws":
        template_path = templates_dir / "aws-trust-role.yaml"
        template_type = "cloudformation"
        template_name = "Jarwis AWS Cross-Account Role"
        instructions = """
1. Log into AWS Console as an administrator
2. Go to CloudFormation > Create Stack > With new resources
3. Upload this template or paste the content
4. Enter the External ID shown below
5. Complete the stack creation
6. Copy the Role ARN from the Outputs tab
7. Paste the Role ARN in Jarwis Cloud Scan configuration
"""
    elif provider == "azure":
        template_path = templates_dir / "azure-service-principal-setup.ps1"
        template_type = "powershell"
        template_name = "Jarwis Azure Service Principal Setup"
        instructions = """
1. Open Azure Cloud Shell or local PowerShell with Azure CLI
2. Run this script: ./azure-service-principal-setup.ps1
3. Follow the prompts to create the service principal
4. Copy the output credentials into Jarwis Cloud Scan configuration
"""
    elif provider == "gcp":
        template_path = templates_dir / "gcp-service-account-setup.sh"
        template_type = "shell"
        template_name = "Jarwis GCP Service Account Setup"
        instructions = """
1. Open Google Cloud Shell or local terminal with gcloud CLI
2. Make the script executable: chmod +x gcp-service-account-setup.sh
3. Run the script: ./gcp-service-account-setup.sh
4. Follow the prompts to create the service account
5. Copy the output credentials into Jarwis Cloud Scan configuration
"""
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown provider: {provider}"
        )
    
    try:
        with open(template_path, 'r') as f:
            template_content = f.read()
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Template not found for provider: {provider}"
        )
    
    return OnboardingTemplateResponse(
        provider=provider,
        template_type=template_type,
        template_name=template_name,
        template_content=template_content,
        instructions=instructions.strip(),
        external_id=external_id
    )


@router.post("/generate-external-id")
async def generate_external_id(
    current_user: User = Depends(get_current_active_user)
):
    """Generate a new external ID for AWS cross-account role assumption"""
    import uuid
    external_id = f"jarwis-{uuid.uuid4().hex[:16]}"
    return {"external_id": external_id}


# ========== Scan Endpoints ==========

@router.post("/start", response_model=CloudScanResponse, status_code=status.HTTP_201_CREATED)
async def start_cloud_scan(
    scan_request: CloudScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new cloud security scan.
    
    - **provider**: Cloud provider (aws, azure, gcp)
    - **credentials**: Provider-specific credentials
    - **regions**: Optional list of regions to scan (default: all)
    - **services**: Optional list of services to scan (default: all)
    
    ## AWS Authentication Modes:
    - **Cross-Account Role (Recommended)**: Provide `role_arn` and `external_id`
    - **Direct Credentials (Legacy)**: Provide `access_key_id` and `secret_access_key`
    
    ## Azure Authentication:
    - Provide `tenant_id`, `client_id`, `client_secret`
    - Use `subscription_ids` for multiple subscriptions
    
    ## GCP Authentication Modes:
    - **Service Account Key (Legacy)**: Provide `service_account_key` JSON
    - **Workload Identity (Enterprise)**: Provide pool and provider IDs
    """
    # ========== SUBSCRIPTION ENFORCEMENT ==========
    # Check if user has cloud scan feature
    await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_CLOUD_SCAN)
    
    # Check scan limit
    await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    # ==============================================
    
    # Validate credentials based on provider
    provider = scan_request.provider.lower()
    credentials = scan_request.credentials
    auth_mode = None
    
    if provider == "aws":
        # Check for cross-account role mode (enterprise - recommended)
        if credentials.get("role_arn"):
            if not credentials.get("external_id"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="AWS cross-account role requires external_id"
                )
            auth_mode = "assume_role"
        # Check for direct credentials mode (legacy)
        elif credentials.get("access_key_id") and credentials.get("secret_access_key"):
            auth_mode = "direct"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AWS credentials require either (role_arn + external_id) or (access_key_id + secret_access_key)"
            )
    elif provider == "azure":
        # Support both single subscription and multiple subscriptions
        has_subscription = credentials.get("subscription_id") or credentials.get("subscription_ids")
        if not has_subscription:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Azure credentials require subscription_id or subscription_ids"
            )
        required = ["tenant_id", "client_id", "client_secret"]
        missing = [f for f in required if not credentials.get(f)]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Azure credentials missing: {', '.join(missing)}"
            )
        auth_mode = "service_principal"
    elif provider == "gcp":
        # Support both single project and multiple projects
        has_project = credentials.get("project_id") or credentials.get("project_ids")
        if not has_project:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="GCP credentials require project_id or project_ids"
            )
        # Check auth mode
        if credentials.get("workload_identity_pool"):
            auth_mode = "workload_identity"
        elif credentials.get("service_account_key"):
            auth_mode = "service_account_key"
        else:
            auth_mode = "default"  # Will use ADC
    
    # Generate scan ID
    scan_id = str(uuid_lib.uuid4())[:8]
    
    # Determine account ID for display
    account_id = ""
    if provider == "aws":
        if auth_mode == "assume_role":
            # Extract account ID from role ARN
            role_arn = credentials.get("role_arn", "")
            try:
                account_id = role_arn.split(":")[4] if ":" in role_arn else "unknown"
            except:
                account_id = "role-based"
        else:
            account_id = credentials.get("access_key_id", "")[:8] + "..."
    elif provider == "azure":
        # Use first subscription ID
        sub_ids = credentials.get("subscription_ids") or [credentials.get("subscription_id", "")]
        account_id = sub_ids[0][:8] + "..." if sub_ids[0] else ""
    elif provider == "gcp":
        # Use first project ID
        proj_ids = credentials.get("project_ids") or [credentials.get("project_id", "")]
        account_id = proj_ids[0] if proj_ids[0] else ""
    
    # Determine services to scan
    services_to_scan = scan_request.services
    if not services_to_scan:
        # Get default services from scanner
        if provider == "aws":
            from attacks.cloud.aws_scanner import AWSSecurityScanner
            services_to_scan = list(AWSSecurityScanner.AVAILABLE_SERVICES.keys())
        elif provider == "azure":
            from attacks.cloud.azure_scanner_complete import AzureSecurityScanner
            services_to_scan = list(AzureSecurityScanner.AVAILABLE_SERVICES.keys())
        elif provider == "gcp":
            from attacks.cloud.gcp_scanner import GCPSecurityScanner
            services_to_scan = list(GCPSecurityScanner.AVAILABLE_SERVICES.keys())
    
    # Create scan record in database (don't store credentials)
    scan = await crud.create_scan(
        db=db,
        user_id=current_user.id,
        scan_id=scan_id,
        target_url=f"cloud://{provider}/{account_id}",
        scan_type="cloud",
        config={
            "provider": provider,
            "account_id": account_id,
            "auth_mode": auth_mode,
            "regions": scan_request.regions,
            "services": services_to_scan,
            "notes": scan_request.notes
        }
    )
    
    # Increment usage counter
    await increment_usage_counter(db, current_user.id, "scans")
    
    # Initialize in-memory job (with credentials for the scan process)
    cloud_scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "user_id": current_user.id,
        "status": "queued",
        "progress": 0,
        "phase": "Initializing",
        "provider": provider,
        "account_id": account_id,
        "auth_mode": auth_mode,
        "credentials": credentials,  # Only in memory, not DB
        "config": {
            "regions": scan_request.regions,
            "services": services_to_scan,
        },
        "findings": [],
        "resources_scanned": 0,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "stop_requested": False
    }
    cloud_scan_logs[scan_id] = []
    
    # Start scan in background
    background_tasks.add_task(
        run_cloud_scan,
        scan_id=scan_id,
        user_id=current_user.id
    )
    
    return CloudScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Cloud scan started for {provider.upper()} account",
        provider=provider,
        auth_mode=auth_mode,
        services=services_to_scan,
        external_id=credentials.get("external_id") if provider == "aws" and auth_mode == "assume_role" else None
    )


@router.get("/{scan_id}/status", response_model=CloudScanStatusResponse)
async def get_cloud_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get status of a cloud scan"""
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    job = cloud_scan_jobs.get(scan_id, {})
    
    return CloudScanStatusResponse(
        scan_id=scan_id,
        status=scan.status,
        progress=scan.progress,
        phase=scan.phase or job.get("phase", ""),
        provider=scan.config.get("provider", ""),
        account_id=scan.config.get("account_id", ""),
        findings_count=scan.findings_count,
        started_at=scan.started_at.isoformat() if scan.started_at else "",
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None
    )


@router.get("/{scan_id}/logs")
async def get_cloud_scan_logs(
    scan_id: str,
    since: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get logs for a cloud scan"""
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    logs = cloud_scan_logs.get(scan_id, [])
    
    if since:
        logs = [l for l in logs if l.get("timestamp", "") > since]
    
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "logs": logs[-100:]
    }


@router.get("/{scan_id}/findings")
async def get_cloud_scan_findings(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get findings for a cloud scan"""
    from database.models import ScanHistory, Finding
    from sqlalchemy import select
    
    # Get scan from database
    scan_result = await db.execute(
        select(ScanHistory).where(
            ScanHistory.scan_id == scan_id,
            ScanHistory.user_id == current_user.id
        )
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    # Get findings from database
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    findings = [{
        'id': str(f.id),
        'finding_id': f.finding_id,
        'category': f.category,
        'severity': f.severity,
        'title': f.title,
        'description': f.description,
        'url': f.url,
        'method': f.method,
        'parameter': f.parameter,
        'evidence': f.evidence,
        'poc': f.poc,
        'reasoning': f.reasoning,
        'ai_verified': f.ai_verified,
        'is_false_positive': f.is_false_positive,
    } for f in findings_result.scalars().all()]
    
    # Also check in-memory job for live results
    job = cloud_scan_jobs.get(scan_id, {})
    if job.get('findings') and not findings:
        findings = job.get('findings', [])
    
    return {
        'scan_id': scan_id,
        'findings': findings,
        'summary': {
            'total': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'critical']),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low']),
            'info': len([f for f in findings if f.get('severity') == 'info']),
        }
    }


@router.post("/{scan_id}/stop")
async def stop_cloud_scan(
    scan_id: str,
    confirmed: bool = False,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Stop a running cloud scan"""
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    if scan.status not in ["running", "queued"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not running"
        )
    
    if not confirmed:
        return {
            "message": "Are you sure you want to stop this scan?",
            "confirm_required": True,
            "scan_id": scan_id
        }
    
    if scan_id in cloud_scan_jobs:
        cloud_scan_jobs[scan_id]["stop_requested"] = True
    
    await crud.update_scan_status(db, scan, "stopped")
    
    try:
        await decrement_usage_counter(db, current_user.id, "scans")
    except Exception as e:
        logger.warning(f"Failed to refund scan credit: {e}")
    
    return {
        "message": "Cloud scan stopped",
        "scan_id": scan_id,
        "success": True
    }


@router.get("/providers")
async def get_cloud_providers(
    current_user: User = Depends(get_current_active_user)
):
    """Get available cloud providers and their configuration"""
    return {
        "providers": [
            {
                "id": "aws",
                "name": "Amazon Web Services",
                "logo": "aws",
                "credentials_required": ["access_key_id", "secret_access_key"],
                "optional_fields": ["region", "session_token"],
                "services": ["s3", "ec2", "iam", "lambda", "rds", "vpc", "cloudtrail"]
            },
            {
                "id": "azure",
                "name": "Microsoft Azure",
                "logo": "azure",
                "credentials_required": ["subscription_id", "tenant_id", "client_id", "client_secret"],
                "optional_fields": [],
                "services": ["storage", "vms", "ad", "functions", "sql", "network"]
            },
            {
                "id": "gcp",
                "name": "Google Cloud Platform",
                "logo": "gcp",
                "credentials_required": ["project_id"],
                "optional_fields": ["service_account_key"],
                "services": ["gcs", "compute", "iam", "functions", "sql", "vpc"]
            }
        ]
    }


# ========== Background Task ==========

async def run_cloud_scan(scan_id: str, user_id):
    """Background task to run cloud security scan using CloudSecurityService"""
    from database.connection import AsyncSessionLocal
    from services.cloud_service import CloudSecurityService
    
    async with AsyncSessionLocal() as db:
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return
        
        job = cloud_scan_jobs.get(scan_id, {})
        logs = cloud_scan_logs.get(scan_id, [])
        
        def log(message: str, level: str = "info"):
            logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "level": level,
                "message": message
            })
            logger.info(f"[{scan_id}] {message}")
        
        async def progress_callback(progress_data: dict):
            """Callback to update scan progress"""
            phase = progress_data.get('phase', '')
            progress = progress_data.get('progress', 0)
            current_task = progress_data.get('current_task', '')
            findings_count = progress_data.get('findings_count', 0)
            
            job["phase"] = f"{phase}: {current_task}"
            job["progress"] = progress
            job["findings_count"] = findings_count
            
            await crud.update_scan_status(db, scan, "running", progress, job["phase"])
            log(current_task)
        
        try:
            await crud.update_scan_status(db, scan, "running", 5, "Initializing Cloud Scanner")
            log("Starting Jarwis Cloud Security Scan...")
            
            provider = job.get("provider", "")
            credentials = job.get("credentials", {})
            config = job.get("config", {})
            
            if job.get("stop_requested"):
                log("Scan stopped by user", "warning")
                return
            
            # Build runner configuration
            runner_config = {
                'regions': config.get('regions') or [],
                'services': config.get('services') or [],  # Service selection
                'auth_mode': job.get('auth_mode'),  # Authentication mode
                'ciem_scan_enabled': True,
                'kubernetes_scan_enabled': config.get('kubernetes_enabled', False),
                'drift_scan_enabled': config.get('drift_enabled', False),
                'data_scan_enabled': config.get('data_security_enabled', False),
                'iac_paths': config.get('iac_paths', []),
                'container_registries': config.get('container_registries', []),
                'compliance_frameworks': ['CIS', 'PCI-DSS', 'HIPAA', 'SOC2'],
            }
            
            log(f"Initializing {provider.upper()} cloud scanner...")
            
            # Use service layer instead of importing core directly
            results = await CloudSecurityService.execute_background_scan(
                scan_id=scan_id,
                user_id=user_id,
                provider=provider,
                credentials=credentials,
                config=runner_config,
                progress_callback=progress_callback
            )
            
            if job.get("stop_requested"):
                log("Scan stopped by user", "warning")
                return
            
            # Extract findings
            findings = results.get('findings', [])
            job["findings"] = findings
            job["resources_scanned"] = results.get('resources_scanned', 0)
            job["attack_paths"] = results.get('attack_graph', {}).get('attack_paths', [])
            job["compliance_scores"] = results.get('compliance_scores', {})
            
            # Calculate severity counts
            severity_counts = results.get('severity_counts', {
                "critical": len([f for f in findings if f.get("severity") == "critical"]),
                "high": len([f for f in findings if f.get("severity") == "high"]),
                "medium": len([f for f in findings if f.get("severity") == "medium"]),
                "low": len([f for f in findings if f.get("severity") == "low"]),
                "info": len([f for f in findings if f.get("severity") == "info"]),
            })
            
            # Store full results
            await crud.update_scan_results(
                db, scan,
                findings_count=len(findings),
                severity_counts=severity_counts,
                report_paths={},
                results=results  # Store full results including compliance scores
            )
            
            # Complete
            job["phase"] = "Completed"
            job["progress"] = 100
            job["completed_at"] = datetime.utcnow().isoformat()
            await crud.update_scan_status(db, scan, "completed", 100, "Completed")
            
            # Log completion with layer breakdown
            layer_counts = results.get('layer_counts', {})
            log(f"Cloud scan completed! Found {len(findings)} issues across {job.get('resources_scanned', 0)} resources")
            log(f"Detection layers: {layer_counts}")
            if job.get('compliance_scores'):
                for fw, score in job['compliance_scores'].items():
                    log(f"  {fw} Compliance: {score.get('score', 0):.1f}%")
            
            # Clear credentials from memory
            if scan_id in cloud_scan_jobs:
                cloud_scan_jobs[scan_id].pop("credentials", None)
            
        except Exception as e:
            logger.error(f"Cloud scan error: {e}", exc_info=True)
            log(f"Scan error: {str(e)}", "error")
            await crud.update_scan_status(db, scan, "error", scan.progress, f"Error: {str(e)}")
            
            try:
                await decrement_usage_counter(db, user_id, "scans")
                log("Scan credit refunded due to error", "info")
            except Exception as refund_error:
                log(f"Failed to refund scan credit: {str(refund_error)}", "warning")
            
            # Clear credentials on error too
            if scan_id in cloud_scan_jobs:
                cloud_scan_jobs[scan_id].pop("credentials", None)


# ========== List Cloud Scans ==========

@router.get("/")
async def list_cloud_scans(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all cloud scans for the current user"""
    scans, total = await crud.get_user_scans(
        db=db,
        user_id=current_user.id,
        skip=0,
        limit=100,
        scan_type="cloud"
    )
    
    return {
        "scans": [
            {
                "id": str(s.id),
                "scan_id": s.scan_id,
                "status": s.status,
                "provider": s.config.get("provider", ""),
                "account_id": s.config.get("account_id", ""),
                "progress": s.progress,
                "findings_count": s.findings_count,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in scans
        ],
        "total": total
    }


# ========== Attack Paths & Compliance (NEW) ==========

@router.get("/{scan_id}/attack-paths")
async def get_attack_paths(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get attack path analysis for a cloud scan.
    
    Attack paths show how an attacker could move from an entry point (e.g., public internet)
    to sensitive resources (e.g., databases with PII).
    
    Each path includes:
    - description: Human-readable explanation
    - path: List of resource IDs traversed
    - blast_radius: Impact score (0-100)
    - severity: critical/high/medium/low
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    # Get attack paths from scan results
    attack_paths = []
    if scan.results and isinstance(scan.results, dict):
        attack_paths = scan.results.get("attack_paths", [])
    elif scan_id in cloud_scan_jobs:
        # Try in-memory job
        attack_paths = cloud_scan_jobs[scan_id].get("attack_paths", [])
    
    return {
        "scan_id": scan_id,
        "attack_paths": attack_paths,
        "count": len(attack_paths)
    }


@router.get("/{scan_id}/compliance")
async def get_compliance_scores(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get compliance framework scores for a cloud scan.
    
    Frameworks:
    - CIS: Center for Internet Security Benchmarks
    - PCI-DSS: Payment Card Industry Data Security Standard
    - HIPAA: Health Insurance Portability and Accountability Act
    - SOC2: Service Organization Control 2
    
    Scores are percentages (0-100) indicating compliance level.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    # Get findings from scan results
    findings = []
    if scan.results and isinstance(scan.results, dict):
        findings = scan.results.get("findings", [])
    elif scan_id in cloud_scan_jobs:
        findings = cloud_scan_jobs[scan_id].get("findings", [])
    
    # Calculate compliance scores
    severity_weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}
    
    # Group findings by framework indicators
    framework_findings = {
        'CIS': [],
        'PCI-DSS': [],
        'HIPAA': [],
        'SOC2': []
    }
    
    for finding in findings:
        # All findings count toward CIS
        framework_findings['CIS'].append(finding)
        
        # Encryption/data findings affect PCI-DSS and HIPAA
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        
        if any(keyword in title + description for keyword in ['encrypt', 'storage', 'data', 'database', 'backup']):
            framework_findings['PCI-DSS'].append(finding)
            framework_findings['HIPAA'].append(finding)
        
        # Access control findings affect SOC2
        if any(keyword in title + description for keyword in ['access', 'iam', 'public', 'permission', 'policy']):
            framework_findings['SOC2'].append(finding)
    
    # Calculate scores
    compliance_scores = {}
    for framework, fw_findings in framework_findings.items():
        if not fw_findings:
            compliance_scores[framework] = 100.0
            continue
        
        total_weight = sum(severity_weights.get(f.get('severity', 'info'), 0) for f in fw_findings)
        max_possible = len(fw_findings) * 10
        
        if max_possible > 0:
            score = max(0, 100 - (total_weight / max_possible * 100))
            compliance_scores[framework] = round(score, 1)
        else:
            compliance_scores[framework] = 100.0
    
    return {
        "scan_id": scan_id,
        "compliance_scores": compliance_scores,
        "findings_count": len(findings),
        "breakdown": {
            framework: {
                "total_findings": len(fw_findings),
                "critical": len([f for f in fw_findings if f.get('severity') == 'critical']),
                "high": len([f for f in fw_findings if f.get('severity') == 'high']),
                "medium": len([f for f in fw_findings if f.get('severity') == 'medium']),
                "low": len([f for f in fw_findings if f.get('severity') == 'low'])
            }
            for framework, fw_findings in framework_findings.items()
        }
    }


@router.get("/{scan_id}/export")
async def export_cloud_scan_results(
    scan_id: str,
    format: str = "json",
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export cloud scan results in various formats.
    
    Supported formats:
    - json: JSON file with all findings
    - sarif: SARIF format for IDE integration
    - html: HTML report with charts and tables
    - pdf: PDF report for sharing/printing
    """
    if format not in ['json', 'sarif', 'html', 'pdf']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid format. Use: json, sarif, html, pdf"
        )
    
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud scan not found"
        )
    
    # Get findings
    findings = []
    if scan.results and isinstance(scan.results, dict):
        findings = scan.results.get("findings", [])
    elif scan_id in cloud_scan_jobs:
        findings = cloud_scan_jobs[scan_id].get("findings", [])
    
    if not findings:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No findings to export"
        )
    
    if format == 'json':
        import json
        from fastapi.responses import JSONResponse
        return JSONResponse(
            content=findings,
            headers={
                "Content-Disposition": f"attachment; filename=cloud_scan_{scan_id}.json"
            }
        )
    
    elif format == 'sarif':
        # Generate SARIF format
        sarif_output = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Jarwis Cloud Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://jarwis.ai"
                    }
                },
                "results": [
                    {
                        "ruleId": f.get('id', ''),
                        "message": {"text": f.get('description', '')},
                        "level": {
                            "critical": "error",
                            "high": "error", 
                            "medium": "warning",
                            "low": "note",
                            "info": "none"
                        }.get(f.get('severity', 'info'), 'note'),
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.get('resource_arn', f.get('resource_id', ''))}
                            }
                        }]
                    }
                    for f in findings
                ]
            }]
        }
        
        import json
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(
            content=json.dumps(sarif_output, indent=2),
            media_type="application/sarif+json",
            headers={
                "Content-Disposition": f"attachment; filename=cloud_scan_{scan_id}.sarif"
            }
        )
    
    elif format in ['html', 'pdf']:
        # Use CloudSecurityService for HTML/PDF - respects layered architecture
        try:
            from services.cloud_service import CloudSecurityService
            
            scan_config = {
                "scan_id": scan_id,
                "provider": scan.config.get("provider", "cloud"),
                "account_id": scan.config.get("account_id", "")
            }
            
            result = await CloudSecurityService.generate_report(
                findings=findings,
                scan_config=scan_config,
                format=format,
                output_dir="reports"
            )
            
            if result and result.get('file_path'):
                from fastapi.responses import FileResponse
                return FileResponse(
                    path=result['file_path'],
                    media_type=result['mime_type'],
                    filename=f"cloud_scan_{scan_id}.{format}"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Failed to generate {format.upper()} report"
                )
        
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate {format.upper()} report: {str(e)}"
            )


@router.post("/validate-credentials")
async def validate_cloud_credentials(
    provider: str,
    credentials: dict,
    current_user: User = Depends(get_current_active_user)
):
    """
    Validate cloud provider credentials before starting a scan.
    
    Providers:
    - aws: Requires access_key_id, secret_access_key
    - azure: Requires tenant_id, client_id, client_secret, subscription_id
    - gcp: Requires project_id, service_account_key (JSON string)
    
    Returns account info if valid, or error message if invalid.
    """
    from services.cloud_service import CloudSecurityService
    
    result = await CloudSecurityService.validate_credentials(
        provider=provider,
        credentials=credentials
    )
    
    return result

