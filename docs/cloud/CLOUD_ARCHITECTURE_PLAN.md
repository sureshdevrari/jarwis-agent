# Cloud Security Scan - Architecture & Fix Plan

**Status**: Analysis Phase (Jan 9, 2026)  
**Target**: Production-ready cloud scanning with unified architecture

---

## Current State Analysis

### ✅ What Works

1. **Basic Flow Structure**
   - 6-phase execution model in `CloudScanRunner`
   - Discovery → CSPM → IaC → Container → Runtime → AI Analysis
   - Phase progression with progress tracking

2. **Provider Coverage**
   - AWS: 696 lines, CIS Benchmark checks defined
   - Azure: Some implementation started
   - GCP: Skeleton in place
   - Container, IaC, Runtime scanners partially implemented

3. **API Routes**
   - `/api/scan/cloud/start` - initiates scans
   - `/api/scan/cloud/status/{scan_id}` - tracks progress
   - Credential validation endpoints

4. **Database Integration**
   - Service layer (`CloudSecurityService`) bridges API to runners
   - Subscription limits enforced
   - Basic CRUD operations

---

## ❌ Problems Identified

### 1. **Registry Type Implementation Issues**
- **Problem**: No unified CloudScannerRegistry exists
  - Each provider has separate scanner class
  - No metadata tracking (timeout, contexts, OWASP mapping)
  - No dynamic loader for scanner discovery
  - No enable/disable mechanism

- **Impact**: 
  - Hard to add new scanners
  - No control over which scanners run
  - Can't track scanner compatibility

- **Location**: Missing `attacks/cloud/registry.py`

---

### 2. **Inconsistent Error Handling**
- **Problem**: Generic try/except blocks throughout
  ```python
  except Exception as e:
      logger.error(f"Error: {e}")  # Too generic!
  ```

- **Missing**:
  - Custom exception classes (`CloudScanError`, `ProviderError`, `CredentialError`)
  - Typed error responses
  - Retry logic for transient failures
  - Error recovery mechanisms

- **Locations**: 
  - `core/cloud_scan_runner.py` (lines 221, 255, 684, 737, 788)
  - `attacks/cloud/aws_scanner.py`
  - `attacks/cloud/azure_scanner.py`

---

### 3. **Attack Coverage Gaps**
- **AWS**: ~60% coverage (S3, IAM, EC2 basic)
  - Missing: Lambda security, RDS checks, VPC/Network deep-dive
  - Missing: Secrets Manager, Athena, DynamoDB, KMS

- **Azure**: ~30% coverage
  - Skeleton only, no active scanning
  - Missing: Storage security, Key Vault, AD/RBAC, SQL Server

- **GCP**: ~20% coverage
  - Minimal implementation
  - Missing: GCS bucket hardening, IAM conditions, Compute Engine security

- **Container Registry**: Limited
  - No ECR/ACR/GCR actual scanning
  - Missing: Malware detection, supply chain validation

---

### 4. **Finding Schema Inconsistencies**
- **Problem**: Multiple finding definitions
  - `CloudFinding` in `cloud_scanner.py` (9 fields)
  - `CloudFinding` in `cloud_scan_runner.py` (17 fields)
  - `AWSFinding` in `aws_scanner.py` (8 fields)
  - `AzureFinding` (if exists) probably different
  - `GCPFinding` (if exists) probably different

- **Result**: 
  - Conversion overhead between formats
  - Missing data in some findings
  - No unified API response

- **Locations**:
  - `attacks/cloud/cloud_scanner.py` line 17
  - `core/cloud_scan_runner.py` line 41
  - `attacks/cloud/aws_scanner.py` line 18

---

### 5. **Execution Flow Issues**
- **Problem**: Phases not cleanly separated
  - Methods call each other without clear data flow
  - No phase checkpoints (can't resume)
  - Unclear data dependencies

- **Missing**:
  - Phase interface/contract
  - Progress serialization for long scans
  - Scan state machine
  - Cancel/pause operations

---

### 6. **Async/Concurrency Problems**
- **Issue**: Mixed async/sync operations
  - boto3 is sync-only, wrapped with `asyncio.to_thread()` throughout
  - No connection pooling
  - No concurrency limits (can DOS provider APIs)
  - No rate limiting

- **Impact**: 
  - Slow scans
  - Risk of throttling from cloud providers
  - Resource exhaustion

---

### 7. **Config & Context Management**
- **Problem**: Context is mutable, shared across threads
  - No thread-safety for `context.findings`
  - Circular dependencies (config → context → callbacks → config)
  - No config validation before scan start

- **Locations**:
  - `core/cloud_scan_runner.py` line 62 (CloudScanContext)

---

### 8. **Testing & Observability**
- **Missing**:
  - Unit tests for individual scanners
  - Integration tests for multi-provider scans
  - Mock cloud APIs for CI/CD testing
  - Structured logging (JSON format)
  - Metrics (findings per provider, avg scan time, errors)

---

## Implementation Plan (Priority Order)

### Phase 1: Foundation (Days 1-2)

#### 1.1 Create Custom Exceptions (`attacks/cloud/exceptions.py`)
```python
class CloudScanError(Exception): pass
class ProviderError(Exception): pass
class CredentialError(Exception): pass
class ResourceDiscoveryError(Exception): pass
class RateLimitError(Exception): pass
class ConfigurationError(Exception): pass
class IaCParseError(Exception): pass
class ContainerScanError(Exception): pass
```

**Why First**: All error handling depends on this

---

#### 1.2 Unified Finding Schema (`attacks/cloud/schemas.py`)
```python
@dataclass
class CloudFinding:
    # Unified across all providers
    id: str
    provider: str  # aws, azure, gcp
    severity: str  # critical, high, medium, low, info
    category: str  # CSPM, IaC, Container, Runtime, etc.
    title: str
    description: str
    affected_resource: CloudResource
    evidence: Dict[str, Any]
    remediation: str
    remediation_cli: str
    compliance_frameworks: List[str]  # CIS, PCI-DSS, HIPAA, etc.
    cvss_score: float
    attack_paths: List[List[str]]  # [[resource1, resource2, ...], ...]
    detected_at: datetime
    detection_layer: str  # cspm, iac, container, runtime, ai
```

**Why Here**: Unified upstream, solves finding inconsistency

---

#### 1.3 CloudScannerInterface (`attacks/cloud/base.py`)
```python
class CloudScanner(ABC):
    """Base class for all cloud scanners"""
    
    @abstractmethod
    async def scan(self) -> List[CloudFinding]: pass
    
    @abstractmethod
    def validate_config(self) -> bool: pass
    
    @abstractmethod
    def get_metadata(self) -> ScannerMetadata: pass
```

**Why Here**: Enforce consistent interface before registry

---

### Phase 2: Registry System (Days 2-3)

#### 2.1 CloudScannerRegistry (`attacks/cloud/registry.py`)
```python
@dataclass
class ScannerMetadata:
    name: str
    scanner_class: Type[CloudScanner]
    provider: str  # aws, azure, gcp, all
    layer: str  # cspm, iac, container, runtime, ai
    timeout: int
    enabled: bool
    description: str
    owasp_mapping: List[str]
    
class CloudScannerRegistry:
    """Unified registry for all cloud scanners"""
    
    def get_scanners(self, provider: str, layer: str) -> List[Type[CloudScanner]]: pass
    def register(self, metadata: ScannerMetadata): pass
    def enable(self, name: str): pass
    def disable(self, name: str): pass
```

**Benefits**:
- Easy to add/remove scanners
- Dynamic discovery
- Per-scanner configuration
- Enable/disable mechanism

---

#### 2.2 Register All Scanners
```python
# In CloudScannerRegistry.__init__()
self.register(ScannerMetadata(
    name="aws_cspm",
    scanner_class=AWSCSPMScanner,
    provider="aws",
    layer="cspm",
    timeout=300,
    enabled=True
))
# ... repeat for all 20+ scanners
```

---

### Phase 3: Error Handling & Resilience (Days 3-4)

#### 3.1 Add Retry Logic
```python
async def _run_with_retry(
    func: Callable,
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    on_error: Optional[Callable] = None
) -> Any:
    """Retry with exponential backoff"""
    for attempt in range(max_retries):
        try:
            return await func()
        except RateLimitError:
            wait_time = backoff_factor ** attempt
            await asyncio.sleep(wait_time)
        except CloudScanError:
            raise  # Don't retry scan errors
```

#### 3.2 Comprehensive Error Handling
```python
try:
    findings = await scanner.scan()
except CredentialError as e:
    await self._handle_credential_error(e)
except RateLimitError as e:
    await self._handle_rate_limit(e)
except ResourceDiscoveryError as e:
    # Log but continue
    logger.warning(f"Discovery partial: {e}")
except Exception as e:
    # Unknown error - log and fail
    raise CloudScanError(f"Unexpected: {e}") from e
```

---

### Phase 4: Attack Coverage Expansion (Days 4-7)

#### 4.1 AWS Comprehensive Coverage
**Current**: S3, IAM, EC2, RDS basic
**Add**:
- Lambda: Function policies, env variables, VPC config
- Secrets Manager: Secret exposure, rotation
- DynamoDB: Encryption, point-in-time recovery
- KMS: Key rotation, key usage
- CloudFront: Distribution security, logging
- API Gateway: Auth, WAF, throttling
- SNS/SQS: Resource policies, encryption

#### 4.2 Azure Expansion
**Current**: Minimal skeleton
**Add**:
- Storage Account: Public access, encryption, logging
- Key Vault: Access policies, secret rotation
- Azure AD: RBAC, conditional access, MFA
- App Service: HTTPS, cert validation, auth
- SQL Server: Firewall, encryption, auditing
- Network: NSG rules, DDoS protection
- Cosmos DB: Encryption, firewall

#### 4.3 GCP Completion
**Current**: Minimal skeleton
**Add**:
- GCS Bucket: Uniform ACLs, public access, encryption
- IAM: Custom roles, SA permissions, hierarchy
- Compute Engine: Metadata server, service accounts, disks
- Cloud Function: Permissions, env vars, secrets
- Cloud SQL: Backups, encryption, HA
- VPC: Firewall rules, VPC peering, private Google access

#### 4.4 Container Registry Integration
**Add**:
- ECR scanning with Trivy API
- ACR vulnerability detection
- GCR image scanning
- OCI manifest validation
- Supply chain security (attestations)

---

### Phase 5: Flow Architecture (Days 7-8)

#### 5.1 Phase Interface
```python
class CloudPhase(ABC):
    """Base for each scan phase"""
    
    async def execute(self, context: CloudScanContext) -> CloudScanContext:
        """Execute phase, return updated context"""
        pass
    
    async def rollback(self): pass  # For recovery
```

#### 5.2 Phase Implementations
- `DiscoveryPhase`: Resource enumeration
- `CSPMPhase`: Configuration scanning
- `IaCPhase`: Infrastructure-as-Code analysis
- `ContainerPhase`: Container & image scanning
- `RuntimePhase`: Activity log analysis
- `AIPhase`: Attack path analysis

#### 5.3 Orchestration
```python
class CloudScanOrchestrator:
    """Manages phase execution"""
    
    phases: List[CloudPhase] = [
        DiscoveryPhase(),
        CSPMPhase(),
        IaCPhase(),
        ContainerPhase(),
        RuntimePhase(),
        AIPhase(),
    ]
    
    async def run(self, context: CloudScanContext):
        for phase in self.phases:
            context = await phase.execute(context)
```

**Benefits**:
- Clear separation of concerns
- Easy to add phases
- Testable individually
- Checkpoints for resume

---

### Phase 6: Concurrency & Performance (Days 8-9)

#### 6.1 Connection Pooling
```python
class CloudClientPool:
    """Manages AWS/Azure/GCP client connections"""
    
    def get_aws_client(self, service: str):
        # Reuse boto3 session
        pass
    
    def get_azure_client(self, service: str):
        # Reuse Azure SDK client
        pass
```

#### 6.2 Rate Limiting
```python
class RateLimiter:
    """Prevent API throttling"""
    
    async def acquire(self, provider: str):
        # Respect cloud provider API limits
        # AWS: 20 req/sec per service
        # Azure: varies by API
        pass
```

#### 6.3 Concurrent Scanner Execution
```python
# Run multiple scanners per layer concurrently
tasks = [
    scanner.scan() for scanner in layer_scanners
]
results = await asyncio.gather(*tasks, return_exceptions=True)
```

---

### Phase 7: Testing & Observability (Days 9-10)

#### 7.1 Unit Tests
- Test each scanner with mocked APIs
- Test error scenarios
- Test finding generation

#### 7.2 Integration Tests
- Multi-provider scans
- Phase transitions
- Error recovery

#### 7.3 Mock Cloud APIs
- Mock boto3 for AWS tests
- Mock Azure SDK
- Mock GCP libraries

#### 7.4 Observability
- Structured JSON logging
- Metrics collection (findings/provider, scan duration)
- Trace scanning flow

---

## Execution Dependencies

```
Phase 1 (Foundation)
├─ 1.1 Custom Exceptions
├─ 1.2 Unified Finding Schema  
├─ 1.3 CloudScanner Interface
└─ ✅ Can do in parallel

Phase 2 (Registry)
├─ Depends on: Phase 1
├─ 2.1 CloudScannerRegistry
└─ 2.2 Register all scanners

Phase 3 (Error Handling)
├─ Depends on: Phase 1
├─ 3.1 Retry logic
└─ 3.2 Comprehensive error handling

Phase 4 (Attack Coverage)
├─ Depends on: Phase 1-3
├─ 4.1 AWS expansion
├─ 4.2 Azure expansion
├─ 4.3 GCP completion
└─ 4.4 Container registry
    (Can do in parallel)

Phase 5 (Flow)
├─ Depends on: Phase 1-4
├─ 5.1 Phase interface
├─ 5.2 Phase implementations
└─ 5.3 Orchestration

Phase 6 (Performance)
├─ Depends on: Phase 2-5
├─ 6.1 Connection pooling
├─ 6.2 Rate limiting
└─ 6.3 Concurrent execution
    (Can do in parallel)

Phase 7 (Testing)
├─ Depends on: All phases
└─ Tests, mocks, observability
```

---

## Files to Create/Modify

### New Files
```
attacks/cloud/
├── exceptions.py           ← Custom exceptions
├── schemas.py              ← Unified CloudFinding
├── base.py                 ← CloudScanner ABC
├── registry.py             ← CloudScannerRegistry
├── phases.py               ← Phase interface & implementations
└── utils/
    ├── retry.py            ← Retry decorator
    ├── rate_limiter.py     ← Rate limiting
    └── connection_pool.py   ← Client pooling
```

### Modified Files
```
attacks/cloud/
├── __init__.py             ← Register all scanners
├── aws_scanner.py          ← Refactor to inherit CloudScanner
├── azure_scanner.py        ← Refactor & expand
├── gcp_scanner.py          ← Refactor & expand
├── cloud_scanner.py        ← Use unified finding
├── container_scanner.py    ← Add registry, error handling
├── iac_scanner.py          ← Add registry, error handling
├── runtime_scanner.py      ← Add registry, error handling
└── ciem_scanner.py         ← Add registry, error handling

core/
├── cloud_scan_runner.py    ← Use phases, registry
└── cloud_graph.py          ← Use unified finding

services/
└── cloud_service.py        ← Handle new errors

api/routes/
└── cloud.py                ← Handle new error types
```

### Test Files
```
tests/
└── cloud/
    ├── test_aws_scanner.py
    ├── test_azure_scanner.py
    ├── test_gcp_scanner.py
    ├── test_registry.py
    ├── test_phases.py
    ├── mocks/
    │   ├── aws_mock.py
    │   ├── azure_mock.py
    │   └── gcp_mock.py
    └── fixtures/
        ├── cloud_findings.json
        └── test_resources.json
```

---

## What to Do First

### **IMMEDIATE (Next 2 hours)**

1. ✅ **Create `attacks/cloud/exceptions.py`**
   - Define all custom exception classes
   - Add docstrings with when to use each

2. ✅ **Create `attacks/cloud/schemas.py`**
   - Unified `CloudFinding` dataclass
   - Common enums (severity, layer, provider)

3. ✅ **Create `attacks/cloud/base.py`**
   - `CloudScanner` ABC
   - `ScannerMetadata` dataclass
   - Enforce interface

### **SHORT TERM (Days 1-2)**

4. Create `attacks/cloud/registry.py`
5. Refactor AWS/Azure/GCP to inherit from CloudScanner
6. Register all scanners in registry
7. Update `CloudScanRunner` to use registry

### **MEDIUM TERM (Days 3-5)**

8. Expand AWS coverage (Lambda, Secrets, DynamoDB, KMS)
9. Implement Azure expansion (Storage, Key Vault, AD, App Service)
10. Implement GCP completion (GCS, IAM, Compute, Cloud Functions)

### **LONG TERM (Days 6-10)**

11. Create phase system (DiscoveryPhase, CSPMPhase, etc.)
12. Add retry logic & resilience
13. Add connection pooling & rate limiting
14. Comprehensive testing suite

---

## Success Criteria

✅ **Architecture**
- [ ] All cloud scanners inherit from `CloudScanner` interface
- [ ] Registry system with metadata for each scanner
- [ ] Unified `CloudFinding` schema used everywhere
- [ ] Custom exception classes for all error scenarios

✅ **Coverage**
- [ ] AWS: 15+ scanner modules
- [ ] Azure: 12+ scanner modules
- [ ] GCP: 10+ scanner modules
- [ ] Container + IaC + Runtime layers working

✅ **Reliability**
- [ ] Retry logic for transient failures (rate limits, timeouts)
- [ ] Comprehensive error handling with typed responses
- [ ] Graceful degradation (one service fails, scan continues)
- [ ] 100% test coverage on scanners

✅ **Performance**
- [ ] Multi-provider scans < 5min (vs. current ~10min)
- [ ] Concurrent scanner execution
- [ ] Connection pooling & reuse
- [ ] Rate limiting prevents API throttling

✅ **Observability**
- [ ] Structured JSON logging
- [ ] Metrics: findings/provider, scan duration, errors
- [ ] Scan progress tracking
- [ ] Detailed audit trail

---

## Risk Mitigation

| Risk | Mitigation |
|------|-----------|
| Breaking existing cloud scans | Use feature flags, maintain backward compatibility |
| Credential exposure in logs | Mask sensitive data in all logs |
| Rate limiting from cloud APIs | Implement rate limiter with exponential backoff |
| Long scan times | Add phase checkpoints, allow resume |
| Memory leak (client connections) | Use connection pooling with proper cleanup |
| Database overwhelm (many findings) | Batch writes, pagination support |

---

## Timeline

- **Phase 1** (Foundation): 1 day
- **Phase 2** (Registry): 1 day
- **Phase 3** (Error Handling): 1 day
- **Phase 4** (Coverage): 3 days
- **Phase 5** (Flow): 1 day
- **Phase 6** (Performance): 1 day
- **Phase 7** (Testing): 2 days

**Total**: 10 days for complete implementation

