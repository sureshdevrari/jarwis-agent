# Cloud Security Architecture - Visual Overview

## Current Problems & Solutions

### Problem 1: No Registry System
```
❌ CURRENT (Ad-hoc)
├── AWSSecurityScanner → aws_scanner.py
├── AzureSecurityScanner → azure_scanner.py
├── GCPSecurityScanner → gcp_scanner.py
├── ContainerScanner → container_scanner.py
├── IaCScanner → iac_scanner.py
└── (No way to discover, enable/disable, or manage them)

✅ FIXED (Registry-based)
└── CloudScannerRegistry
    ├── aws_cspm → AWSCSPMScanner (metadata)
    ├── aws_iam → AWSIAMScanner (metadata)
    ├── aws_ec2 → AWSEC2Scanner (metadata)
    ├── ... 20+ scanners ...
    └── Methods: get_scanners(), enable(), disable()
```

### Problem 2: Inconsistent Finding Schemas
```
❌ CURRENT (Multiple formats)
├── CloudFinding (9 fields)
├── CloudFinding in CloudScanRunner (17 fields) ← Duplicate name!
├── AWSFinding (8 fields)
├── AzureFinding (unknown)
└── GCPFinding (unknown)

✅ FIXED (Single schema)
└── CloudFinding (unified)
    ├── id, provider, service, resource_id
    ├── severity, category, title, description
    ├── evidence, remediation, remediation_cli
    ├── compliance_frameworks, cvss_score
    ├── attack_paths, detected_at, detection_layer
    └── Used by ALL scanners & API
```

### Problem 3: Generic Error Handling
```
❌ CURRENT (Catch-all)
try:
    do_something()
except Exception as e:
    logger.error(f"Error: {e}")  # Can't tell what went wrong!
    return 500

✅ FIXED (Typed exceptions)
try:
    validate_creds()
except CredentialError as e:
    return 403 with clear message
except RateLimitError as e:
    retry with exponential backoff
except CloudScanError as e:
    log and continue (non-fatal)
except Exception as e:
    fail fast (unknown error)
```

### Problem 4: Loose Coupling to Interface
```
❌ CURRENT (No interface)
class AWSSecurityScanner:
    async def scan(self):  # Different signature per provider!
        ...

class AzureSecurityScanner:
    async def scan(self):  # Same name, different behavior!
        ...

✅ FIXED (Strict interface)
class CloudScanner(ABC):
    @abstractmethod
    async def scan(self) -> List[CloudFinding]: pass
    
    @abstractmethod
    def validate_config(self) -> bool: pass
    
    @abstractmethod
    def get_metadata(self) -> ScannerMetadata: pass

# All scanners inherit & implement
class AWSCSPMScanner(CloudScanner):
    async def scan(self) -> List[CloudFinding]: ...
```

---

## Solution Architecture (10-Day Plan)

```
┌─────────────────────────────────────────────────────────────────┐
│                    PHASE 1: FOUNDATION (Day 1)                  │
│                                                                 │
│  attacks/cloud/exceptions.py  ← Custom exceptions              │
│  ├── CloudScanError                                            │
│  ├── ProviderError                                             │
│  ├── CredentialError                                           │
│  ├── ResourceDiscoveryError                                    │
│  ├── RateLimitError                                            │
│  └── ... 8 total                                               │
│                                                                 │
│  attacks/cloud/schemas.py  ← Unified schemas                   │
│  ├── CloudFinding (17 fields, unified)                         │
│  ├── CloudResource                                             │
│  ├── CloudScanContext                                          │
│  └── Enums (Severity, Category, Layer, Provider)              │
│                                                                 │
│  attacks/cloud/base.py  ← Abstract base class                  │
│  ├── CloudScanner (interface)                                  │
│  ├── ScannerMetadata (dataclass)                               │
│  └── Cloud resource types                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   PHASE 2: REGISTRY (Days 1-2)                  │
│                                                                 │
│  attacks/cloud/registry.py  ← Scanner discovery                │
│  ├── CloudScannerRegistry (singleton)                          │
│  ├── register(metadata)                                        │
│  ├── get_scanners(provider, layer)                             │
│  ├── enable(name), disable(name)                               │
│  └── 20+ scanners auto-discovered                              │
│                                                                 │
│  Usage in CloudScanRunner:                                      │
│  registry = CloudScannerRegistry()                             │
│  for scanner_cls in registry.get_scanners('aws', 'cspm'):     │
│      scanner = scanner_cls(config, context)                    │
│      findings += await scanner.scan()                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                PHASE 3: ERROR HANDLING (Days 2-3)               │
│                                                                 │
│  attacks/cloud/utils/retry.py  ← Retry logic                   │
│  ├── Exponential backoff                                       │
│  ├── Jitter to prevent thundering herd                         │
│  └── Typed exception handling                                  │
│                                                                 │
│  attacks/cloud/utils/rate_limiter.py  ← API throttling         │
│  ├── Per-provider limits (AWS, Azure, GCP)                     │
│  ├── Token bucket algorithm                                    │
│  └── Graceful backoff                                          │
│                                                                 │
│  Updated CloudScanRunner:                                       │
│  try:                                                           │
│      async with rate_limiter.acquire('aws'):                   │
│          findings = await scanner.scan()                       │
│  except RateLimitError:                                        │
│      await retry_with_backoff()                                │
│  except CredentialError:                                       │
│      raise CloudScanError("Auth failed")  # Typed!             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│               PHASE 4: ATTACK COVERAGE (Days 3-6)               │
│                                                                 │
│  AWS Expansion (15 scanners):                                  │
│  ├── CSPM: S3, IAM, EC2, RDS, Lambda, ... (+10)               │
│  ├── IaC: Terraform, CloudFormation validation                │
│  ├── Container: ECR scanning                                   │
│  └── Runtime: CloudTrail analysis                              │
│                                                                 │
│  Azure Expansion (12 scanners):                                │
│  ├── CSPM: Storage, KeyVault, AppService, SQL, ...            │
│  ├── IaC: ARM template validation                              │
│  ├── Container: ACR scanning                                   │
│  └── Runtime: Activity Logs analysis                           │
│                                                                 │
│  GCP Completion (10 scanners):                                 │
│  ├── CSPM: GCS, IAM, Compute, Functions, ...                  │
│  ├── IaC: Terraform validation                                 │
│  ├── Container: GCR scanning                                   │
│  └── Runtime: Cloud Audit Logs analysis                        │
│                                                                 │
│  All return unified CloudFinding format                         │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 PHASE 5: FLOW ARCHITECTURE (Day 7)              │
│                                                                 │
│  attacks/cloud/phases.py  ← Phase interface                    │
│  ├── CloudPhase (ABC)                                          │
│  │   ├── execute(context) → context                            │
│  │   └── rollback()                                            │
│  │                                                              │
│  ├── DiscoveryPhase                                            │
│  ├── CSPMPhase                                                 │
│  ├── IaCPhase                                                  │
│  ├── ContainerPhase                                            │
│  ├── RuntimePhase                                              │
│  └── AIPhase                                                   │
│                                                                 │
│  CloudScanOrchestrator:                                        │
│  for phase in phases:                                          │
│      context = await phase.execute(context)                    │
│      # Can checkpoint here for resume                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│               PHASE 6: PERFORMANCE (Days 7-8)                   │
│                                                                 │
│  attacks/cloud/utils/connection_pool.py                        │
│  ├── Reuse boto3 sessions                                      │
│  ├── Reuse Azure SDK clients                                   │
│  ├── Reuse GCP clients                                         │
│  └── Pooling: 1 connection per region/service                  │
│                                                                 │
│  Concurrent execution:                                         │
│  tasks = [scanner.scan() for scanner in scanners]             │
│  results = await asyncio.gather(*tasks)  # Parallel!          │
│                                                                 │
│  Result: ~3-5x faster scans                                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                 PHASE 7: TESTING (Days 8-10)                    │
│                                                                 │
│  tests/cloud/                                                  │
│  ├── test_aws_scanner.py (mock boto3)                          │
│  ├── test_azure_scanner.py (mock Azure SDK)                    │
│  ├── test_gcp_scanner.py (mock GCP SDK)                        │
│  ├── test_registry.py                                          │
│  ├── test_error_handling.py                                    │
│  ├── mocks/aws_mock.py  ← Fake AWS responses                   │
│  ├── mocks/azure_mock.py                                       │
│  └── fixtures/ ← Test data                                     │
│                                                                 │
│  Coverage: 85%+ on core scanning logic                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Dependency Graph

```
Foundation (Phase 1)
├─ exceptions.py
├─ schemas.py
└─ base.py
   │
   └─ Registry (Phase 2)
      ├─ registry.py
      └─ All scanners updated
         │
         ├─ Error Handling (Phase 3)
         │  ├─ retry.py
         │  └─ rate_limiter.py
         │  │
         │  ├─ Coverage (Phase 4) [parallel with error handling]
         │  │  ├─ aws_scanner.py (expanded)
         │  │  ├─ azure_scanner.py (expanded)
         │  │  └─ gcp_scanner.py (completed)
         │  │
         │  ├─ Flow (Phase 5)
         │  │  └─ phases.py
         │  │     └─ cloud_scan_runner.py (refactored)
         │  │
         │  ├─ Performance (Phase 6)
         │  │  └─ connection_pool.py
         │  │
         │  └─ Testing (Phase 7)
         │     └─ Full test suite
         │
         └─ Deployment
            └─ Production ready!
```

---

## Key Files & Lines of Code

### Foundation Files (LOC)
- `exceptions.py`: ~100 lines (8 exception classes)
- `schemas.py`: ~200 lines (3 dataclasses, 4 enums)
- `base.py`: ~150 lines (CloudScanner ABC, ScannerMetadata)

**Total Phase 1**: ~450 lines (easy to review)

### Registry (LOC)
- `registry.py`: ~300 lines (singleton, metadata tracking)

**Total Phase 2**: ~300 lines

### Error Handling (LOC)
- `retry.py`: ~100 lines (retry decorator, backoff)
- `rate_limiter.py`: ~150 lines (token bucket)
- Updated `cloud_scan_runner.py`: +300 lines (error handling throughout)

**Total Phase 3**: ~550 lines

### Coverage (LOC per provider)
- AWS: aws_scanner.py from 696 → 1000+ lines (expanded)
- Azure: azure_scanner.py from ~300 → 800+ lines
- GCP: gcp_scanner.py from ~200 → 600+ lines

**Total Phase 4**: ~1500 lines (heavy lifting)

### Flow & Performance (LOC)
- `phases.py`: ~400 lines (6 phase classes)
- `connection_pool.py`: ~200 lines
- `cloud_scan_runner.py`: refactored, -200 lines (cleaner)

**Total Phases 5-6**: ~400 lines

### Testing (LOC)
- Test files: ~2000 lines
- Mocks: ~500 lines
- Fixtures: ~300 lines

**Total Phase 7**: ~2800 lines

---

## Overall Statistics

| Metric | Current | Target |
|--------|---------|--------|
| **Total Scanner Modules** | 8 | 37+ |
| **Scanner Interface** | None | CloudScanner ABC |
| **Registry System** | No | Yes (singleton) |
| **Exception Classes** | 1 (generic) | 8+ (typed) |
| **Finding Schema** | 4 variants | 1 unified |
| **AWS Services Covered** | 5 | 15+ |
| **Azure Services Covered** | 2 | 12+ |
| **GCP Services Covered** | 2 | 10+ |
| **Error Handling** | Generic try/except | Typed exceptions + retry |
| **Concurrency** | Limited | Full async/await + pooling |
| **Rate Limiting** | None | Per-provider limits |
| **Test Coverage** | ~10% | 85%+ |
| **Lines of Code** | ~5000 | ~10000 |

---

## Backwards Compatibility

### Breaking Changes (Minimal)
```python
# OLD API (still works via adapter)
result = await CloudSecurityScanner.scan_aws(...)

# NEW API (preferred)
registry = CloudScannerRegistry()
scanners = registry.get_scanners('aws', 'cspm')
findings = await asyncio.gather(*[s.scan() for s in scanners])
```

### Compatibility Layer
```python
# In cloud_scanner.py - add adapter methods
async def scan_aws(self, ...):
    """Deprecated: Use CloudScannerRegistry instead"""
    scanner = AWSCSPMScanner(...)
    return await scanner.scan()
```

This allows gradual migration without breaking existing code.

---

## Checklist for Implementation

### Phase 1 (Foundation - ~2 hours)
- [ ] Create exceptions.py with 8 exception classes
- [ ] Create schemas.py with unified CloudFinding
- [ ] Create base.py with CloudScanner ABC interface
- [ ] Run linter (flake8), type checker (mypy)

### Phase 2 (Registry - ~4 hours)
- [ ] Create registry.py with CloudScannerRegistry
- [ ] Update aws_scanner.py to inherit from CloudScanner
- [ ] Update azure_scanner.py to inherit from CloudScanner
- [ ] Update gcp_scanner.py to inherit from CloudScanner
- [ ] Register all scanners in __init__.py

### Phase 3 (Error Handling - ~6 hours)
- [ ] Create retry.py with exponential backoff
- [ ] Create rate_limiter.py with token bucket
- [ ] Update cloud_scan_runner.py with try/except blocks
- [ ] Update api/routes/cloud.py with new error types
- [ ] Test error scenarios (credential failure, rate limit, timeout)

### Phase 4 (Coverage - ~24 hours)
- [ ] Add 10 new AWS scanners (Lambda, Secrets, DynamoDB, KMS, CloudFront, API GW, SNS/SQS)
- [ ] Add 10 new Azure scanners (Storage, KeyVault, AppService, SQL, AD, NSG, Cosmos, etc.)
- [ ] Add 8 new GCP scanners (GCS, IAM, Compute, Functions, SQL, VPC, etc.)
- [ ] Test each scanner with mock data
- [ ] Verify all return unified CloudFinding

### Phase 5 (Flow - ~6 hours)
- [ ] Create phases.py with CloudPhase interface
- [ ] Implement 6 phase classes
- [ ] Refactor cloud_scan_runner.py to use phases
- [ ] Add phase checkpoints for resume capability

### Phase 6 (Performance - ~6 hours)
- [ ] Create connection_pool.py with client pooling
- [ ] Implement concurrent scanner execution
- [ ] Add metrics collection (scan time, findings per provider)
- [ ] Performance test (target: <5min for full scan)

### Phase 7 (Testing - ~12 hours)
- [ ] Create unit tests for each scanner
- [ ] Create integration tests (multi-provider)
- [ ] Create mock cloud APIs (boto3, Azure SDK, GCP SDK)
- [ ] Achieve 85%+ code coverage

---

## Start Here!

**NEXT STEP**: Implement Phase 1 (Foundation) - creates the groundwork for everything else.

```bash
# Phase 1 tasks
1. Create attacks/cloud/exceptions.py
2. Create attacks/cloud/schemas.py
3. Create attacks/cloud/base.py

# Takes ~2 hours
# Unblocks: Phase 2, 3, 4 (parallel work)
```

