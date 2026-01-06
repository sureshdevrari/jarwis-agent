# Session 2026-01-04 - AWS Deployment Planning

## Developer Input Log

### Request 1: Complete AWS Deployment Plan
**Query:**
> Create a full plan to deploy the complete project in AWS step by step, what to do first, where to move files, how to connect with each other. Also want to use Bedrock for replacing Ollama. Make a proper plan with high level architecture and save PDF as deployplan.pdf

**Resolution:**
- Created comprehensive deployment documentation:
  - `docs/deployplan.pdf` - Main PDF deployment guide
  - `docs/deployplan.md` - Markdown version with all commands
  - `docs/bedrock_integration.py` - Code to replace Ollama with Bedrock
  - `docs/generate_pdf.py` - Script to regenerate PDF

**Deployment Plan Contents:**
1. Phase 1: AWS Account Setup & Prerequisites
2. Phase 2: VPC, Subnets, Security Groups
3. Phase 3: RDS PostgreSQL Database
4. Phase 4: Docker & ECR Setup
5. Phase 5: Amazon Bedrock Integration (replaces Ollama)
6. Phase 6: ECS Fargate Deployment
7. Phase 7: Frontend S3 + CloudFront
8. Phase 8: DNS & SSL Certificates
9. Phase 9: Monitoring & Logging
10. Phase 10: CI/CD Pipeline

---

### Request 2: Backend Process Location in AWS
**Query:**
> Where our backend process will run in AWS?

**Answer:**
- **Amazon ECS Fargate** (Serverless Containers)
- Configuration:
  - Launch Type: Fargate (no EC2 management)
  - CPU: 1 vCPU
  - Memory: 2 GB RAM
  - Tasks: 2 (for high availability)
  - Auto-scaling: Up to 10 tasks

**Architecture Flow:**
```
User → Route 53 → ALB → ECS Fargate (Private Subnet)
                           ├── Task 1: Jarwis API
                           └── Task 2: Jarwis API
                                  ↓
                           Amazon Bedrock → RDS PostgreSQL
```

---

### Request 3: Multiple Concurrent Scans
**Query:**
> If multiple users scan at the same time then?

**Answer:**
- Current 2GB RAM per task limits to 1-2 concurrent scans (Playwright uses ~1GB)
- Recommended architecture: **SQS Queue + Dedicated Workers**

**Proposed Solution:**
```
[User Requests] → [API Server] → [SQS Queue]
                                      ↓
                            [Scan Worker Pool]
                            ├── Worker 1
                            ├── Worker 2
                            └── Worker N (auto-scaled)
```

**Benefits:**
- Non-blocking API (users don't wait)
- Workers scale based on queue depth
- Fault tolerant (failed scans retry)
- Cost efficient (workers scale to zero when idle)

**Worker Configuration:**
| Type | CPU | Memory | Max Tasks |
|------|-----|--------|-----------|
| API Server | 512 (0.5 vCPU) | 1024 MB | 4 |
| Scan Worker | 2048 (2 vCPU) | 4096 MB | 20 |

---

### Request 4: AWS Billing - Idle vs Active Costs
**Query:**
> The bill only happens when we run the scan or running it alone will cost me?

**Answer:**

**Always Running Costs (24/7):**
| Service | Monthly Cost |
|---------|-------------|
| RDS PostgreSQL | ~$120 |
| NAT Gateway | ~$45 |
| ALB | ~$18 |
| Route 53 | ~$0.50 |
| Secrets Manager | ~$1 |
| **Fixed Total** | **~$185/month** |

**Pay-Per-Use Costs:**
| Service | Idle Cost | Per Scan Cost |
|---------|-----------|---------------|
| ECS Fargate | $0 (if scaled to 0) | ~$0.04-0.08/hour |
| Amazon Bedrock | $0 | ~$0.01-0.05/scan |
| CloudWatch Logs | ~$0.50/GB | ~$0.50/GB |

**Cost Scenarios:**
- Idle (no users): ~$185-218/month
- Light usage (10 scans/day): ~$240/month
- Heavy usage (100 scans/day): ~$385/month

**Cost Optimization Recommendations:**
1. Use RDS Serverless v2 (reduces to ~$50 when idle)
2. Use Fargate Spot for workers (70% savings)
3. Replace NAT Gateway with VPC Endpoints (saves $45)
4. Scale ECS to 0 when idle

**Optimized Architecture Idle Cost: ~$100/month**

---

## Files Created/Modified

| File | Action | Description |
|------|--------|-------------|
| `docs/deployplan.pdf` | Created | AWS deployment guide PDF |
| `docs/deployplan.md` | Created | Markdown deployment guide |
| `docs/bedrock_integration.py` | Created | Bedrock code integration |
| `docs/generate_pdf.py` | Created | PDF generation script |

---

## Key Decisions Made

1. **Container Platform:** ECS Fargate (serverless, no EC2 management)
2. **AI Provider:** Amazon Bedrock with Claude 3.5 Sonnet (replacing Ollama)
3. **Database:** RDS PostgreSQL with Multi-AZ
4. **Frontend Hosting:** S3 + CloudFront CDN
5. **Scan Architecture:** SQS queue with auto-scaling workers
6. **Cost Optimization:** Fargate Spot, RDS Serverless v2, VPC Endpoints

---

## Next Steps

1. [ ] Update deployment plan PDF with queue-based architecture
2. [ ] Implement Bedrock integration in `core/ai_planner.py`
3. [ ] Add SQS integration for scan queue
4. [ ] Create Dockerfile.api and Dockerfile.worker
5. [ ] Set up CI/CD with GitHub Actions
6. [ ] Test deployment in AWS sandbox environment

---

*Session Date: January 4, 2026*
*Topics: AWS Deployment, Bedrock Integration, Cost Analysis, Scalability*
