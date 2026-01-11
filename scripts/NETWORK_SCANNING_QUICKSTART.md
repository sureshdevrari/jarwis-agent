"""
NETWORK SCANNING ARCHITECTURE REFACTOR - QUICK START GUIDE

This is a comprehensive refactor of network scanning to follow
Jarwis' layered architecture. Follow these steps to deploy.
"""

# ============================================================================
# STEP 1: RUN DATABASE MIGRATION
# ============================================================================

"""
The migration script creates:
- agents table
- config column in scan_history
- checkpoint_data column in scan_history

Important: This is a one-time setup. Run before starting services.
"""

# Command:
python migrate_network_scanning.py

# Expected output:
# ✓ Tables created successfully
# ✓ Added 'config' column
# ✓ Added 'checkpoint_data' column
# ✓ Migration completed successfully!

# Verify:
python -c "from database.models import Agent; print('✓ Agent model loaded')"


# ============================================================================
# STEP 2: VALIDATE ARCHITECTURE
# ============================================================================

"""
Ensure all imports follow the layered architecture rules:
- API routes only call services
- Services call core and database
- Core calls attacks
- No circular imports
"""

# Command:
python validate_network_architecture.py

# Expected result:
# RESULT: PASSED ✅
# Architecture validation successful! Ready for deployment.


# ============================================================================
# STEP 3: TEST API ENDPOINTS
# ============================================================================

# Make sure FastAPI server is running:
# python -m uvicorn api.server:app --reload

import asyncio
import httpx
import json

TOKEN = "your-jwt-token-here"  # Get from login
BASE_URL = "http://localhost:8000"

async def test_network_scanning():
    """Test network scanning API"""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        
        # Test 1: Start network scan
        print("\n[1] Starting network scan...")
        response = await client.post(
            f"{BASE_URL}/api/network/scan",
            json={
                "targets": "8.8.8.8",
                "profile": "quick"
            },
            headers=headers
        )
        scan_data = response.json()
        scan_id = scan_data['scan_id']
        print(f"✓ Scan created: {scan_id}")
        
        # Test 2: Get scan status
        print(f"\n[2] Getting scan status...")
        response = await client.get(
            f"{BASE_URL}/api/network/scan/{scan_id}",
            headers=headers
        )
        status = response.json()
        print(f"✓ Status: {status['status']}")
        
        # Test 3: List scans
        print(f"\n[3] Listing network scans...")
        response = await client.get(
            f"{BASE_URL}/api/network/scans",
            headers=headers
        )
        scans_data = response.json()
        print(f"✓ Found {scans_data['total']} scans")
        
        # Test 4: Get dashboard summary
        print(f"\n[4] Getting dashboard summary...")
        response = await client.get(
            f"{BASE_URL}/api/network/dashboard/summary",
            headers=headers
        )
        summary = response.json()
        print(f"✓ Total CVEs: {summary['data']['total_cves']}")

# Run tests
asyncio.run(test_network_scanning())


# ============================================================================
# STEP 4: TEST AGENT MANAGEMENT (OPTIONAL)
# ============================================================================

"""
If you want to enable private network scanning via Jarwis Agents,
register an agent for your network.
"""

async def test_agents():
    """Test agent management"""
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        
        # Register agent
        print("\n[Agent] Registering agent...")
        response = await client.post(
            f"{BASE_URL}/api/network/agents",
            json={
                "agent_name": "Internal Network Agent",
                "description": "Scans 10.0.0.0/8 network",
                "network_ranges": ["10.0.0.0/8"]
            },
            headers=headers
        )
        agent = response.json()
        print(f"✓ Agent registered: {agent['agent_id']}")
        print(f"✓ Agent key: {agent['agent_key']} (store securely!)")
        
        # List agents
        print(f"\n[Agent] Listing agents...")
        response = await client.get(
            f"{BASE_URL}/api/network/agents",
            headers=headers
        )
        agents_data = response.json()
        print(f"✓ Found {agents_data['total']} agents")

asyncio.run(test_agents())


# ============================================================================
# STEP 5: VERIFY DATABASE PERSISTENCE
# ============================================================================

"""
Check that scans are persisted to the database.
"""

import sqlite3
from pathlib import Path

def verify_database():
    """Verify database has network scan records"""
    db_path = Path(__file__).parent.parent / "data" / "jarwis.db"
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    
    # Check scan_history table
    print("\n[Database] Checking scan_history...")
    cursor.execute("""
        SELECT COUNT(*) FROM scan_history 
        WHERE scan_type = 'network'
    """)
    count = cursor.fetchone()[0]
    print(f"✓ Network scans in database: {count}")
    
    # Check findings
    print(f"\n[Database] Checking findings...")
    cursor.execute("""
        SELECT COUNT(*) FROM findings
        WHERE scan_id IN (
            SELECT id FROM scan_history 
            WHERE scan_type = 'network'
        )
    """)
    findings_count = cursor.fetchone()[0]
    print(f"✓ Findings from network scans: {findings_count}")
    
    # Check agents
    print(f"\n[Database] Checking agents...")
    cursor.execute("SELECT COUNT(*) FROM agents")
    agents_count = cursor.fetchone()[0]
    print(f"✓ Registered agents: {agents_count}")
    
    conn.close()

verify_database()


# ============================================================================
# STEP 6: REVIEW ARCHITECTURE (DOCUMENTATION)
# ============================================================================

"""
Read these documents to understand the implementation:

1. NETWORK_SCANNING_SUMMARY.md
   - High-level overview
   - What was changed and why
   - Success metrics

2. NETWORK_SCANNING_REFACTOR.md
   - Complete implementation guide
   - Architecture details
   - Remaining work

3. Code comments in:
   - services/network_service.py
   - core/network_scan_runner.py
   - api/routes/network.py
   - services/agent_service.py
"""


# ============================================================================
# STEP 7: NEXT PHASES (NOT YET IMPLEMENTED)
# ============================================================================

"""
These are the remaining pieces to complete the refactor:

Phase 1: Registry Pattern (2-3 hours)
- Update attacks/network/orchestrator.py
- Use ScannerRegistry for auto-discovery
- See: attacks/scanner_registry.py

Phase 2: Network Reporting (3-4 hours)
- Add generate_network_report() to core/reporters.py
- Create templates/network_report.html
- Generate HTML/PDF reports like web scanning

Phase 3: Performance Optimization (1-2 hours)
- Implement tool availability caching
- Create core/tool_registry.py
- Reduce startup overhead
"""


# ============================================================================
# DEPLOYMENT CHECKLIST
# ============================================================================

"""
Before deploying to production:

Pre-Deployment
□ Run migrate_network_scanning.py
□ Run validate_network_architecture.py
□ Test all API endpoints
□ Verify database persistence
□ Review error handling
□ Check logging output

Deployment
□ Backup database
□ Stop current service
□ Deploy new code
□ Run migrations
□ Validate with tests
□ Monitor logs

Post-Deployment
□ Verify scans still work
□ Check dashboard stats
□ Test agent registration (if enabled)
□ Monitor performance
□ Collect user feedback

Rollback Plan
□ Stop service
□ Restore previous code
□ Restore database backup
□ Verify with tests
□ Monitor logs
"""


# ============================================================================
# TROUBLESHOOTING
# ============================================================================

"""
Common Issues & Solutions:

1. "Agent model not found"
   - Run: python migrate_network_scanning.py
   - Check: database/models.py has Agent class

2. "Import error from services.network_service"
   - Ensure file: services/network_service.py exists
   - Check: No circular imports
   - Verify: All dependencies installed

3. "Scans not in database"
   - Check: migrate_network_scanning.py was run
   - Verify: ScanHistory table exists and has records
   - Look at: API response status code

4. "Agent registration fails"
   - Verify: Network ranges are valid CIDR notation
   - Check: User is authenticated (valid JWT)
   - Review: agents table created in database

5. "Performance issues"
   - Enable tool caching (Phase 3)
   - Check: Database indexes on user_id
   - Profile: Slow queries
   - Review: Concurrent scan limits
"""


# ============================================================================
# SUPPORT
# ============================================================================

"""
For detailed information:

1. Read the implementation guides:
   - NETWORK_SCANNING_SUMMARY.md
   - NETWORK_SCANNING_REFACTOR.md

2. Check code documentation:
   - services/network_service.py (service layer)
   - core/network_scan_runner.py (orchestrator)
   - api/routes/network.py (HTTP handlers)
   - services/agent_service.py (agent management)

3. Review architecture rules:
   - implementation_rules/01_ROOT_ARCHITECTURE.md
   - implementation_rules/03_LAYERED_RULES.md

4. Run validation:
   - python validate_network_architecture.py

5. Test functionality:
   - See "STEP 3: TEST API ENDPOINTS" above
"""

print("\n✅ Network Scanning Architecture Refactor - Ready to Deploy!")
print("📖 Next: Read NETWORK_SCANNING_SUMMARY.md for overview")
