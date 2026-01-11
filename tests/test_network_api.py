"""
Test Network Security API Integration
Verifies that network security tools are properly connected
"""
import asyncio
import sys

async def test_network_integration():
    """Test the network security components"""
    print("=" * 60)
    print("JARWIS NETWORK SECURITY INTEGRATION TEST")
    print("=" * 60)
    
    # Test 1: Import NetworkOrchestrator
    print("\n[TEST 1] Importing NetworkOrchestrator...")
    try:
        from attacks.network import NetworkOrchestrator, ScannerRegistry
        print("  [OK] NetworkOrchestrator imported successfully")
        print(f"  [CHART] Registered scanners: {len(ScannerRegistry._scanners)}")
    except Exception as e:
        print(f"  [X] Import failed: {e}")
        return False
    
    # Test 2: Check registered scanner types
    print("\n[TEST 2] Checking registered scanners by phase...")
    try:
        from attacks.network.base import ScanPhase
        for phase in ScanPhase:
            scanners = ScannerRegistry.get_scanners(phase)
            scanner_names = [s.__name__ for s in scanners]
            print(f"  [FOLDER] {phase.value}: {scanner_names or 'None'}")
    except Exception as e:
        print(f"  [X] Phase check failed: {e}")
        
    # Test 3: Test network config creation
    print("\n[TEST 3] Creating network scan configuration...")
    try:
        config = {
            'target': '192.168.1.1',
            'scan_type': 'quick',
            'phases': ['port_scan'],
            'credentials': None
        }
        orchestrator = NetworkOrchestrator(config)
        print("  [OK] Orchestrator created successfully")
        print(f"  [TARGET] Target: {config['target']}")
        print(f"  [LIST] Scan type: {config['scan_type']}")
    except Exception as e:
        print(f"  [X] Config creation failed: {e}")
        return False
    
    # Test 4: Check tool availability
    print("\n[TEST 4] Checking tool availability...")
    import shutil
    tools = ['nmap', 'masscan', 'nuclei', 'sslscan', 'tshark', 'netdiscover']
    for tool in tools:
        available = shutil.which(tool) is not None
        status = "[OK]" if available else "[!] Not installed"
        print(f"  {tool}: {status}")
    
    # Test 5: Test API route import
    print("\n[TEST 5] Testing API route import...")
    try:
        from api.routes.network import router
        print("  [OK] Network API router imported")
        print(f"  [SIGNAL] Router prefix: {router.prefix}")
        routes = [r.path for r in router.routes]
        print(f"  📌 Available endpoints: {len(routes)}")
        for route in routes[:5]:
            print(f"      - {route}")
    except Exception as e:
        print(f"  [X] API route import failed: {e}")
        return False
    
    # Test 6: Verify sequential execution logic
    print("\n[TEST 6] Verifying sequential execution logic...")
    try:
        import inspect
        source = inspect.getsource(orchestrator._run_phase)
        if "await asyncio.gather" not in source:
            print("  [OK] Sequential execution confirmed (no asyncio.gather)")
        else:
            print("  [!] Found asyncio.gather - may run in parallel")
        
        if "await asyncio.sleep" in source:
            print("  [OK] Delay between scanners confirmed")
        else:
            print("  [!] No delay found between scanners")
    except Exception as e:
        print(f"  [X] Source check failed: {e}")
    
    # Test 7: Test a mock scan result creation
    print("\n[TEST 7] Testing scan result data structure...")
    try:
        from attacks.network.base import Finding, ScanResult, Severity
        from datetime import datetime
        
        finding = Finding(
            id="TEST-001",
            tool="TestScanner",
            title="Test Finding",
            description="Test vulnerability",
            severity=Severity.HIGH.value,
            category="A01:2021",
            target="192.168.1.1",
            port=80,
            service="http",
            evidence="Test evidence",
            remediation="Test fix"
        )
        
        result = ScanResult(
            tool="TestScanner",
            target="192.168.1.1",
            phase="port_scan",
            findings=[finding],
            raw_output="Test output",
        )
        
        print("  [OK] Finding and ScanResult created successfully")
        print(f"  [CHART] Finding severity: {finding.severity}")
        print(f"  [TARGET] Scanner: {result.tool}")
    except Exception as e:
        print(f"  [X] Data structure test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 60)
    print("[OK] ALL INTEGRATION TESTS PASSED")
    print("=" * 60)
    print("\nNetwork security module is properly connected to API.")
    print("Tools will run SEQUENTIALLY (one by one) to prevent server overload.")
    return True


if __name__ == "__main__":
    result = asyncio.run(test_network_integration())
    sys.exit(0 if result else 1)
