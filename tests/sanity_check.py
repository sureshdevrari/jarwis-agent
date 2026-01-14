"""
Jarwis End-to-End Sanity Check
Tests the complete flow from frontend API to backend scan runners
"""

import sys
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def run_sanity_check():
    print('=' * 70)
    print('JARWIS END-TO-END SANITY CHECK')
    print('=' * 70)

    errors = []
    warnings = []

    # 1. Check API Routes can import
    print('\n[1] CHECKING API ROUTES IMPORT...')
    try:
        from api.routes import api_router
        print('   ✅ api_router imported successfully')
    except Exception as e:
        errors.append(f'API Routes: {e}')
        print(f'   ❌ FAILED: {e}')

    # 2. Check individual route modules
    print('\n[2] CHECKING INDIVIDUAL ROUTE MODULES...')
    route_modules = [
        ('api.routes.scans', 'Web Scans'),
        ('api.routes.mobile', 'Mobile Scans'),
        ('api.routes.network', 'Network Scans'),
        ('api.routes.cloud', 'Cloud Scans'),
        ('api.routes.sast', 'SAST Scans'),
    ]
    for module, name in route_modules:
        try:
            __import__(module)
            print(f'   ✅ {name} route OK')
        except Exception as e:
            errors.append(f'{name} Route: {e}')
            print(f'   ❌ {name}: {e}')

    # 3. Check Services Layer
    print('\n[3] CHECKING SERVICES LAYER...')
    services = [
        ('services.scan_service', 'ScanService'),
        ('services.mobile_service', 'MobileScanService'),
        ('services.network_service', 'NetworkScanService'),
        ('services.cloud_service', 'CloudService'),
        ('services.sast_service', 'SASTService'),
    ]
    for module, svc_name in services:
        try:
            mod = __import__(module, fromlist=[svc_name])
            if hasattr(mod, svc_name):
                print(f'   ✅ {svc_name} OK')
            else:
                warnings.append(f'{svc_name} not found in {module}')
                print(f'   ⚠️  {svc_name} not exported from {module}')
        except Exception as e:
            errors.append(f'{svc_name}: {e}')
            print(f'   ❌ {svc_name}: {e}')

    # 4. Check Core Scan Runners
    print('\n[4] CHECKING CORE SCAN RUNNERS...')
    runners = [
        ('core.web_scan_runner', 'WebScanRunner'),
        ('core.mobile_attack_engine', 'MobileAttackEngine'),
        ('core.network_scan_runner', 'NetworkScanRunner'),
        ('core.cloud_scan_runner', 'CloudScanRunner'),
        ('core.sast_scan_runner', 'SASTScanRunner'),
    ]
    for module, cls_name in runners:
        try:
            mod = __import__(module, fromlist=[cls_name])
            if hasattr(mod, cls_name):
                print(f'   ✅ {cls_name} OK')
            else:
                warnings.append(f'{cls_name} not found in {module}')
                print(f'   ⚠️  {cls_name} not exported from {module}')
        except Exception as e:
            errors.append(f'{cls_name}: {e}')
            print(f'   ❌ {cls_name}: {e}')

    # 5. Check Attack Registries
    print('\n[5] CHECKING ATTACK REGISTRIES...')
    registries = [
        ('attacks.unified_registry', 'UnifiedScannerRegistry'),
        ('attacks.scanner_registry', 'scanner_registry'),
        ('attacks.registry', 'AttackRegistry'),
        ('core.scanner_registry', 'ScannerRegistry'),
        ('core.cloud_scanner_registry', 'CloudScannerRegistry'),
    ]
    for module, cls_name in registries:
        try:
            mod = __import__(module, fromlist=[cls_name])
            if hasattr(mod, cls_name):
                obj = getattr(mod, cls_name)
                if callable(obj):
                    print(f'   ✅ {cls_name} OK (class/function)')
                else:
                    print(f'   ✅ {cls_name} OK (instance)')
            else:
                warnings.append(f'{cls_name} not in {module}')
                print(f'   ⚠️  {cls_name} not in {module}')
        except Exception as e:
            errors.append(f'{module}: {e}')
            print(f'   ❌ {module}: {e}')

    # 6. Check Web Attack Modules
    print('\n[6] CHECKING WEB ATTACK MODULES (sample)...')
    web_attacks = [
        ('attacks.web.a01_broken_access.idor_scanner', 'IDOR'),
        ('attacks.web.a03_injection.xss.reflected', 'XSS Reflected'),
        ('attacks.web.a03_injection.sqli.error_based', 'SQLi Error Based'),
        ('attacks.web.a07_auth_failures.auth_scanner', 'Auth Scanner'),
        ('attacks.web.a10_ssrf.ssrf.basic', 'SSRF Basic'),
    ]
    for module, name in web_attacks:
        try:
            __import__(module)
            print(f'   ✅ {name} OK')
        except Exception as e:
            errors.append(f'Web/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # 7. Check Network Attack Modules
    print('\n[7] CHECKING NETWORK ATTACK MODULES...')
    network_attacks = [
        ('attacks.network.port_scanner', 'Port Scanner'),
        ('attacks.network.service_detector', 'Service Detector'),
        ('attacks.network.vuln_scanner', 'Vuln Scanner'),
        ('attacks.network.network_scanner', 'Network Scanner'),
    ]
    for module, name in network_attacks:
        try:
            __import__(module)
            print(f'   ✅ {name} OK')
        except Exception as e:
            errors.append(f'Network/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # 8. Check Mobile Attack Modules
    print('\n[8] CHECKING MOBILE ATTACK MODULES...')
    mobile_attacks = [
        ('attacks.mobile.static.static_analyzer', 'Static Analyzer'),
        ('attacks.mobile.dynamic.runtime_analyzer', 'Runtime Analyzer'),
        ('attacks.mobile.api.mobile_mitm', 'Mobile MITM'),
        ('attacks.mobile.platform.android', 'Android Platform'),
    ]
    for module, name in mobile_attacks:
        try:
            __import__(module)
            print(f'   ✅ {name} OK')
        except Exception as e:
            errors.append(f'Mobile/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # 9. Check Cloud Attack Modules
    print('\n[9] CHECKING CLOUD ATTACK MODULES...')
    cloud_attacks = [
        ('attacks.cloud.aws.aws_scanner', 'AWS Scanner'),
        ('attacks.cloud.azure.azure_scanner', 'Azure Scanner'),
        ('attacks.cloud.gcp.gcp_scanner', 'GCP Scanner'),
        ('attacks.cloud.cnapp.ciem_scanner', 'CIEM Scanner'),
    ]
    for module, name in cloud_attacks:
        try:
            __import__(module)
            print(f'   \u2705 {name} OK')
        except Exception as e:
            errors.append(f'Cloud/{name}: {e}')
            print(f'   \u274c {name}: {e}')

    # 10. Check SAST Attack Modules
    print('\n[10] CHECKING SAST ATTACK MODULES...')
    sast_attacks = [
        ('attacks.sast.analyzers.secret_scanner', 'Secret Scanner'),
        ('attacks.sast.analyzers.dependency_scanner', 'Dependency Scanner'),
        ('attacks.sast.analyzers.code_analyzer', 'Code Analyzer'),
        ('attacks.sast.providers.github_scanner', 'GitHub Scanner'),
        ('attacks.sast.providers.gitlab_scanner', 'GitLab Scanner'),
    ]
    for module, name in sast_attacks:
        try:
            __import__(module)
            print(f'   ✅ {name} OK')
        except Exception as e:
            errors.append(f'SAST/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # 11. Check Database Layer
    print('\n[11] CHECKING DATABASE LAYER...')
    db_modules = [
        ('database.connection', 'get_db'),
        ('database.models', 'User'),
        ('database.models', 'ScanHistory'),
        ('database.schemas', 'ScanCreate'),
        ('database.crud', 'crud'),
    ]
    for module, name in db_modules:
        try:
            mod = __import__(module, fromlist=[name])
            if hasattr(mod, name):
                print(f'   ✅ {name} OK')
            else:
                warnings.append(f'{name} not in {module}')
                print(f'   ⚠️  {name} not in {module}')
        except Exception as e:
            errors.append(f'DB/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # 12. Check WebSocket for real-time updates
    print('\n[12] CHECKING WEBSOCKET LAYER...')
    ws_funcs = [
        ('api.websocket', 'broadcast_scan_progress'),
        ('api.websocket', 'broadcast_scan_status'),
        ('api.websocket', 'broadcast_finding'),
    ]
    for module, name in ws_funcs:
        try:
            mod = __import__(module, fromlist=[name])
            if hasattr(mod, name):
                print(f'   ✅ {name} OK')
            else:
                warnings.append(f'{name} not in {module}')
                print(f'   ⚠️  {name} not in {module}')
        except Exception as e:
            errors.append(f'WS/{name}: {e}')
            print(f'   ❌ {name}: {e}')

    # Summary
    print('\n' + '=' * 70)
    print('SUMMARY')
    print('=' * 70)
    print(f'ERRORS:   {len(errors)}')
    print(f'WARNINGS: {len(warnings)}')
    
    if errors:
        print('\n❌ ERRORS FOUND:')
        for e in errors:
            print(f'   - {e}')
    
    if warnings:
        print('\n⚠️  WARNINGS:')
        for w in warnings:
            print(f'   - {w}')
    
    print('=' * 70)
    
    return len(errors), len(warnings)


if __name__ == '__main__':
    run_sanity_check()
