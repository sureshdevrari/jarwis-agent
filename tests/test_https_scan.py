"""Test HTTPS web scanning - With MITM proxy"""
import asyncio
import logging
import sys
import traceback

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout,
    force=True
)

async def test():
    from core.web_scan_runner import WebScanRunner
    
    config = {
        'target': {'url': 'https://httpbin.org'},
        'auth': {'enabled': False},
        'browser': {'headless': False},  # Show browser
        'crawl': {'max_pages': 2, 'max_depth': 1},  # Small crawl
        'proxy': {'port': 8889, 'enabled': True},  # Enable proxy
        'rate_limit': 5,
        'timeout': 30,
        'report': {'output_dir': 'reports', 'formats': ['html', 'json']}
    }
    
    print('='*60, flush=True)
    print('Testing HTTPS scan WITH MITM proxy...', flush=True)
    print('='*60, flush=True)
    
    try:
        runner = WebScanRunner(config)
        result = await runner.run()
        
        print('\n' + '='*60, flush=True)
        print('SCAN RESULT:', flush=True)
        print('='*60, flush=True)
        print(f"  Status: {result.get('status')}", flush=True)
        
        total = result.get('total_vulnerabilities', 0)
        partial = result.get('partial_findings', 0)
        print(f"  Total Findings: {total if total else partial}", flush=True)
        
        if result.get('error'):
            print(f"  Error: {result.get('error')}", flush=True)
        
        if result.get('report'):
            paths = result.get('report', {}).get('report_paths', {})
            print(f"  Report paths: {paths}", flush=True)
        
        if result.get('checkpoint_summary'):
            summary = result.get('checkpoint_summary', {})
            print(f"  Phases completed: {list(summary.get('phases', {}).keys())}", flush=True)
        
        print('='*60, flush=True)
        return result
    except Exception as e:
        print(f"\n\nERROR: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
        return {"status": "error", "error": str(e)}

if __name__ == "__main__":
    try:
        asyncio.run(test())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user", flush=True)
    except Exception as e:
        print(f"\n\nFatal error: {type(e).__name__}: {e}", flush=True)
        traceback.print_exc()
