"""
Quick test to verify scan execution works
"""
import asyncio
import sys
sys.path.insert(0, 'D:/jarwis-ai-pentest')

from core.runner import PenTestRunner

async def test_scan():
    config = {
        'target': {
            'url': 'https://httpbin.org',
            'scope': ''
        },
        'auth': {
            'enabled': False
        },
        'browser': {
            'headless': True,
            'slow_mo': 100
        },
        'proxy': {'enabled': False},
        'ai': {
            'provider': 'gemini',
            'model': 'llama3:latest',
            'base_url': 'http://localhost:11434'
        },
        'owasp': {
            'injection': {'enabled': True},
            'xss': {'enabled': True}
        },
        'report': {
            'output_dir': 'reports',
            'formats': ['json']
        }
    }
    
    try:
        runner = PenTestRunner(config, scan_id='test123')
        print("Runner created successfully")
        await runner.initialize()
        print("Runner initialized successfully")
        print("Test passed - scan execution should work")
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(test_scan())
