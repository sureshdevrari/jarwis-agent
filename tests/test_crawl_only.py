"""Test crawling directly without full scan flow"""
import asyncio
import sys

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

async def test_crawl():
    print("Starting crawl test...", flush=True)
    
    from core.browser import BrowserController
    
    browser = BrowserController(headless=False)
    
    try:
        print("Starting browser...", flush=True)
        await browser.start()
        print("Browser started!", flush=True)
        
        print("Navigating to httpbin.org...", flush=True)
        await browser.goto("https://httpbin.org", timeout=30000)
        print("Navigation complete!", flush=True)
        
        # Wait to see the page
        await asyncio.sleep(5)
        
        print("Crawling...", flush=True)
        urls = await browser.discover_links("https://httpbin.org", max_depth=1, max_urls=5)
        print(f"Found {len(urls)} URLs: {urls}", flush=True)
        
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", flush=True)
        import traceback
        traceback.print_exc()
    finally:
        print("Closing browser...", flush=True)
        await browser.close()
        print("Done!", flush=True)

if __name__ == "__main__":
    asyncio.run(test_crawl())
