"""
Test script for Human Behavior Simulator

Demonstrates:
- Stealth patches
- Human-like mouse movements
- Natural typing patterns
- Page exploration

Run with: python -m pytest tests/test_human_behavior.py -v -s
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.browser import BrowserController


async def test_basic_human_behavior():
    """Test basic human-like interactions"""
    
    print("\n=== Testing Human Behavior Simulator ===\n")
    
    # Initialize browser with human behavior enabled
    browser = BrowserController(
        headless=False,  # Visible to see the behavior
        enable_human_behavior=True
    )
    
    try:
        # Start browser
        print("Starting browser with stealth patches...")
        await browser.start()
        
        # Navigate to test page
        print("\nNavigating to test page...")
        await browser.goto("https://www.google.com")
        await asyncio.sleep(1)
        
        # Check if stealth patches worked
        webdriver_status = await browser.page.evaluate('() => navigator.webdriver')
        plugins_count = await browser.page.evaluate('() => navigator.plugins.length')
        has_chrome = await browser.page.evaluate('() => !!window.chrome')
        
        print(f"\n✓ Stealth Check:")
        print(f"  navigator.webdriver = {webdriver_status} (should be False)")
        print(f"  navigator.plugins.length = {plugins_count} (should be > 0)")
        print(f"  window.chrome exists = {has_chrome} (should be True)")
        
        # Test natural page exploration
        print("\n✓ Performing natural page exploration (random movements)...")
        await browser.explore_page_naturally(duration=3.0)
        
        # Test human-like search interaction
        if browser._human:
            print("\n✓ Testing human-like typing in search box...")
            search_selector = 'textarea[name="q"]'
            
            try:
                await browser._human.human_type(
                    search_selector, 
                    "JARWIS penetration testing"
                )
                print("  Typed with variable speed and natural delays")
                
                await asyncio.sleep(1)
                
                print("\n✓ Testing human-like click on search button...")
                # Google search button
                await browser._human.human_click('input[name="btnK"]')
                print("  Clicked with mouse movement and natural delay")
                
                await asyncio.sleep(2)
                
            except Exception as e:
                print(f"  Note: Interaction test skipped - {e}")
        
        print("\n=== Test Complete ===")
        print("\nHuman behavior features demonstrated:")
        print("  ✓ Stealth patches applied (hidden automation)")
        print("  ✓ Bezier curve mouse movements")
        print("  ✓ Variable typing speed")
        print("  ✓ Natural pauses and exploration")
        print("  ✓ Overshoot correction")
        
        await asyncio.sleep(3)
        
    finally:
        await browser.close()


async def test_login_simulation():
    """Simulate human-like login behavior"""
    
    print("\n=== Testing Login Simulation ===\n")
    
    browser = BrowserController(headless=False, enable_human_behavior=True)
    
    try:
        await browser.start()
        
        # Navigate to a login page (example)
        print("Navigating to login page...")
        await browser.goto("https://accounts.google.com")
        await asyncio.sleep(2)
        
        # Natural exploration before login
        print("\n✓ Exploring page naturally (appears human)...")
        await browser.explore_page_naturally(duration=2.0)
        
        print("\n✓ Ready for human-like login interaction")
        print("  This would type username/password with:")
        print("  - Variable speed (50-200ms per keystroke)")
        print("  - Random pauses (thinking time)")
        print("  - Curved mouse movements")
        print("  - Natural click delays")
        
        await asyncio.sleep(3)
        
    finally:
        await browser.close()


if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════════════════════════╗
║         JARWIS - Human Behavior Simulator Test               ║
║                                                                ║
║  This demonstrates bot detection evasion techniques:          ║
║  • Stealth patches (hide navigator.webdriver)                 ║
║  • Bezier curve mouse movements                               ║
║  • Variable typing speed                                      ║
║  • Natural pauses and exploration                             ║
║  • Overshoot correction                                       ║
║                                                                ║
║  Watch the browser window to see human-like behavior!         ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Run basic test
        asyncio.run(test_basic_human_behavior())
        
        # Ask if user wants to see login simulation
        print("\n" + "="*60)
        response = input("\nRun login simulation test? (y/n): ")
        if response.lower() == 'y':
            asyncio.run(test_login_simulation())
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
