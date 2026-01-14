# Human Behavior Simulator - Bot Detection Evasion

## Overview

The **Human Behavior Simulator** module simulates human-like browser interactions to evade bot detection systems used by sites like Instagram, Facebook, Gmail, and other complex web applications.

## Why This Matters

Modern websites use sophisticated bot detection that analyzes:
- **Mouse movements** (straight lines = bot, curved paths = human)
- **Typing patterns** (constant speed = bot, variable speed = human)
- **Click timing** (instant = bot, with pauses = human)
- **Browser fingerprints** (`navigator.webdriver = true` = bot)

Without evasion, automated logins trigger **CAPTCHA challenges** or get blocked entirely.

---

## Features Implemented

### ✅ 1. Stealth Patches
Hides automation signals that sites check for:

```javascript
navigator.webdriver         // false (was true)
navigator.plugins.length    // > 0 (was 0 in headless)
window.chrome              // realistic object (was missing)
navigator.languages        // ['en-US', 'en'] (was empty)
```

### ✅ 2. Bezier Curve Mouse Movements
- **Curved paths** instead of straight lines
- **Variable acceleration** (speed up in middle, slow at ends)
- **Micro-jitter** (simulates hand tremor)
- **Overshoot correction** (humans overshoot targets slightly)

### ✅ 3. Human-Like Typing
- **Variable inter-key delay** (50-200ms per keystroke)
- **Longer pauses** after spaces and punctuation
- **Occasional thinking pauses** (300-700ms randomly)
- **Faster for repeated characters**

### ✅ 4. Natural Interactions
- **Pause before clicking** (100-300ms thinking time)
- **Click off-center** (humans don't click pixel-perfect center)
- **Variable click hold duration** (50-150ms)
- **Random page exploration** (mouse movements, scrolling before actions)

---

## Usage

### Basic Usage

```python
from core.browser import BrowserController

# Enable human behavior (default: True)
browser = BrowserController(
    headless=False,
    enable_human_behavior=True
)

await browser.start()
await browser.goto("https://instagram.com")

# Natural exploration (appears more human)
await browser.explore_page_naturally(duration=2.0)

# Fill form with human-like typing
await browser.fill_form({
    "input[name='username']": "my_username",
    "input[name='password']": "my_password"
})

# Click with human-like mouse movement
await browser.click("button[type='submit']")
```

### Advanced: Direct HumanBehavior Access

```python
# Access the HumanBehavior instance directly
human = browser._human

# Custom mouse movement
await human.human_mouse_move(500, 300)

# Type with custom behavior
await human.human_type(
    selector="input#email",
    text="user@example.com",
    clear_first=True
)

# Click with options
await human.human_click(
    selector="button#login",
    button='left',
    double_click=False
)

# Scroll naturally
await human.human_scroll(
    direction='down',
    amount=300,
    smooth=True
)

# Random exploration
await human.random_page_exploration(duration=3.0)

# Random wait (thinking time)
await human.wait_random(min_seconds=0.5, max_seconds=2.0)
```

---

## How It Works

### Mouse Movement Algorithm

```python
# 1. Generate control points for Bezier curve
# 2. Calculate curved path from start to target
# 3. Apply smoothstep easing (acceleration/deceleration)
# 4. Add micro-jitter (hand tremor simulation)
# 5. Add overshoot and correction (70% of time)

Path: Start → Curve → Overshoot → Correction → Target
      (slow)   (fast)    (quick)     (adjust)   (stop)
```

### Typing Pattern

```
Character: h  e  l  l  o  _  w  o  r  l  d
Delay:     80 120 95 60 110 180 90 105 115 70 85 (ms)
                       ↑              ↑
               Faster repeat      Longer after space
```

### Stealth Patches Applied

```javascript
// Applied on browser start via page.add_init_script()
1. navigator.webdriver = false
2. navigator.plugins = [fake plugins]
3. window.chrome = {runtime, loadTimes, csi, app}
4. navigator.languages = ['en-US', 'en']
5. Permissions API fix (consistent states)
6. Hardware concurrency = 8 (not VM detection)
7. outerWidth/outerHeight fix (headless detection)
8. Mouse position tracking for natural movements
```

---

## Configuration

### Randomness Control

```python
from core.human_behavior import HumanBehavior

# Default: randomness=1.0
human = HumanBehavior(page, randomness=1.0)

# More predictable (faster, less random)
human = HumanBehavior(page, randomness=0.5)

# More chaotic (slower, more random)
human = HumanBehavior(page, randomness=2.0)
```

### Disable for Specific Operations

```python
# Disable globally
browser = BrowserController(enable_human_behavior=False)

# Or bypass for specific actions
await browser._page_fill(selector, value)  # Direct fill
await browser._page_click(selector)        # Direct click
```

---

## Testing

Run the test script to see it in action:

```bash
# Activate virtual environment
.venv\Scripts\activate

# Run test (opens visible browser)
python tests\test_human_behavior.py
```

**What you'll see:**
1. Browser opens with stealth patches applied
2. Mouse moves in curved paths (not straight lines)
3. Typing happens at variable speed
4. Random page exploration (scrolling, mouse movements)
5. Natural pauses before actions

---

## When CAPTCHAs Still Appear

Even with perfect human simulation, CAPTCHAs may appear due to:

| Factor | Solution |
|--------|----------|
| **Datacenter IP** | Use residential proxy |
| **New device fingerprint** | Build reputation slowly |
| **High request rate** | Add delays between actions |
| **reCAPTCHA history** | Clean browser profile or rotate |
| **Site-specific detection** | Use manual login flow |

### Fallback: Manual Authentication

For sites with very strong detection (Instagram, Facebook, Gmail):

```python
# Use social_login method (pauses for manual completion)
config = {
    'auth': {
        'method': 'social_login',
        'login_url': 'https://instagram.com/accounts/login/'
    }
}

# Scanner opens browser, user logs in manually, scan continues
```

---

## Architecture

```
core/
├── human_behavior.py       # Main simulator module
│   ├── HumanBehavior       # Main class
│   ├── _bezier_curve()     # Curved path calculation
│   ├── _generate_mouse_path() # Path generation
│   ├── _add_overshoot()    # Overshoot simulation
│   ├── apply_stealth_patches() # Hide automation
│   ├── human_mouse_move()  # Curved mouse movement
│   ├── human_click()       # Natural clicking
│   ├── human_type()        # Variable speed typing
│   ├── human_scroll()      # Natural scrolling
│   └── random_page_exploration() # Appear human
│
└── browser.py              # Integration
    ├── __init__()          # Initialize HumanBehavior
    ├── start()             # Apply stealth patches
    ├── fill_form()         # Use human_type()
    ├── click()             # Use human_click()
    └── explore_page_naturally() # Wrapper
```

---

## Research References

Based on comprehensive research into:
- reCAPTCHA v3 scoring system
- Browser fingerprinting techniques
- Behavioral biometrics analysis
- Mouse movement pattern detection
- Typing dynamics analysis
- puppeteer-extra-plugin-stealth implementation
- undetected-chromedriver techniques

---

## Limitations

### What It Cannot Bypass

1. **IP-based rate limiting** - Need residential proxies
2. **Account reputation** - New accounts flagged more
3. **Device fingerprint history** - Need clean profiles
4. **Advanced ML models** - Some sites use very sophisticated AI
5. **CAPTCHA v2 challenges** - If shown, need manual solving or service

### Recommended Approach

For maximum success:
1. ✅ **Use human behavior** (this module)
2. ✅ **Use residential proxy** (not datacenter IPs)
3. ✅ **Build reputation slowly** (don't spam actions)
4. ✅ **Rotate browser profiles** (don't reuse fingerprints)
5. ✅ **Add realistic delays** (2-5 seconds between pages)
6. ✅ **Fallback to manual** (for very secure sites)

---

## Performance Impact

| Feature | Time Added | Worth It? |
|---------|-----------|-----------|
| Stealth patches | ~50ms | ✅ Yes (one-time) |
| Mouse movement | ~200-500ms | ✅ Yes (prevents blocks) |
| Human typing | ~100ms per char | ✅ Yes (prevents blocks) |
| Page exploration | ~2-3 seconds | ⚠️ Optional (helps a lot) |

**Total overhead: ~1-3 seconds per interaction**

For penetration testing, this is negligible compared to getting blocked.

---

## Future Enhancements

Potential additions:
- [ ] Canvas fingerprint randomization
- [ ] WebGL vendor/renderer spoofing
- [ ] Audio context fingerprint randomization
- [ ] Touch event simulation for mobile
- [ ] Realistic scroll physics
- [ ] Browser profile rotation
- [ ] Proxy rotation integration
- [ ] ML-based behavior modeling

---

## Examples

### Login to Instagram (with human behavior)

```python
browser = BrowserController(headless=False, enable_human_behavior=True)
await browser.start()

# Navigate
await browser.goto("https://www.instagram.com/accounts/login/")
await asyncio.sleep(2)

# Explore naturally (important!)
await browser.explore_page_naturally(duration=3.0)

# Fill form with human-like typing
await browser.fill_form({
    "input[name='username']": "test_user",
    "input[name='password']": "test_password"
})

# Click with natural mouse movement
await browser.click("button[type='submit']")

# Wait for result
await asyncio.sleep(5)
```

### Compare: Without Human Behavior

```python
# This would likely trigger CAPTCHA or block:
await page.fill("input[name='username']", "test_user")  # Instant
await page.fill("input[name='password']", "test_password")  # Instant
await page.click("button[type='submit']")  # Instant click

# Red flags:
# - No mouse movement
# - Instant typing (no delays)
# - Perfect timing
# - Straight-line cursor paths
# - navigator.webdriver = true
```

---

## Integration with Existing Code

The module is **backward compatible**:

```python
# Old code still works
browser = BrowserController()
await browser.start()
await browser.fill_form({...})  # Uses direct fill

# New code with human behavior
browser = BrowserController(enable_human_behavior=True)
await browser.start()
await browser.fill_form({...})  # Uses human_type()
```

**No breaking changes** - just enable the flag!

---

## Conclusion

This module significantly improves the success rate of automated logins on sites with bot detection. For sites like **Instagram, Facebook, and Gmail**, combine this with:
- Residential proxies
- Manual authentication fallback
- Realistic interaction patterns
- Rate limiting

For regular web apps without sophisticated detection, this alone should be sufficient to avoid CAPTCHA challenges.
