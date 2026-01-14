"""
JARWIS AGI PEN TEST - Human Behavior Simulator
================================================

Simulates human-like browser interactions to evade bot detection systems.

Features:
- Bezier curve mouse movements (curved paths, not straight lines)
- Variable typing speeds with natural delays
- Natural pauses before actions
- Micro-jitter in mouse movements
- Overshoot and correction when targeting elements
- Stealth patches to hide automation signals

This significantly reduces CAPTCHA triggers on sites like Instagram, Facebook, Gmail, etc.
"""

import asyncio
import logging
import random
import math
from typing import Tuple, List, Optional
from playwright.async_api import Page, ElementHandle

logger = logging.getLogger(__name__)


class HumanBehavior:
    """
    Simulates human-like browser interactions to evade bot detection.
    
    Usage:
        human = HumanBehavior(page)
        await human.apply_stealth_patches()
        await human.human_click(selector)
        await human.human_type(selector, "text")
    """
    
    def __init__(self, page: Page, randomness: float = 1.0):
        """
        Initialize human behavior simulator.
        
        Args:
            page: Playwright page instance
            randomness: Multiplier for randomness (0.5 = more predictable, 2.0 = more chaotic)
        """
        self.page = page
        self.randomness = randomness
        self._current_x = 0
        self._current_y = 0
    
    async def apply_stealth_patches(self):
        """
        Apply stealth patches to hide automation signals.
        
        Patches:
        - navigator.webdriver → false
        - navigator.plugins → realistic fake plugins
        - window.chrome → realistic object
        - navigator.languages → realistic array
        - Permissions API → consistent states
        """
        logger.info("Applying stealth patches to hide automation")
        
        stealth_script = """
        () => {
            // 1. Hide webdriver property
            Object.defineProperty(navigator, 'webdriver', {
                get: () => false,
                configurable: true
            });
            
            // 2. Add realistic plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [
                    {
                        name: 'Chrome PDF Plugin',
                        description: 'Portable Document Format',
                        filename: 'internal-pdf-viewer',
                        length: 1
                    },
                    {
                        name: 'Chrome PDF Viewer',
                        description: '',
                        filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai',
                        length: 1
                    },
                    {
                        name: 'Native Client',
                        description: '',
                        filename: 'internal-nacl-plugin',
                        length: 2
                    }
                ]
            });
            
            // 3. Fix Chrome object (headless detection)
            if (!window.chrome) {
                window.chrome = {
                    runtime: {},
                    loadTimes: function() {},
                    csi: function() {},
                    app: {}
                };
            }
            
            // 4. Set realistic languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
                configurable: true
            });
            
            // 5. Fix permissions API
            const originalQuery = window.navigator.permissions.query;
            window.navigator.permissions.query = (parameters) => (
                parameters.name === 'notifications' ?
                    Promise.resolve({ state: Notification.permission }) :
                    originalQuery(parameters)
            );
            
            // 6. Mock hardware concurrency (avoid revealing VM)
            Object.defineProperty(navigator, 'hardwareConcurrency', {
                get: () => 8,
                configurable: true
            });
            
            // 7. Override navigator.platform if headless
            if (navigator.platform === 'Win32' && !navigator.userAgent.includes('Windows')) {
                Object.defineProperty(navigator, 'platform', {
                    get: () => 'Win64',
                    configurable: true
                });
            }
            
            // 8. Mock outerWidth/outerHeight (headless detection)
            if (window.outerWidth === 0 || window.outerHeight === 0) {
                Object.defineProperty(window, 'outerWidth', {
                    get: () => window.innerWidth,
                    configurable: true
                });
                Object.defineProperty(window, 'outerHeight', {
                    get: () => window.innerHeight + 85,
                    configurable: true
                });
            }
            
            // 9. Track mouse position (for mouse movement simulation)
            window.mouseX = 0;
            window.mouseY = 0;
            document.addEventListener('mousemove', (e) => {
                window.mouseX = e.clientX;
                window.mouseY = e.clientY;
            });
            
            // 10. Override toString to hide proxy
            const handler = {
                get: (target, key) => {
                    if (key === 'toString') {
                        return target.toString.bind(target);
                    }
                    return Reflect.get(target, key);
                }
            };
            
            console.log('[Jarwis] Stealth patches applied successfully');
        }
        """
        
        await self.page.add_init_script(stealth_script)
        logger.info("Stealth patches applied successfully")
    
    def _bezier_curve(
        self, 
        p0: Tuple[float, float], 
        p1: Tuple[float, float], 
        p2: Tuple[float, float], 
        p3: Tuple[float, float], 
        t: float
    ) -> Tuple[float, float]:
        """Calculate point on cubic Bezier curve."""
        x = (
            (1 - t)**3 * p0[0] +
            3 * (1 - t)**2 * t * p1[0] +
            3 * (1 - t) * t**2 * p2[0] +
            t**3 * p3[0]
        )
        y = (
            (1 - t)**3 * p0[1] +
            3 * (1 - t)**2 * t * p1[1] +
            3 * (1 - t) * t**2 * p2[1] +
            t**3 * p3[1]
        )
        return (x, y)
    
    def _smoothstep(self, t: float) -> float:
        """Smooth interpolation curve (ease-in-out effect)."""
        return t * t * (3 - 2 * t)
    
    def _generate_mouse_path(
        self, 
        start: Tuple[float, float], 
        end: Tuple[float, float], 
        steps: int = 50
    ) -> List[Tuple[float, float]]:
        """
        Generate human-like mouse path using Bezier curves.
        
        Args:
            start: Starting position (x, y)
            end: Target position (x, y)
            steps: Number of intermediate points
            
        Returns:
            List of (x, y) coordinates forming a curved path
        """
        # Calculate distance to determine path complexity
        distance = math.sqrt((end[0] - start[0])**2 + (end[1] - start[1])**2)
        
        # Adjust steps based on distance (longer moves = more steps)
        steps = max(20, min(80, int(distance / 10) * self.randomness))
        
        # Generate random control points for natural curve
        ctrl1_offset = random.uniform(0.2, 0.4) * self.randomness
        ctrl2_offset = random.uniform(0.6, 0.8) * self.randomness
        
        # Add perpendicular offset for more natural curves
        angle = math.atan2(end[1] - start[1], end[0] - start[0])
        perpendicular = angle + math.pi / 2
        
        curve_strength = random.uniform(-50, 50) * self.randomness
        
        ctrl1 = (
            start[0] + ctrl1_offset * (end[0] - start[0]) + curve_strength * math.cos(perpendicular),
            start[1] + ctrl1_offset * (end[1] - start[1]) + curve_strength * math.sin(perpendicular)
        )
        
        curve_strength2 = random.uniform(-50, 50) * self.randomness
        
        ctrl2 = (
            start[0] + ctrl2_offset * (end[0] - start[0]) + curve_strength2 * math.cos(perpendicular),
            start[1] + ctrl2_offset * (end[1] - start[1]) + curve_strength2 * math.sin(perpendicular)
        )
        
        # Generate path points
        path = []
        for i in range(steps):
            t = i / (steps - 1)
            # Apply smoothstep for natural acceleration/deceleration
            t = self._smoothstep(t)
            
            point = self._bezier_curve(start, ctrl1, ctrl2, end, t)
            
            # Add micro-jitter (human hand tremor)
            jitter_x = random.gauss(0, 1.5 * self.randomness)
            jitter_y = random.gauss(0, 1.5 * self.randomness)
            
            path.append((point[0] + jitter_x, point[1] + jitter_y))
        
        return path
    
    def _add_overshoot(
        self, 
        path: List[Tuple[float, float]], 
        target: Tuple[float, float]
    ) -> List[Tuple[float, float]]:
        """
        Add human-like overshoot and correction at the end of path.
        
        Humans often overshoot their target slightly and correct back.
        """
        if len(path) < 2 or random.random() > 0.7:  # 70% chance of overshoot
            return path
        
        # Calculate overshoot distance (5-15 pixels)
        overshoot_distance = random.uniform(5, 15) * self.randomness
        
        # Calculate direction vector
        if len(path) >= 2:
            direction_x = path[-1][0] - path[-2][0]
            direction_y = path[-1][1] - path[-2][1]
            magnitude = math.sqrt(direction_x**2 + direction_y**2)
            
            if magnitude > 0:
                direction_x /= magnitude
                direction_y /= magnitude
                
                # Overshoot point
                overshoot = (
                    target[0] + direction_x * overshoot_distance,
                    target[1] + direction_y * overshoot_distance
                )
                
                # Add overshoot and correction
                path.append(overshoot)
                
                # Add 2-3 correction points back to target
                correction_steps = random.randint(2, 3)
                for i in range(1, correction_steps + 1):
                    t = i / correction_steps
                    correction = (
                        overshoot[0] + t * (target[0] - overshoot[0]),
                        overshoot[1] + t * (target[1] - overshoot[1])
                    )
                    path.append(correction)
        
        return path
    
    async def human_mouse_move(self, target_x: float, target_y: float):
        """
        Move mouse to target position with human-like behavior.
        
        Args:
            target_x: Target X coordinate
            target_y: Target Y coordinate
        """
        # Get current position
        current_pos = await self.page.evaluate('() => ({ x: window.mouseX || 0, y: window.mouseY || 0 })')
        start = (current_pos['x'], current_pos['y'])
        target = (target_x, target_y)
        
        # Generate curved path
        path = self._generate_mouse_path(start, target)
        
        # Add overshoot effect
        if random.random() > 0.3:  # 70% chance
            path = self._add_overshoot(path, target)
        
        # Move mouse along path with variable speed
        for i, point in enumerate(path):
            await self.page.mouse.move(point[0], point[1])
            
            # Variable delay between movements (faster in middle)
            progress = i / len(path)
            if progress < 0.2 or progress > 0.8:
                # Slower at start and end
                delay = random.uniform(0.003, 0.012) * self.randomness
            else:
                # Faster in middle
                delay = random.uniform(0.001, 0.006) * self.randomness
            
            await asyncio.sleep(delay)
        
        # Update tracked position
        self._current_x = target_x
        self._current_y = target_y
    
    async def human_click(
        self, 
        selector: str, 
        button: str = 'left',
        double_click: bool = False
    ):
        """
        Click element with human-like behavior.
        
        Args:
            selector: CSS selector of element to click
            button: Mouse button ('left', 'right', 'middle')
            double_click: Whether to perform double-click
        """
        try:
            # Wait for element to be visible
            element = await self.page.wait_for_selector(selector, state='visible', timeout=10000)
            
            # Get element bounding box
            box = await element.bounding_box()
            if not box:
                logger.warning(f"Element {selector} has no bounding box")
                # Fallback to direct click
                await element.click()
                return
            
            # Calculate click position (humans don't click dead center)
            # Click slightly off-center with random offset
            target_x = box['x'] + box['width'] * random.uniform(0.3, 0.7)
            target_y = box['y'] + box['height'] * random.uniform(0.3, 0.7)
            
            # Move mouse to target
            await self.human_mouse_move(target_x, target_y)
            
            # Pause before clicking (thinking time)
            await asyncio.sleep(random.uniform(0.1, 0.3) * self.randomness)
            
            # Perform click with realistic timing
            await self.page.mouse.down(button=button)
            
            # Hold mouse button down (human click duration)
            await asyncio.sleep(random.uniform(0.05, 0.15) * self.randomness)
            
            await self.page.mouse.up(button=button)
            
            # Double click if requested
            if double_click:
                await asyncio.sleep(random.uniform(0.05, 0.12))
                await self.page.mouse.down(button=button)
                await asyncio.sleep(random.uniform(0.05, 0.12))
                await self.page.mouse.up(button=button)
            
            logger.debug(f"Human-like click on {selector}")
            
        except Exception as e:
            logger.warning(f"Human click failed for {selector}: {e}")
            # Fallback to direct click
            try:
                await self.page.click(selector)
            except:
                pass
    
    async def human_type(
        self, 
        selector: str, 
        text: str,
        clear_first: bool = True
    ):
        """
        Type text with human-like variable speed.
        
        Args:
            selector: CSS selector of input element
            text: Text to type
            clear_first: Clear existing text first
        """
        try:
            # Click to focus input
            await self.human_click(selector)
            
            # Small delay after click
            await asyncio.sleep(random.uniform(0.1, 0.2) * self.randomness)
            
            # Clear existing text if requested
            if clear_first:
                await self.page.fill(selector, '')
            
            # Type each character with variable delay
            for i, char in enumerate(text):
                await self.page.keyboard.type(char)
                
                # Variable inter-key delay based on character type
                if char == ' ':
                    # Longer pause after space (word boundary)
                    delay = random.uniform(0.1, 0.2) * self.randomness
                elif char in '.,!?;:':
                    # Slight pause after punctuation
                    delay = random.uniform(0.08, 0.15) * self.randomness
                elif i > 0 and text[i-1] == text[i]:
                    # Faster for repeated characters
                    delay = random.uniform(0.03, 0.08) * self.randomness
                else:
                    # Normal typing speed
                    delay = random.uniform(0.05, 0.15) * self.randomness
                
                # Occasional longer pause (thinking/hesitation)
                if random.random() < 0.05:
                    delay += random.uniform(0.3, 0.7) * self.randomness
                
                await asyncio.sleep(delay)
            
            logger.debug(f"Human-like typing on {selector}: '{text[:20]}...'")
            
        except Exception as e:
            logger.warning(f"Human typing failed for {selector}: {e}")
            # Fallback to direct fill
            try:
                await self.page.fill(selector, text)
            except:
                pass
    
    async def human_scroll(
        self, 
        direction: str = 'down', 
        amount: int = None,
        smooth: bool = True
    ):
        """
        Scroll page with human-like behavior.
        
        Args:
            direction: 'down', 'up', 'left', 'right'
            amount: Scroll distance in pixels (random if None)
            smooth: Use smooth scrolling
        """
        if amount is None:
            amount = random.randint(200, 800)
        
        # Determine scroll delta
        delta_map = {
            'down': (0, amount),
            'up': (0, -amount),
            'left': (-amount, 0),
            'right': (amount, 0)
        }
        
        delta = delta_map.get(direction, (0, amount))
        
        if smooth:
            # Smooth scroll with multiple small steps
            steps = random.randint(8, 15)
            step_x = delta[0] / steps
            step_y = delta[1] / steps
            
            for _ in range(steps):
                await self.page.mouse.wheel(step_x, step_y)
                await asyncio.sleep(random.uniform(0.02, 0.05) * self.randomness)
        else:
            # Single scroll action
            await self.page.mouse.wheel(delta[0], delta[1])
        
        logger.debug(f"Human-like scroll {direction} by {amount}px")
    
    async def random_page_exploration(self, duration: float = 2.0):
        """
        Perform random page exploration (mouse movements, scrolling) to appear human.
        
        This is useful before filling forms to make behavior more natural.
        
        Args:
            duration: Exploration duration in seconds
        """
        logger.info(f"Performing {duration}s of random page exploration")
        
        start_time = asyncio.get_event_loop().time()
        actions = 0
        
        while (asyncio.get_event_loop().time() - start_time) < duration:
            action = random.choice(['move', 'scroll', 'pause'])
            
            if action == 'move':
                # Random mouse movement
                viewport = self.page.viewport_size
                target_x = random.randint(100, viewport['width'] - 100)
                target_y = random.randint(100, viewport['height'] - 100)
                await self.human_mouse_move(target_x, target_y)
                
            elif action == 'scroll':
                # Random scroll
                direction = random.choice(['down', 'up'])
                await self.human_scroll(direction, amount=random.randint(100, 400))
                
            else:  # pause
                # Just pause (reading content)
                await asyncio.sleep(random.uniform(0.5, 1.5))
            
            actions += 1
            await asyncio.sleep(random.uniform(0.2, 0.8) * self.randomness)
        
        logger.info(f"Page exploration complete: {actions} actions in {duration}s")
    
    async def wait_random(self, min_seconds: float = 0.5, max_seconds: float = 2.0):
        """Wait for a random duration (simulates reading/thinking)."""
        delay = random.uniform(min_seconds, max_seconds) * self.randomness
        await asyncio.sleep(delay)


# Convenience functions for backward compatibility
async def apply_stealth_patches(page: Page):
    """Apply stealth patches to a page."""
    human = HumanBehavior(page)
    await human.apply_stealth_patches()


async def human_click(page: Page, selector: str):
    """Perform human-like click."""
    human = HumanBehavior(page)
    await human.human_click(selector)


async def human_type(page: Page, selector: str, text: str):
    """Perform human-like typing."""
    human = HumanBehavior(page)
    await human.human_type(selector, text)
