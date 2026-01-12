"""
Jarwis AGI Pen Test - Unified Scanner Executor

Executes ALL scanners on captured request data.
Handles timeouts, error isolation, and result aggregation.

Usage:
    executor = UnifiedExecutor(config, request_store)
    results = await executor.run(context="pre_login")
    # results contains all findings from all scanners
"""

import asyncio
import logging
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime

from .scanner_registry import get_registry, ScannerMeta, ScanContext
from .request_store import RequestStore

# Import WebSocket broadcast for real-time updates
try:
    from api.websocket import broadcast_scan_progress, broadcast_scan_log
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

logger = logging.getLogger(__name__)


@dataclass
class ScannerExecutionResult:
    """Result from executing a single scanner"""
    scanner_name: str
    status: str  # "success", "failed", "timeout", "skipped", "circuit_open"
    findings: List[Any] = field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    retry_count: int = 0
    circuit_breaker_open: bool = False


@dataclass
class CircuitBreakerState:
    """State for a single scanner's circuit breaker"""
    failure_count: int = 0
    last_failure_time: float = 0.0
    is_open: bool = False
    cooldown_until: float = 0.0
    total_successes: int = 0
    total_failures: int = 0


@dataclass
class ExecutionSummary:
    """Summary of all scanner executions"""
    context: str
    total_scanners: int = 0
    ran: int = 0
    success: int = 0
    failed: int = 0
    timeout: int = 0
    skipped: int = 0
    retried: int = 0
    circuit_breaker_skipped: int = 0
    total_findings: int = 0
    execution_time: float = 0.0
    scanner_results: List[ScannerExecutionResult] = field(default_factory=list)
    all_findings: List[Any] = field(default_factory=list)


class UnifiedExecutor:
    """
    Unified executor for all vulnerability scanners.
    
    Features:
    - Runs ALL applicable scanners for a context
    - Timeout per scanner (configurable)
    - Error isolation (one failure doesn't crash all)
    - Retry logic with exponential backoff
    - Circuit breaker to skip consistently failing scanners
    - Progress tracking
    - Result aggregation and deduplication
    """
    
    # Circuit breaker settings (class-level for persistence across executor instances)
    _circuit_breakers: Dict[str, 'CircuitBreakerState'] = {}
    
    def __init__(
        self,
        config: Dict[str, Any],
        request_store: RequestStore,
        scan_context: Optional[Any] = None,  # Legacy ScanContext from runner
        browser_controller: Optional[Any] = None,
        status_callback: Optional[Any] = None,
        on_finding_callback: Optional[Any] = None,  # Called when findings are discovered
        heartbeat_callback: Optional[Callable] = None,  # For recovery manager heartbeats
        scan_id: str = None  # For WebSocket broadcasts
    ):
        self.config = config
        self.request_store = request_store
        self.scan_context = scan_context
        self.browser = browser_controller
        self.status_callback = status_callback
        self.on_finding_callback = on_finding_callback
        self.heartbeat_callback = heartbeat_callback
        self.scan_id = scan_id
        
        # Get registry
        self.registry = get_registry()
        
        # Execution settings
        self.default_timeout = config.get('scanner_timeout', 60)
        self.max_concurrent = config.get('max_concurrent_scanners', 5)
        self.stop_on_critical = config.get('stop_on_critical', False)
        
        # Retry settings
        self.max_retries = config.get('scanner_max_retries', 2)
        self.retry_delay_base = config.get('scanner_retry_delay', 1.0)  # Exponential backoff base
        
        # Circuit breaker settings
        self.circuit_failure_threshold = config.get('circuit_failure_threshold', 3)  # Failures before open
        self.circuit_cooldown_seconds = config.get('circuit_cooldown_seconds', 300)  # 5 minutes cooldown
    
    async def run(
        self,
        context: str = "pre_login",
        owasp_filter: Optional[List[str]] = None,
        scanner_filter: Optional[List[str]] = None
    ) -> ExecutionSummary:
        """
        Run all scanners for a given context.
        
        Args:
            context: "pre_login" or "post_login"
            owasp_filter: Optional list of OWASP categories to run (e.g., ["A01", "A03"])
            scanner_filter: Optional list of scanner names to run
            
        Returns:
            ExecutionSummary with all results
        """
        start_time = time.time()
        
        # Get applicable scanners
        scanners = self.registry.get_scanners(
            context=context,
            owasp_filter=owasp_filter
        )
        
        # Apply scanner name filter if provided
        if scanner_filter:
            scanners = [s for s in scanners if s.name in scanner_filter]
        
        # Apply attacks config filter from config['attacks']
        attacks_config = self.config.get('attacks', {})
        if attacks_config:
            scanners = self._filter_by_attacks_config(scanners, attacks_config)
        
        summary = ExecutionSummary(
            context=context,
            total_scanners=len(scanners)
        )
        
        logger.info(f"Starting {context} scan with {len(scanners)} scanners")
        
        if self.status_callback:
            await self._update_status(f"Running {len(scanners)} scanners", 0, context)
        
        # Run scanners
        if self.max_concurrent > 1:
            # Parallel execution with semaphore
            results = await self._run_parallel(scanners, context)
        else:
            # Sequential execution
            results = await self._run_sequential(scanners, context)
        
        # Aggregate results
        for result in results:
            summary.scanner_results.append(result)
            
            if result.status == "success":
                summary.success += 1
                summary.ran += 1
            elif result.status == "failed":
                summary.failed += 1
                summary.ran += 1
            elif result.status == "timeout":
                summary.timeout += 1
                summary.ran += 1
            elif result.status == "skipped":
                summary.skipped += 1
            elif result.status == "circuit_open":
                summary.circuit_breaker_skipped += 1
            
            # Track retries
            if result.retry_count > 0:
                summary.retried += 1
            
            summary.all_findings.extend(result.findings)
        
        # Deduplicate findings
        summary.all_findings = self._deduplicate_findings(summary.all_findings)
        summary.total_findings = len(summary.all_findings)
        summary.execution_time = time.time() - start_time
        
        logger.info(
            f"Scan complete: {summary.ran} ran, {summary.success} success, "
            f"{summary.failed} failed, {summary.timeout} timeout, "
            f"{summary.retried} retried, {summary.circuit_breaker_skipped} circuit-skipped, "
            f"{summary.total_findings} findings in {summary.execution_time:.1f}s"
        )
        
        return summary
    
    async def _run_sequential(
        self,
        scanners: List[ScannerMeta],
        context: str
    ) -> List[ScannerExecutionResult]:
        """Run scanners sequentially with retry support and heartbeat updates"""
        results = []
        total_scanners = len(scanners)
        
        for i, scanner_meta in enumerate(scanners):
            progress = int((i / total_scanners) * 100)
            
            # Update status callback
            if self.status_callback:
                await self._update_status(
                    f"Running {scanner_meta.name}",
                    progress,
                    context
                )
            
            # Send heartbeat to recovery manager
            self._send_heartbeat(context, progress)
            
            # Broadcast progress via WebSocket
            await self._broadcast_scanner_progress(
                scanner_name=scanner_meta.name,
                scanner_index=i + 1,
                total_scanners=total_scanners,
                context=context
            )
            
            result = await self._execute_scanner_with_retry(scanner_meta, context)
            results.append(result)
            
            # Check for critical finding and stop if configured
            if self.stop_on_critical and self._has_critical(result.findings):
                logger.warning(f"Critical finding detected, stopping scan")
                break
        
        return results
    
    def _send_heartbeat(self, phase: str, progress: int):
        """Send heartbeat to recovery manager"""
        if self.heartbeat_callback:
            try:
                self.heartbeat_callback(phase, progress)
            except Exception as e:
                logger.debug(f"Heartbeat callback error: {e}")
    
    async def _broadcast_scanner_progress(
        self,
        scanner_name: str,
        scanner_index: int,
        total_scanners: int,
        context: str
    ):
        """Broadcast scanner progress via WebSocket"""
        if HAS_WEBSOCKET and self.scan_id:
            try:
                # Map context to phase
                phase = "pre_login_attacks" if context == "pre_login" else "post_login_attacks"
                # Progress range: 50-100% (AttackEngine takes 0-50%)
                base_progress = 50 if context == "pre_login" else 80
                progress = base_progress + int((scanner_index / total_scanners) * 15)
                
                await broadcast_scan_progress(
                    scan_id=self.scan_id,
                    progress=progress,
                    phase=phase,
                    message=f"Scanner {scanner_index}/{total_scanners}: {scanner_name}",
                    current_task=f"Running {scanner_name}"
                )
            except Exception as e:
                logger.debug(f"WebSocket broadcast error: {e}")
    
    async def _run_parallel(
        self,
        scanners: List[ScannerMeta],
        context: str
    ) -> List[ScannerExecutionResult]:
        """Run scanners in parallel with concurrency limit and heartbeat updates"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        total_scanners = len(scanners)
        completed_count = [0]  # Use list to allow modification in nested function
        
        async def run_with_semaphore(scanner_meta: ScannerMeta, index: int):
            async with semaphore:
                result = await self._execute_scanner_with_retry(scanner_meta, context)
                
                # Update progress after each completion
                completed_count[0] += 1
                progress = int((completed_count[0] / total_scanners) * 100)
                
                # Send heartbeat every 5 completions
                if completed_count[0] % 5 == 0:
                    self._send_heartbeat(context, progress)
                    await self._broadcast_scanner_progress(
                        scanner_name=scanner_meta.name,
                        scanner_index=completed_count[0],
                        total_scanners=total_scanners,
                        context=context
                    )
                
                return result
        
        tasks = [run_with_semaphore(s, i) for i, s in enumerate(scanners)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions from gather
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(ScannerExecutionResult(
                    scanner_name=scanners[i].name,
                    status="failed",
                    error=str(result)
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    def _get_circuit_breaker(self, scanner_name: str) -> 'CircuitBreakerState':
        """Get or create circuit breaker state for a scanner"""
        if scanner_name not in UnifiedExecutor._circuit_breakers:
            UnifiedExecutor._circuit_breakers[scanner_name] = CircuitBreakerState()
        return UnifiedExecutor._circuit_breakers[scanner_name]
    
    def _is_circuit_open(self, scanner_name: str) -> bool:
        """Check if circuit breaker is open for a scanner"""
        cb = self._get_circuit_breaker(scanner_name)
        
        if not cb.is_open:
            return False
        
        # Check if cooldown has passed
        if time.time() > cb.cooldown_until:
            # Half-open state - allow one attempt
            logger.info(f"Circuit breaker for {scanner_name} entering half-open state")
            cb.is_open = False
            return False
        
        return True
    
    def _record_success(self, scanner_name: str):
        """Record successful scanner execution"""
        cb = self._get_circuit_breaker(scanner_name)
        cb.failure_count = 0  # Reset on success
        cb.total_successes += 1
        cb.is_open = False
    
    def _record_failure(self, scanner_name: str):
        """Record scanner failure, potentially opening circuit"""
        cb = self._get_circuit_breaker(scanner_name)
        cb.failure_count += 1
        cb.last_failure_time = time.time()
        cb.total_failures += 1
        
        if cb.failure_count >= self.circuit_failure_threshold:
            cb.is_open = True
            cb.cooldown_until = time.time() + self.circuit_cooldown_seconds
            logger.warning(
                f"Circuit breaker OPEN for {scanner_name} after {cb.failure_count} failures. "
                f"Cooldown until {datetime.fromtimestamp(cb.cooldown_until).isoformat()}"
            )
    
    async def _execute_scanner_with_retry(
        self,
        scanner_meta: ScannerMeta,
        context: str
    ) -> ScannerExecutionResult:
        """Execute scanner with retry logic and circuit breaker"""
        scanner_name = scanner_meta.name
        
        # Check circuit breaker
        if self._is_circuit_open(scanner_name):
            logger.info(f"Skipping {scanner_name} - circuit breaker open")
            return ScannerExecutionResult(
                scanner_name=scanner_name,
                status="circuit_open",
                error="Circuit breaker open - scanner disabled due to repeated failures",
                circuit_breaker_open=True
            )
        
        # Retry loop
        last_error = None
        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                # Exponential backoff
                delay = self.retry_delay_base * (2 ** (attempt - 1))
                logger.info(f"Retrying {scanner_name} (attempt {attempt + 1}) after {delay:.1f}s delay")
                await asyncio.sleep(delay)
            
            result = await self._execute_scanner(scanner_meta, context)
            
            if result.status == "success":
                self._record_success(scanner_name)
                result.retry_count = attempt
                
                # Notify callback of findings
                if self.on_finding_callback and result.findings:
                    try:
                        await self.on_finding_callback(result.findings)
                    except Exception as e:
                        logger.warning(f"Finding callback failed: {e}")
                
                return result
            
            # Don't retry on skip
            if result.status == "skipped":
                return result
            
            # Record failure and prepare for retry
            last_error = result.error
            
            # Don't count timeout as failure for circuit breaker if it's the first attempt
            if result.status == "timeout" and attempt == 0:
                pass  # Give it another chance
            else:
                self._record_failure(scanner_name)
        
        # All retries exhausted
        logger.error(f"Scanner {scanner_name} failed after {self.max_retries + 1} attempts")
        return ScannerExecutionResult(
            scanner_name=scanner_name,
            status="failed",
            error=f"Failed after {self.max_retries + 1} attempts. Last error: {last_error}",
            retry_count=self.max_retries
        )
    
    async def _execute_scanner(
        self,
        scanner_meta: ScannerMeta,
        context: str
    ) -> ScannerExecutionResult:
        """Execute a single scanner with timeout and error handling"""
        scanner_name = scanner_meta.name
        timeout = scanner_meta.timeout or self.default_timeout
        start_time = datetime.now()
        
        logger.debug(f"Executing scanner: {scanner_name} (timeout: {timeout}s)")
        
        try:
            # Instantiate scanner
            scanner_class = scanner_meta.scanner_class
            
            # Different scanners have different constructor signatures
            # Try to handle common patterns
            scanner = self._instantiate_scanner(scanner_class, context)
            
            if scanner is None:
                return ScannerExecutionResult(
                    scanner_name=scanner_name,
                    status="skipped",
                    error="Could not instantiate scanner"
                )
            
            # Run with timeout
            exec_start = time.time()
            findings = await asyncio.wait_for(
                self._run_scanner(scanner),
                timeout=timeout
            )
            exec_time = time.time() - exec_start
            
            return ScannerExecutionResult(
                scanner_name=scanner_name,
                status="success",
                findings=findings or [],
                execution_time=exec_time,
                start_time=start_time.isoformat(),
                end_time=datetime.now().isoformat()
            )
            
        except asyncio.TimeoutError:
            logger.warning(f"Scanner {scanner_name} timed out after {timeout}s")
            return ScannerExecutionResult(
                scanner_name=scanner_name,
                status="timeout",
                error=f"Timed out after {timeout}s",
                start_time=start_time.isoformat(),
                end_time=datetime.now().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Scanner {scanner_name} failed: {e}")
            return ScannerExecutionResult(
                scanner_name=scanner_name,
                status="failed",
                error=str(e),
                start_time=start_time.isoformat(),
                end_time=datetime.now().isoformat()
            )
    
    def _instantiate_scanner(self, scanner_class, context: str):
        """Instantiate a scanner with appropriate arguments"""
        try:
            # Build context object for legacy scanners
            scan_context = self.scan_context
            if scan_context is None:
                # Create minimal context from request store
                scan_context = self._build_context_from_store(context)
            
            # Try different constructor patterns
            try:
                # Pattern 1: (config, context, browser_controller)
                scanner = scanner_class(self.config, scan_context, self.browser)
            except TypeError:
                try:
                    # Pattern 2: (config, context)
                    scanner = scanner_class(self.config, scan_context)
                except TypeError:
                    try:
                        # Pattern 3: (config, request_store)
                        scanner = scanner_class(self.config, self.request_store)
                    except TypeError:
                        try:
                            # Pattern 4: (engine) - for AttackEngine modules
                            scanner = scanner_class(self)
                        except TypeError:
                            # Pattern 5: No args
                            scanner = scanner_class()
            
            return scanner
            
        except Exception as e:
            logger.error(f"Failed to instantiate {scanner_class.__name__}: {e}")
            return None
    
    def _build_context_from_store(self, context: str):
        """Build a context object from RequestStore for legacy scanners"""
        is_post_login = context == "post_login"
        requests = self.request_store.get_all_requests(post_login=is_post_login)
        
        # Build endpoints list from captured requests
        endpoints = []
        upload_endpoints = []
        api_endpoints = []
        
        for req in requests:
            endpoint = {
                'url': req.url,
                'method': req.method,
                'params': req.parameters,
                'type': req.endpoint_type,
                'headers': req.headers
            }
            endpoints.append(endpoint)
            
            # Categorize by type
            if req.endpoint_type == 'upload' or 'upload' in req.url.lower():
                upload_endpoints.append(endpoint)
            if req.endpoint_type == 'api' or '/api/' in req.url:
                api_endpoints.append(endpoint)
        
        # Log endpoint counts for debugging
        logger.info(f"Building context for {context}: {len(endpoints)} endpoints, "
                   f"{len(upload_endpoints)} upload, {len(api_endpoints)} API")
        
        if len(endpoints) == 0:
            logger.warning(f"WARNING: No endpoints in RequestStore for {context} context. "
                          "Scanners will have nothing to test!")
        
        # Simple context object with all expected attributes
        class SimpleContext:
            pass
        
        ctx = SimpleContext()
        ctx.endpoints = endpoints
        ctx.upload_endpoints = upload_endpoints
        ctx.api_endpoints = api_endpoints
        ctx.target_url = self.config.get('target', {}).get('url', '')
        ctx.cookies = self.request_store.auth_tokens if is_post_login else {}
        ctx.is_authenticated = is_post_login
        
        # Add auth headers and cookies for scanners to use in HTTP requests
        if is_post_login and self.request_store.has_authentication():
            ctx.auth_headers = self.request_store.get_auth_headers()
            ctx.auth_cookies = self.request_store.get_auth_cookies()
            ctx.session_kwargs = self.request_store.get_authenticated_session_kwargs()
            logger.info(f"Context includes auth: {len(ctx.auth_headers)} headers, {len(ctx.auth_cookies)} cookies")
        else:
            ctx.auth_headers = {}
            ctx.auth_cookies = {}
            ctx.session_kwargs = {}
        
        # Store reference to request_store for scanners that need it
        ctx.request_store = self.request_store
        
        return ctx
    
    async def _run_scanner(self, scanner) -> List[Any]:
        """Run scanner and return findings"""
        import inspect
        
        # Check if the scanner requires session/request args (AttackEngine modules)
        # These should be skipped as they're run by AttackEngine, not UnifiedExecutor
        if hasattr(scanner, 'run'):
            sig = inspect.signature(scanner.run)
            params = list(sig.parameters.keys())
            # Skip if requires 'session' or 'request' positional args (AttackEngine modules)
            if 'session' in params or 'request' in params:
                # These are AttackEngine modules that need captured requests
                # They're already run by AttackEngine with proper session/request
                return []
        
        # Check for async scan method (most scanners)
        if hasattr(scanner, 'scan'):
            result = scanner.scan()
            if asyncio.iscoroutine(result):
                return await result
            return result
        elif hasattr(scanner, 'run'):
            result = scanner.run()
            if asyncio.iscoroutine(result):
                return await result
            return result
        else:
            logger.warning(f"Scanner has no scan() or run() method")
            return []
    
    def _has_critical(self, findings: List[Any]) -> bool:
        """Check if findings contain critical severity"""
        for finding in findings:
            severity = getattr(finding, 'severity', None) or finding.get('severity', '')
            if severity.lower() == 'critical':
                return True
        return False
    
    def _filter_by_attacks_config(self, scanners: List[ScannerMeta], attacks_config: Dict[str, Any]) -> List[ScannerMeta]:
        """
        Filter scanners based on attacks configuration.
        
        Maps attack types to scanner names/categories and filters accordingly.
        
        Args:
            scanners: List of scanner metadata
            attacks_config: Dict like {"sqli": {"enabled": True}, "xss": {"enabled": False}, ...}
        
        Returns:
            Filtered list of scanners
        """
        # Map attack types to scanner name patterns and OWASP categories
        ATTACK_TO_SCANNER_MAP = {
            'sqli': ['SQL', 'Injection'],
            'xss': ['XSS', 'CrossSite'],
            'nosqli': ['NoSQL', 'Mongo'],
            'cmdi': ['Command', 'RCE', 'CodeExecution'],
            'ssti': ['Template', 'SSTI'],
            'xxe': ['XXE', 'XML'],
            'ldapi': ['LDAP'],
            'xpath': ['XPath'],
            'idor': ['IDOR', 'DirectObject'],
            'bola': ['BOLA', 'ObjectLevel'],
            'bfla': ['BFLA', 'FunctionLevel'],
            'path_traversal': ['PathTraversal', 'DirectoryTraversal', 'LFI', 'RFI'],
            'auth_bypass': ['Auth', 'Authentication', 'Bypass'],
            'jwt': ['JWT', 'Token'],
            'session': ['Session', 'Cookie'],
            'ssrf': ['SSRF', 'ServerSide'],
            'csrf': ['CSRF', 'CrossSiteRequest'],
            'host_header': ['HostHeader', 'Host'],
            'cors': ['CORS', 'CrossOrigin'],
            'hpp': ['HPP', 'ParameterPollution'],
            'crlf': ['CRLF', 'HeaderInjection'],
            'cache_poison': ['CachePoison', 'WebCache'],
            'http_smuggling': ['Smuggling', 'HTTPSmuggling'],
            'open_redirect': ['OpenRedirect', 'Redirect'],
            'file_upload': ['FileUpload', 'Upload'],
            'rate_limit': ['RateLimit', 'Bruteforce'],
        }
        
        # Get set of enabled attack types
        enabled_attacks = set()
        for attack_type, config in attacks_config.items():
            if isinstance(config, dict) and config.get('enabled', True):
                enabled_attacks.add(attack_type)
            elif isinstance(config, bool) and config:
                enabled_attacks.add(attack_type)
        
        # If no attacks config, return all scanners
        if not enabled_attacks and not attacks_config:
            return scanners
        
        # Filter scanners
        filtered = []
        for scanner in scanners:
            scanner_name = scanner.name.lower()
            scanner_category = scanner.owasp_category
            
            # Check if any enabled attack type matches this scanner
            scanner_enabled = False
            for attack_type in enabled_attacks:
                patterns = ATTACK_TO_SCANNER_MAP.get(attack_type, [])
                for pattern in patterns:
                    if pattern.lower() in scanner_name:
                        scanner_enabled = True
                        break
                if scanner_enabled:
                    break
            
            # If scanner doesn't match any attack patterns, still include it
            # (for scanners that don't fit into specific attack types)
            if not scanner_enabled:
                # Check if scanner is explicitly related to a disabled attack
                is_explicitly_disabled = False
                for attack_type, config in attacks_config.items():
                    if isinstance(config, dict) and not config.get('enabled', True):
                        patterns = ATTACK_TO_SCANNER_MAP.get(attack_type, [])
                        for pattern in patterns:
                            if pattern.lower() in scanner_name:
                                is_explicitly_disabled = True
                                break
                    if is_explicitly_disabled:
                        break
                
                if not is_explicitly_disabled:
                    scanner_enabled = True
            
            if scanner_enabled:
                filtered.append(scanner)
        
        logger.info(f"Attack config filtered: {len(scanners)} → {len(filtered)} scanners")
        return filtered
    
    def _deduplicate_findings(self, findings: List[Any]) -> List[Any]:
        """Remove duplicate findings based on key attributes"""
        seen = set()
        unique = []
        
        for finding in findings:
            # Create a key from important attributes
            if hasattr(finding, '__dict__'):
                key_parts = [
                    getattr(finding, 'title', ''),
                    getattr(finding, 'url', ''),
                    getattr(finding, 'parameter', ''),
                    getattr(finding, 'category', '')
                ]
            elif isinstance(finding, dict):
                key_parts = [
                    finding.get('title', ''),
                    finding.get('url', ''),
                    finding.get('parameter', ''),
                    finding.get('category', '')
                ]
            else:
                # Can't dedupe, keep it
                unique.append(finding)
                continue
            
            key = tuple(str(p) for p in key_parts)
            
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    async def _update_status(self, message: str, progress: int, phase: str):
        """Update scan status via callback"""
        if self.status_callback:
            try:
                if asyncio.iscoroutinefunction(self.status_callback):
                    await self.status_callback(message, progress, phase)
                else:
                    self.status_callback(message, progress, phase)
            except Exception as e:
                logger.error(f"Status callback error: {e}")
    
    @classmethod
    def reset_circuit_breaker(cls, scanner_name: str = None):
        """
        Reset circuit breaker for a specific scanner or all scanners.
        
        Args:
            scanner_name: Specific scanner to reset, or None to reset all
        """
        if scanner_name:
            if scanner_name in cls._circuit_breakers:
                cls._circuit_breakers[scanner_name] = CircuitBreakerState()
                logger.info(f"Reset circuit breaker for {scanner_name}")
        else:
            cls._circuit_breakers.clear()
            logger.info("Reset all circuit breakers")
    
    @classmethod
    def get_circuit_breaker_status(cls) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers"""
        status = {}
        for name, cb in cls._circuit_breakers.items():
            status[name] = {
                "is_open": cb.is_open,
                "failure_count": cb.failure_count,
                "total_successes": cb.total_successes,
                "total_failures": cb.total_failures,
                "cooldown_until": datetime.fromtimestamp(cb.cooldown_until).isoformat() if cb.cooldown_until > 0 else None
            }
        return status
    
    @classmethod
    def get_problematic_scanners(cls, failure_threshold: int = 2) -> List[str]:
        """Get list of scanners that have failed multiple times"""
        problematic = []
        for name, cb in cls._circuit_breakers.items():
            if cb.failure_count >= failure_threshold or cb.is_open:
                problematic.append(name)
        return problematic

