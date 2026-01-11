"""
Jarwis Adaptive Controller - Dynamic Scan Strategy
=====================================================

Adapts scanning strategy based on:
- Target type and characteristics
- Historical learning data
- Real-time scan feedback
- Resource constraints

Features:
- Scanner prioritization based on effectiveness
- Dynamic payload ordering
- Adaptive depth control
- Early termination for unlikely targets

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime
from enum import Enum
import logging
import re

logger = logging.getLogger(__name__)


class TargetType(Enum):
    """Types of scan targets"""
    ECOMMERCE = "ecommerce"
    API = "api"
    SAAS = "saas"
    BANKING = "banking"
    HEALTHCARE = "healthcare"
    BLOG = "blog"
    CMS = "cms"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"
    UNKNOWN = "unknown"


class ScanDepth(Enum):
    """Scan depth levels"""
    QUICK = "quick"      # Fast, surface-level
    STANDARD = "standard"  # Normal depth
    DEEP = "deep"        # Thorough, slower
    EXHAUSTIVE = "exhaustive"  # Maximum coverage


class AdaptiveDecision(Enum):
    """Types of adaptive decisions"""
    SKIP_SCANNER = "skip_scanner"
    PRIORITIZE_SCANNER = "prioritize_scanner"
    REDUCE_PAYLOADS = "reduce_payloads"
    INCREASE_PAYLOADS = "increase_payloads"
    SKIP_ENDPOINT = "skip_endpoint"
    FOCUS_ENDPOINT = "focus_endpoint"
    EARLY_TERMINATE = "early_terminate"
    CONTINUE = "continue"


@dataclass
class TargetProfile:
    """Profile of the scan target"""
    domain: str
    target_type: TargetType
    
    # Detected characteristics
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)
    has_login: bool = False
    has_api: bool = False
    has_upload: bool = False
    has_payment: bool = False
    has_admin: bool = False
    
    # Authentication
    requires_auth: bool = False
    auth_type: Optional[str] = None
    
    # Scale
    endpoint_count: int = 0
    parameter_count: int = 0
    
    # Security posture
    has_waf: bool = False
    has_rate_limiting: bool = False
    has_captcha: bool = False
    security_headers_score: float = 0.0
    
    # Historical
    previous_scan_count: int = 0
    historical_vuln_types: List[str] = field(default_factory=list)


@dataclass
class ScannerConfig:
    """Configuration for a scanner module"""
    scanner_id: str
    enabled: bool = True
    priority: int = 50  # 0-100, higher = run earlier
    
    # Payload configuration
    max_payloads: int = 100
    payload_priority: List[str] = field(default_factory=list)  # Ordered payload IDs
    
    # Timing
    timeout_multiplier: float = 1.0
    delay_between_requests: float = 0.1
    
    # Scope
    skip_endpoints: List[str] = field(default_factory=list)
    focus_endpoints: List[str] = field(default_factory=list)


@dataclass
class AdaptiveStrategy:
    """Complete adaptive scan strategy"""
    target_profile: TargetProfile
    scan_depth: ScanDepth
    
    # Scanner configurations
    scanner_configs: Dict[str, ScannerConfig] = field(default_factory=dict)
    
    # Global settings
    max_total_requests: int = 10000
    max_scan_duration_minutes: int = 60
    
    # Decisions made
    decisions: List[Tuple[AdaptiveDecision, str]] = field(default_factory=list)
    
    # Confidence in strategy
    strategy_confidence: float = 0.5


@dataclass
class RealTimeMetrics:
    """Real-time metrics during scan"""
    requests_sent: int = 0
    findings_count: int = 0
    false_positive_rate: float = 0.0
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    blocked_requests: int = 0
    
    # Per scanner
    scanner_findings: Dict[str, int] = field(default_factory=dict)
    scanner_requests: Dict[str, int] = field(default_factory=dict)


class AdaptiveController:
    """
    Adaptive Scan Controller
    
    Dynamically adjusts scan strategy based on target characteristics,
    historical learning data, and real-time feedback.
    """
    
    # Target type detection patterns
    TARGET_PATTERNS: Dict[TargetType, List[str]] = {
        TargetType.ECOMMERCE: [
            "cart", "checkout", "payment", "product", "shop", "store",
            "add-to-cart", "buy", "price", "inventory", "shopify", "woocommerce"
        ],
        TargetType.API: [
            "/api/", "graphql", "swagger", "openapi", "rest", "/v1/", "/v2/",
            "json", "oauth", "bearer", "api-key"
        ],
        TargetType.SAAS: [
            "dashboard", "workspace", "team", "subscription", "billing",
            "upgrade", "plans", "features", "integration"
        ],
        TargetType.BANKING: [
            "account", "transfer", "balance", "transaction", "bank",
            "payment", "wire", "deposit", "withdrawal"
        ],
        TargetType.HEALTHCARE: [
            "patient", "medical", "health", "doctor", "appointment",
            "prescription", "hipaa", "record", "diagnosis"
        ],
        TargetType.CMS: [
            "wordpress", "drupal", "joomla", "wp-content", "wp-admin",
            "/admin/", "cms", "editor", "publish"
        ],
        TargetType.BLOG: [
            "blog", "post", "article", "comment", "author", "category",
            "tag", "archive", "feed"
        ]
    }
    
    # Technology detection patterns
    TECH_PATTERNS: Dict[str, List[str]] = {
        "php": ["php", ".php", "phpinfo", "x-powered-by: php"],
        "python": ["python", "django", "flask", "werkzeug", "wsgi"],
        "nodejs": ["node", "express", "x-powered-by: express"],
        "java": ["java", "spring", "tomcat", "jsessionid", ".jsp"],
        "dotnet": [".net", "asp.net", "aspx", "__viewstate"],
        "ruby": ["ruby", "rails", "rack", "_session"],
        "wordpress": ["wordpress", "wp-content", "wp-includes", "wp-admin"],
        "angular": ["ng-", "angular", "ngsw"],
        "react": ["react", "__react", "data-reactid"],
        "vue": ["vue", "v-bind", "v-model"],
    }
    
    # Scanner priority by target type
    SCANNER_PRIORITIES: Dict[TargetType, Dict[str, int]] = {
        TargetType.ECOMMERCE: {
            "payment_scanner": 100,
            "sqli_scanner": 95,
            "idor_scanner": 90,
            "xss_scanner": 85,
            "csrf_scanner": 80,
        },
        TargetType.API: {
            "injection_scanner": 100,
            "auth_scanner": 95,
            "idor_scanner": 90,
            "rate_limit_scanner": 85,
            "jwt_scanner": 80,
        },
        TargetType.BANKING: {
            "auth_scanner": 100,
            "idor_scanner": 95,
            "sqli_scanner": 90,
            "session_scanner": 85,
            "crypto_scanner": 80,
        },
        TargetType.CMS: {
            "sqli_scanner": 100,
            "file_upload_scanner": 95,
            "path_traversal_scanner": 90,
            "xss_scanner": 85,
            "auth_scanner": 80,
        },
    }
    
    def __init__(
        self,
        feedback_learner=None,
        pattern_matcher=None,
        db_session=None
    ):
        """
        Initialize the adaptive controller
        
        Args:
            feedback_learner: FeedbackLearner for historical data
            pattern_matcher: PatternMatcher for detection
            db_session: Database session
        """
        self.feedback_learner = feedback_learner
        self.pattern_matcher = pattern_matcher
        self.db_session = db_session
        
        # Current state
        self.current_strategy: Optional[AdaptiveStrategy] = None
        self.real_time_metrics = RealTimeMetrics()
    
    def analyze_target(
        self,
        domain: str,
        crawl_data: Dict[str, Any],
        historical_data: Dict[str, Any] = None
    ) -> TargetProfile:
        """
        Analyze target and create profile
        
        Args:
            domain: Target domain
            crawl_data: Data from initial crawl
            historical_data: Previous scan data
            
        Returns:
            TargetProfile with detected characteristics
        """
        historical_data = historical_data or {}
        
        # Detect target type
        target_type = self._detect_target_type(crawl_data)
        
        # Detect technologies
        technologies = self._detect_technologies(crawl_data)
        
        # Detect features
        html_content = crawl_data.get("html", "").lower()
        urls = crawl_data.get("urls", [])
        endpoints = crawl_data.get("endpoints", [])
        
        has_login = any(x in html_content for x in ["login", "signin", "sign in", "password"])
        has_api = any("/api/" in url or "graphql" in url for url in urls)
        has_upload = any(x in html_content for x in ["upload", "file", "attach"])
        has_payment = any(x in html_content for x in ["payment", "checkout", "credit card"])
        has_admin = any("/admin" in url for url in urls)
        
        # Detect security posture
        headers = crawl_data.get("response_headers", {})
        has_waf = self._detect_waf(headers, crawl_data.get("responses", []))
        
        security_headers = ["x-content-type-options", "x-frame-options", 
                          "content-security-policy", "strict-transport-security"]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        security_headers_score = sum(
            1 for h in security_headers if h in headers_lower
        ) / len(security_headers)
        
        # Historical data
        previous_scan_count = historical_data.get("scan_count", 0)
        historical_vuln_types = historical_data.get("vuln_types", [])
        
        return TargetProfile(
            domain=domain,
            target_type=target_type,
            technologies=technologies,
            has_login=has_login,
            has_api=has_api,
            has_upload=has_upload,
            has_payment=has_payment,
            has_admin=has_admin,
            requires_auth=has_login,
            endpoint_count=len(endpoints),
            parameter_count=crawl_data.get("parameter_count", 0),
            has_waf=has_waf,
            has_rate_limiting=self._detect_rate_limiting(crawl_data),
            has_captcha=any("captcha" in html_content for _ in [1]),
            security_headers_score=security_headers_score,
            previous_scan_count=previous_scan_count,
            historical_vuln_types=historical_vuln_types
        )
    
    def _detect_target_type(self, crawl_data: Dict[str, Any]) -> TargetType:
        """Detect target type from crawl data"""
        html = crawl_data.get("html", "").lower()
        urls = " ".join(crawl_data.get("urls", [])).lower()
        combined = f"{html} {urls}"
        
        scores: Dict[TargetType, int] = {}
        
        for target_type, patterns in self.TARGET_PATTERNS.items():
            score = sum(1 for p in patterns if p in combined)
            if score > 0:
                scores[target_type] = score
        
        if scores:
            return max(scores, key=scores.get)
        
        return TargetType.UNKNOWN
    
    def _detect_technologies(self, crawl_data: Dict[str, Any]) -> List[str]:
        """Detect technologies from crawl data"""
        html = crawl_data.get("html", "").lower()
        headers = " ".join(
            f"{k}: {v}" 
            for k, v in crawl_data.get("response_headers", {}).items()
        ).lower()
        combined = f"{html} {headers}"
        
        detected = []
        
        for tech, patterns in self.TECH_PATTERNS.items():
            if any(p in combined for p in patterns):
                detected.append(tech)
        
        return detected
    
    def _detect_waf(
        self, 
        headers: Dict[str, str], 
        responses: List[Dict] = None
    ) -> bool:
        """Detect WAF presence"""
        responses = responses or []
        
        # Check headers for known WAF signatures
        waf_headers = [
            "x-sucuri-id", "x-sucuri-cache",
            "x-cdn", "x-cache",
            "cf-ray", "cf-cache-status",  # Cloudflare
            "x-akamai", "akamai",
            "x-aws-waf",
            "x-mod-security",
            "server: cloudflare",
            "server: sucuri",
        ]
        
        headers_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        
        for waf_header in waf_headers:
            if waf_header.lower() in headers_str:
                return True
        
        # Check for blocked responses
        for response in responses:
            status = response.get("status", 200)
            if status in [403, 406, 429, 503]:
                body = response.get("body", "").lower()
                if any(x in body for x in ["blocked", "waf", "firewall", "security"]):
                    return True
        
        return False
    
    def _detect_rate_limiting(self, crawl_data: Dict[str, Any]) -> bool:
        """Detect rate limiting"""
        responses = crawl_data.get("responses", [])
        
        rate_limit_count = sum(
            1 for r in responses 
            if r.get("status") == 429 or "rate limit" in r.get("body", "").lower()
        )
        
        return rate_limit_count > 0
    
    def build_strategy(
        self,
        target_profile: TargetProfile,
        scan_depth: ScanDepth = ScanDepth.STANDARD,
        available_scanners: List[str] = None
    ) -> AdaptiveStrategy:
        """
        Build adaptive scan strategy for target
        
        Args:
            target_profile: Target analysis profile
            scan_depth: Desired scan depth
            available_scanners: List of available scanner IDs
            
        Returns:
            AdaptiveStrategy with scanner configurations
        """
        available_scanners = available_scanners or []
        
        strategy = AdaptiveStrategy(
            target_profile=target_profile,
            scan_depth=scan_depth
        )
        
        decisions = []
        
        # Get scanner priorities for this target type
        type_priorities = self.SCANNER_PRIORITIES.get(
            target_profile.target_type,
            {}
        )
        
        # Get learned recommendations
        learned_recommendations = {}
        if self.feedback_learner:
            recommendations = self.feedback_learner.get_scanner_recommendation(
                target_profile.target_type.value
            )
            learned_recommendations = {s: score for s, score in recommendations}
        
        # Build scanner configs
        for scanner_id in available_scanners:
            config = ScannerConfig(scanner_id=scanner_id)
            
            # Set priority from type-specific rules
            if scanner_id in type_priorities:
                config.priority = type_priorities[scanner_id]
            
            # Adjust based on learned data
            if scanner_id in learned_recommendations:
                learned_score = learned_recommendations[scanner_id]
                
                # Low effectiveness = lower priority or skip
                if learned_score < 0.2:
                    config.enabled = False
                    decisions.append((
                        AdaptiveDecision.SKIP_SCANNER,
                        f"Skipping {scanner_id}: low historical effectiveness ({learned_score:.0%})"
                    ))
                elif learned_score > 0.7:
                    config.priority = min(100, config.priority + 20)
                    decisions.append((
                        AdaptiveDecision.PRIORITIZE_SCANNER,
                        f"Prioritizing {scanner_id}: high historical effectiveness ({learned_score:.0%})"
                    ))
            
            # Adjust for target characteristics
            if target_profile.has_waf:
                config.delay_between_requests = 0.5  # Slow down to avoid blocking
                config.timeout_multiplier = 1.5
            
            if target_profile.has_rate_limiting:
                config.delay_between_requests = max(config.delay_between_requests, 1.0)
            
            # Adjust payloads based on depth
            if scan_depth == ScanDepth.QUICK:
                config.max_payloads = 20
            elif scan_depth == ScanDepth.STANDARD:
                config.max_payloads = 50
            elif scan_depth == ScanDepth.DEEP:
                config.max_payloads = 100
            elif scan_depth == ScanDepth.EXHAUSTIVE:
                config.max_payloads = 500
            
            # Focus on endpoints with historical vulns
            if target_profile.historical_vuln_types:
                # Get scanner's vuln type
                scanner_type = scanner_id.replace("_scanner", "")
                if scanner_type in target_profile.historical_vuln_types:
                    config.priority = min(100, config.priority + 15)
                    decisions.append((
                        AdaptiveDecision.PRIORITIZE_SCANNER,
                        f"Prioritizing {scanner_id}: historical vulns found"
                    ))
            
            strategy.scanner_configs[scanner_id] = config
        
        # Set global limits based on depth
        depth_limits = {
            ScanDepth.QUICK: (2000, 15),
            ScanDepth.STANDARD: (10000, 60),
            ScanDepth.DEEP: (50000, 180),
            ScanDepth.EXHAUSTIVE: (200000, 480),
        }
        
        limits = depth_limits.get(scan_depth, (10000, 60))
        strategy.max_total_requests = limits[0]
        strategy.max_scan_duration_minutes = limits[1]
        
        # Reduce for small targets
        if target_profile.endpoint_count < 10:
            strategy.max_total_requests = min(
                strategy.max_total_requests,
                target_profile.endpoint_count * 100
            )
        
        strategy.decisions = decisions
        strategy.strategy_confidence = self._calculate_strategy_confidence(
            target_profile, learned_recommendations
        )
        
        self.current_strategy = strategy
        
        return strategy
    
    def _calculate_strategy_confidence(
        self,
        profile: TargetProfile,
        learned_data: Dict[str, float]
    ) -> float:
        """Calculate confidence in the strategy"""
        confidence = 0.5
        
        # More previous scans = higher confidence
        if profile.previous_scan_count > 0:
            confidence += min(0.2, profile.previous_scan_count * 0.05)
        
        # Known target type = higher confidence
        if profile.target_type != TargetType.UNKNOWN:
            confidence += 0.1
        
        # Learned data = higher confidence
        if learned_data:
            confidence += min(0.2, len(learned_data) * 0.02)
        
        # Detected technologies = higher confidence
        if profile.technologies:
            confidence += min(0.1, len(profile.technologies) * 0.02)
        
        return min(0.95, confidence)
    
    def update_real_time(
        self,
        scanner_id: str,
        finding_count: int = 0,
        request_count: int = 0,
        error_count: int = 0,
        blocked: bool = False,
        response_time: float = 0.0
    ) -> Optional[Tuple[AdaptiveDecision, str]]:
        """
        Update real-time metrics and make adaptive decisions
        
        Args:
            scanner_id: Scanner that produced the update
            finding_count: New findings
            request_count: Requests sent
            error_count: Errors encountered
            blocked: Whether request was blocked
            response_time: Response time in seconds
            
        Returns:
            Optional adaptive decision if action needed
        """
        metrics = self.real_time_metrics
        
        # Update global metrics
        metrics.requests_sent += request_count
        metrics.findings_count += finding_count
        
        if blocked:
            metrics.blocked_requests += 1
        
        # Update averages
        if metrics.requests_sent > 0:
            metrics.error_rate = (
                metrics.error_rate * 0.95 + 
                (error_count / max(1, request_count)) * 0.05
            )
            metrics.avg_response_time = (
                metrics.avg_response_time * 0.95 + 
                response_time * 0.05
            )
        
        # Update per-scanner metrics
        if scanner_id not in metrics.scanner_findings:
            metrics.scanner_findings[scanner_id] = 0
            metrics.scanner_requests[scanner_id] = 0
        
        metrics.scanner_findings[scanner_id] += finding_count
        metrics.scanner_requests[scanner_id] += request_count
        
        # Make adaptive decisions
        decision = self._make_real_time_decision(scanner_id)
        
        return decision
    
    def _make_real_time_decision(
        self, scanner_id: str
    ) -> Optional[Tuple[AdaptiveDecision, str]]:
        """Make real-time adaptive decision"""
        metrics = self.real_time_metrics
        
        if not self.current_strategy:
            return None
        
        # Check if being blocked
        if metrics.blocked_requests > 5:
            # Slow down all scanners
            for config in self.current_strategy.scanner_configs.values():
                config.delay_between_requests *= 2
            
            return (
                AdaptiveDecision.REDUCE_PAYLOADS,
                "Detected blocking - reducing request rate"
            )
        
        # Check error rate
        if metrics.error_rate > 0.3:
            return (
                AdaptiveDecision.REDUCE_PAYLOADS,
                f"High error rate ({metrics.error_rate:.0%}) - reducing payloads"
            )
        
        # Check scanner effectiveness
        scanner_requests = metrics.scanner_requests.get(scanner_id, 0)
        scanner_findings = metrics.scanner_findings.get(scanner_id, 0)
        
        if scanner_requests > 100 and scanner_findings == 0:
            # Scanner not finding anything - skip remaining payloads
            return (
                AdaptiveDecision.SKIP_SCANNER,
                f"Scanner {scanner_id} ineffective after {scanner_requests} requests"
            )
        
        # Check if we've hit limits
        strategy = self.current_strategy
        if metrics.requests_sent >= strategy.max_total_requests:
            return (
                AdaptiveDecision.EARLY_TERMINATE,
                f"Request limit reached ({metrics.requests_sent})"
            )
        
        return None
    
    def get_scanner_order(self) -> List[str]:
        """Get scanners ordered by priority"""
        if not self.current_strategy:
            return []
        
        configs = self.current_strategy.scanner_configs
        
        # Filter enabled and sort by priority
        enabled = [
            (sid, cfg) 
            for sid, cfg in configs.items() 
            if cfg.enabled
        ]
        
        enabled.sort(key=lambda x: x[1].priority, reverse=True)
        
        return [sid for sid, _ in enabled]
    
    def should_skip_endpoint(
        self,
        endpoint: str,
        scanner_id: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if endpoint should be skipped for a scanner
        
        Args:
            endpoint: Endpoint URL
            scanner_id: Scanner to check
            
        Returns:
            (should_skip, reason)
        """
        if not self.current_strategy:
            return False, None
        
        config = self.current_strategy.scanner_configs.get(scanner_id)
        if not config:
            return False, None
        
        # Check skip list
        for pattern in config.skip_endpoints:
            if re.search(pattern, endpoint):
                return True, f"Endpoint matches skip pattern: {pattern}"
        
        # Check focus list (if present, skip non-matching)
        if config.focus_endpoints:
            matches_focus = any(
                re.search(p, endpoint) 
                for p in config.focus_endpoints
            )
            if not matches_focus:
                return True, "Endpoint not in focus list"
        
        return False, None
    
    def get_payload_limit(self, scanner_id: str) -> int:
        """Get maximum payloads for a scanner"""
        if not self.current_strategy:
            return 50
        
        config = self.current_strategy.scanner_configs.get(scanner_id)
        return config.max_payloads if config else 50
    
    def get_request_delay(self, scanner_id: str) -> float:
        """Get delay between requests for a scanner"""
        if not self.current_strategy:
            return 0.1
        
        config = self.current_strategy.scanner_configs.get(scanner_id)
        return config.delay_between_requests if config else 0.1
    
    def get_strategy_summary(self) -> Dict[str, Any]:
        """Get summary of current strategy"""
        if not self.current_strategy:
            return {"status": "no_strategy"}
        
        strategy = self.current_strategy
        profile = strategy.target_profile
        
        enabled_scanners = [
            sid for sid, cfg in strategy.scanner_configs.items()
            if cfg.enabled
        ]
        
        return {
            "target_type": profile.target_type.value,
            "technologies": profile.technologies,
            "scan_depth": strategy.scan_depth.value,
            "enabled_scanners": len(enabled_scanners),
            "total_scanners": len(strategy.scanner_configs),
            "max_requests": strategy.max_total_requests,
            "max_duration_minutes": strategy.max_scan_duration_minutes,
            "decisions": [
                {"type": d[0].value, "reason": d[1]}
                for d in strategy.decisions
            ],
            "confidence": round(strategy.strategy_confidence, 2),
            "features_detected": {
                "login": profile.has_login,
                "api": profile.has_api,
                "upload": profile.has_upload,
                "payment": profile.has_payment,
                "admin": profile.has_admin,
                "waf": profile.has_waf,
                "rate_limiting": profile.has_rate_limiting
            }
        }


# Convenience function
def build_scan_strategy(
    domain: str,
    crawl_data: Dict[str, Any],
    scan_depth: str = "standard"
) -> Dict[str, Any]:
    """Quick strategy building without instantiation"""
    controller = AdaptiveController()
    
    profile = controller.analyze_target(domain, crawl_data)
    
    depth_map = {
        "quick": ScanDepth.QUICK,
        "standard": ScanDepth.STANDARD,
        "deep": ScanDepth.DEEP,
        "exhaustive": ScanDepth.EXHAUSTIVE
    }
    
    strategy = controller.build_strategy(
        profile,
        depth_map.get(scan_depth, ScanDepth.STANDARD)
    )
    
    return controller.get_strategy_summary()
