"""
Jarwis AI Engine - Production Intelligence Without LLMs
========================================================

This is the core brain of Jarwis AI. It provides:
- Bayesian confidence scoring for vulnerability detection
- Statistical pattern matching with learned weights
- Evidence correlation and attack chain detection
- Self-improving accuracy through feedback loops

No external LLM or API dependencies - pure algorithmic intelligence.

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
import math
import re
import hashlib
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    """Confidence levels for AI predictions"""
    VERY_HIGH = "very_high"  # 0.9-1.0
    HIGH = "high"            # 0.7-0.9
    MEDIUM = "medium"        # 0.5-0.7
    LOW = "low"              # 0.3-0.5
    VERY_LOW = "very_low"    # 0.0-0.3


class SeverityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class EvidenceIndicator:
    """A single piece of evidence supporting a finding"""
    indicator_type: str  # pattern_match, timing_anomaly, response_diff, etc.
    description: str
    weight: float  # 0.0-1.0 contribution to confidence
    matched_text: Optional[str] = None
    location: Optional[str] = None  # URL, header, body, etc.


@dataclass
class ReasoningStep:
    """A single step in the reasoning chain"""
    step_number: int
    observation: str
    inference: str
    confidence_contribution: float


@dataclass
class AIAnalysisResult:
    """Complete AI analysis result for a finding"""
    # Core scores
    confidence_score: float  # 0.0-1.0
    evidence_strength: float  # 0.0-1.0
    exploitability_score: float  # 0.0-1.0
    false_positive_probability: float  # 0.0-1.0
    
    # Adjusted values
    severity_adjusted: str
    severity_adjustment_reason: Optional[str] = None
    
    # Evidence and reasoning
    evidence_indicators: List[EvidenceIndicator] = field(default_factory=list)
    reasoning_chain: List[ReasoningStep] = field(default_factory=list)
    reasoning_summary: str = ""
    
    # Pattern information
    pattern_matches: List[str] = field(default_factory=list)
    pattern_categories: List[str] = field(default_factory=list)
    
    # Correlation
    related_finding_ids: List[str] = field(default_factory=list)
    attack_chain_id: Optional[str] = None
    
    # Metadata
    analysis_timestamp: datetime = field(default_factory=datetime.utcnow)
    engine_version: str = "1.0.0"


@dataclass
class PatternWeight:
    """Learned weight for a detection pattern"""
    pattern_id: str
    base_weight: float
    learned_adjustment: float  # From feedback
    true_positive_count: int
    false_positive_count: int
    last_updated: datetime
    
    @property
    def effective_weight(self) -> float:
        """Calculate effective weight including learning adjustment"""
        return max(0.0, min(1.0, self.base_weight + self.learned_adjustment))
    
    @property
    def accuracy_rate(self) -> float:
        """Calculate accuracy rate from feedback"""
        total = self.true_positive_count + self.false_positive_count
        if total == 0:
            return 0.5  # No data, assume neutral
        return self.true_positive_count / total


class JarwisAIEngine:
    """
    Jarwis Artificial Intelligence Engine
    
    A pure statistical AI engine that provides:
    - Bayesian confidence scoring
    - Pattern-based vulnerability detection
    - Evidence correlation
    - Self-improving accuracy through feedback
    
    No LLM or external API dependencies.
    """
    
    VERSION = "1.0.0"
    
    # OWASP Category Priors (base probability of each category)
    # These are updated through learning
    CATEGORY_PRIORS: Dict[str, float] = {
        "A01": 0.15,  # Broken Access Control
        "A02": 0.08,  # Cryptographic Failures
        "A03": 0.25,  # Injection (most common)
        "A04": 0.05,  # Insecure Design
        "A05": 0.18,  # Security Misconfiguration
        "A06": 0.08,  # Vulnerable Components
        "A07": 0.10,  # Auth Failures
        "A08": 0.03,  # Software/Data Integrity
        "A09": 0.03,  # Logging Failures
        "A10": 0.05,  # SSRF
    }
    
    # Severity weights for scoring
    SEVERITY_WEIGHTS: Dict[str, float] = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.25,
        "info": 0.1
    }
    
    # Evidence type weights
    EVIDENCE_WEIGHTS: Dict[str, float] = {
        "sql_error_pattern": 0.85,
        "xss_reflection": 0.80,
        "command_output": 0.90,
        "timing_anomaly": 0.70,
        "response_difference": 0.65,
        "header_missing": 0.50,
        "version_disclosure": 0.40,
        "debug_info": 0.55,
        "path_traversal": 0.75,
        "ssrf_indicator": 0.70,
        "auth_bypass": 0.85,
        "idor_pattern": 0.75,
        "csrf_missing": 0.60,
        "generic_error": 0.30,
    }
    
    def __init__(self, db_session=None, pattern_matcher=None):
        """
        Initialize the AI Engine
        
        Args:
            db_session: Database session for learning data (optional)
            pattern_matcher: PatternMatcher instance (optional, will create if None)
        """
        self.db_session = db_session
        self.pattern_matcher = pattern_matcher
        self.pattern_weights: Dict[str, PatternWeight] = {}
        self._load_learned_weights()
    
    def _load_learned_weights(self):
        """Load learned pattern weights from database"""
        if self.db_session:
            try:
                # Query PatternKnowledge table for learned weights
                # This will be implemented when database migration is done
                pass
            except Exception as e:
                logger.warning(f"Could not load learned weights: {e}")
    
    def analyze_finding(
        self,
        finding: Dict[str, Any],
        response_body: str = "",
        response_headers: Dict[str, str] = None,
        request_data: Dict[str, Any] = None,
        historical_context: Dict[str, Any] = None
    ) -> AIAnalysisResult:
        """
        Analyze a finding and calculate AI confidence scores
        
        Args:
            finding: The finding dictionary with title, severity, evidence, etc.
            response_body: HTTP response body
            response_headers: HTTP response headers
            request_data: Original request data
            historical_context: Previous findings/scans context
            
        Returns:
            AIAnalysisResult with confidence scores and reasoning
        """
        response_headers = response_headers or {}
        request_data = request_data or {}
        historical_context = historical_context or {}
        
        # Step 1: Pattern-based evidence collection
        evidence_indicators = self._collect_evidence(
            finding, response_body, response_headers, request_data
        )
        
        # Step 2: Calculate base confidence from evidence
        evidence_strength = self._calculate_evidence_strength(evidence_indicators)
        
        # Step 3: Apply Bayesian inference with category priors
        category = finding.get("category", "A03")
        bayesian_confidence = self._bayesian_confidence(
            evidence_strength, category, historical_context
        )
        
        # Step 4: Calculate exploitability score
        exploitability = self._calculate_exploitability(
            finding, evidence_indicators
        )
        
        # Step 5: Calculate false positive probability
        fp_probability = self._calculate_false_positive_probability(
            evidence_indicators, finding, historical_context
        )
        
        # Step 6: Build reasoning chain
        reasoning_chain = self._build_reasoning_chain(
            finding, evidence_indicators, bayesian_confidence
        )
        
        # Step 7: Adjust severity if needed
        original_severity = finding.get("severity", "medium")
        adjusted_severity, adjustment_reason = self._adjust_severity(
            original_severity, bayesian_confidence, exploitability, fp_probability
        )
        
        # Step 8: Extract pattern matches
        pattern_matches = [e.indicator_type for e in evidence_indicators]
        pattern_categories = list(set([
            self._get_pattern_category(e.indicator_type) 
            for e in evidence_indicators
        ]))
        
        # Build reasoning summary
        reasoning_summary = self._build_reasoning_summary(
            finding, evidence_indicators, bayesian_confidence, reasoning_chain
        )
        
        return AIAnalysisResult(
            confidence_score=bayesian_confidence,
            evidence_strength=evidence_strength,
            exploitability_score=exploitability,
            false_positive_probability=fp_probability,
            severity_adjusted=adjusted_severity,
            severity_adjustment_reason=adjustment_reason,
            evidence_indicators=evidence_indicators,
            reasoning_chain=reasoning_chain,
            reasoning_summary=reasoning_summary,
            pattern_matches=pattern_matches,
            pattern_categories=pattern_categories,
            engine_version=self.VERSION
        )
    
    def _collect_evidence(
        self,
        finding: Dict[str, Any],
        response_body: str,
        response_headers: Dict[str, str],
        request_data: Dict[str, Any]
    ) -> List[EvidenceIndicator]:
        """Collect all evidence indicators from the finding and response"""
        evidence = []
        
        # Get evidence text from finding
        finding_evidence = finding.get("evidence", "")
        finding_title = finding.get("title", "").lower()
        finding_category = finding.get("category", "")
        
        # SQL Injection patterns
        if self._check_sql_patterns(response_body, finding_evidence):
            evidence.append(EvidenceIndicator(
                indicator_type="sql_error_pattern",
                description="Database error message detected in response",
                weight=self.EVIDENCE_WEIGHTS["sql_error_pattern"],
                matched_text=self._extract_sql_error(response_body or finding_evidence),
                location="response_body"
            ))
        
        # XSS reflection patterns
        if self._check_xss_patterns(response_body, finding_evidence, request_data):
            evidence.append(EvidenceIndicator(
                indicator_type="xss_reflection",
                description="Script/payload reflected in response without encoding",
                weight=self.EVIDENCE_WEIGHTS["xss_reflection"],
                matched_text=self._extract_xss_reflection(response_body),
                location="response_body"
            ))
        
        # Command injection patterns
        if self._check_command_patterns(response_body, finding_evidence):
            evidence.append(EvidenceIndicator(
                indicator_type="command_output",
                description="Command execution output detected",
                weight=self.EVIDENCE_WEIGHTS["command_output"],
                matched_text=self._extract_command_output(response_body or finding_evidence),
                location="response_body"
            ))
        
        # Security header checks
        missing_headers = self._check_security_headers(response_headers)
        for header in missing_headers:
            evidence.append(EvidenceIndicator(
                indicator_type="header_missing",
                description=f"Security header missing: {header}",
                weight=self.EVIDENCE_WEIGHTS["header_missing"],
                location="response_headers"
            ))
        
        # Version disclosure
        version_info = self._check_version_disclosure(response_headers, response_body)
        if version_info:
            evidence.append(EvidenceIndicator(
                indicator_type="version_disclosure",
                description=f"Version information disclosed: {version_info}",
                weight=self.EVIDENCE_WEIGHTS["version_disclosure"],
                matched_text=version_info,
                location="response"
            ))
        
        # Debug information
        if self._check_debug_info(response_body, finding_evidence):
            evidence.append(EvidenceIndicator(
                indicator_type="debug_info",
                description="Debug/stack trace information exposed",
                weight=self.EVIDENCE_WEIGHTS["debug_info"],
                location="response_body"
            ))
        
        # SSRF indicators
        if self._check_ssrf_patterns(finding_evidence, response_body):
            evidence.append(EvidenceIndicator(
                indicator_type="ssrf_indicator",
                description="SSRF vulnerability indicator detected",
                weight=self.EVIDENCE_WEIGHTS["ssrf_indicator"],
                location="response_body"
            ))
        
        # Path traversal
        if self._check_path_traversal(response_body, finding_evidence):
            evidence.append(EvidenceIndicator(
                indicator_type="path_traversal",
                description="Path traversal pattern detected",
                weight=self.EVIDENCE_WEIGHTS["path_traversal"],
                location="response_body"
            ))
        
        # If no specific evidence found, add generic indicator
        if not evidence and finding_evidence:
            evidence.append(EvidenceIndicator(
                indicator_type="generic_error",
                description="Evidence present but no specific pattern matched",
                weight=self.EVIDENCE_WEIGHTS["generic_error"],
                matched_text=finding_evidence[:200] if finding_evidence else None,
                location="finding_evidence"
            ))
        
        return evidence
    
    def _check_sql_patterns(self, response_body: str, evidence: str) -> bool:
        """Check for SQL injection indicators"""
        sql_patterns = [
            r"you have an error in your sql syntax",
            r"warning:\s*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"microsoft ole db provider for sql server",
            r"ora-\d{5}",
            r"postgresql.*error",
            r"sqlite.*error",
            r"sqlstate\[",
            r"pdo.*exception",
            r"syntax error.*sql",
            r"mysql_fetch",
            r"pg_query",
            r"sql syntax.*mysql",
            r"valid mysql result",
            r"mssql_query",
            r"odbc.*driver",
            r"driver.*sql.*server",
        ]
        
        text = (response_body or "") + " " + (evidence or "")
        text_lower = text.lower()
        
        for pattern in sql_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _extract_sql_error(self, text: str) -> Optional[str]:
        """Extract the SQL error message"""
        if not text:
            return None
        
        patterns = [
            r"(you have an error in your sql syntax.*?)(?:\n|$)",
            r"(ora-\d{5}:.*?)(?:\n|$)",
            r"(sqlstate\[.*?\].*?)(?:\n|$)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text.lower())
            if match:
                return match.group(1)[:200]
        
        return text[:200] if len(text) > 200 else text
    
    def _check_xss_patterns(
        self, response_body: str, evidence: str, request_data: Dict
    ) -> bool:
        """Check for XSS reflection"""
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
            r"<iframe",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
            r"eval\s*\(",
        ]
        
        text = (response_body or "") + " " + (evidence or "")
        text_lower = text.lower()
        
        for pattern in xss_patterns:
            if re.search(pattern, text_lower):
                return True
        
        # Check if payload from request is reflected
        payload = request_data.get("payload", "")
        if payload and payload in (response_body or ""):
            return True
        
        return False
    
    def _extract_xss_reflection(self, response_body: str) -> Optional[str]:
        """Extract the XSS reflection point"""
        if not response_body:
            return None
        
        patterns = [
            r"(<script[^>]*>.*?</script>)",
            r"(<[^>]+on\w+\s*=[^>]+>)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_body, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1)[:200]
        
        return None
    
    def _check_command_patterns(self, response_body: str, evidence: str) -> bool:
        """Check for command injection output"""
        cmd_patterns = [
            r"root:.*:0:0:",  # /etc/passwd
            r"uid=\d+.*gid=\d+",  # id command
            r"windows.*nt.*version",  # Windows version
            r"volume serial number",
            r"directory of [a-z]:\\",
            r"\[boot loader\]",  # Windows boot.ini
            r"total\s+\d+\s*\n.*drwx",  # ls -la output
        ]
        
        text = (response_body or "") + " " + (evidence or "")
        text_lower = text.lower()
        
        for pattern in cmd_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _extract_command_output(self, text: str) -> Optional[str]:
        """Extract command execution output"""
        if not text:
            return None
        
        # Look for common command outputs
        patterns = [
            r"(root:.*:0:0:.*)",
            r"(uid=\d+\(.*?\).*gid=\d+\(.*?\).*)",
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)[:200]
        
        return None
    
    def _check_security_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check for missing security headers"""
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy",
        ]
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing = []
        
        for header in required_headers:
            if header.lower() not in headers_lower:
                missing.append(header)
        
        return missing
    
    def _check_version_disclosure(
        self, headers: Dict[str, str], body: str
    ) -> Optional[str]:
        """Check for version disclosure"""
        version_patterns = [
            r"(apache/[\d.]+)",
            r"(nginx/[\d.]+)",
            r"(php/[\d.]+)",
            r"(asp\.net.*?[\d.]+)",
            r"(tomcat/[\d.]+)",
            r"(iis/[\d.]+)",
            r"(x-powered-by:\s*[\w\d./-]+)",
            r"(server:\s*[\w\d./-]+)",
        ]
        
        # Check headers
        for key, value in headers.items():
            if key.lower() in ["server", "x-powered-by"]:
                return f"{key}: {value}"
        
        # Check body
        for pattern in version_patterns:
            match = re.search(pattern, (body or "").lower())
            if match:
                return match.group(1)
        
        return None
    
    def _check_debug_info(self, response_body: str, evidence: str) -> bool:
        """Check for debug/stack trace information"""
        debug_patterns = [
            r"stack\s*trace",
            r"traceback.*most recent call",
            r"exception.*at.*line",
            r"debug\s*=\s*true",
            r"error_reporting.*e_all",
            r"display_errors.*on",
            r"\.php:\d+",
            r"\.py.*line\s*\d+",
            r"at\s+[\w.]+\.[\w]+\([\w.]+:\d+\)",  # Java stack trace
        ]
        
        text = (response_body or "") + " " + (evidence or "")
        text_lower = text.lower()
        
        for pattern in debug_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _check_ssrf_patterns(self, evidence: str, response_body: str) -> bool:
        """Check for SSRF indicators"""
        ssrf_patterns = [
            r"127\.0\.0\.1",
            r"localhost",
            r"192\.168\.\d+\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",
            r"169\.254\.\d+\.\d+",  # Link-local
            r"0\.0\.0\.0",
            r"\[::1\]",  # IPv6 localhost
            r"file://",
            r"gopher://",
            r"dict://",
        ]
        
        text = (evidence or "") + " " + (response_body or "")
        
        for pattern in ssrf_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _check_path_traversal(self, response_body: str, evidence: str) -> bool:
        """Check for path traversal indicators"""
        traversal_patterns = [
            r"root:.*:0:0:",  # /etc/passwd content
            r"\[boot loader\]",  # boot.ini
            r"windows.*system32",
            r"/etc/(passwd|shadow|hosts)",
            r"c:\\windows",
        ]
        
        text = (response_body or "") + " " + (evidence or "")
        text_lower = text.lower()
        
        for pattern in traversal_patterns:
            if re.search(pattern, text_lower):
                return True
        return False
    
    def _calculate_evidence_strength(
        self, evidence: List[EvidenceIndicator]
    ) -> float:
        """Calculate overall evidence strength from indicators"""
        if not evidence:
            return 0.0
        
        # Use weighted average with diminishing returns for multiple indicators
        total_weight = 0.0
        for i, e in enumerate(sorted(evidence, key=lambda x: x.weight, reverse=True)):
            # Apply diminishing returns: each additional piece of evidence
            # contributes less (80% of previous)
            diminishing_factor = 0.8 ** i
            total_weight += e.weight * diminishing_factor
        
        # Normalize to 0-1 range
        # Max theoretical: 1 + 0.8 + 0.64 + 0.51 + ... ≈ 5
        normalized = min(1.0, total_weight / 2.0)
        
        return round(normalized, 3)
    
    def _bayesian_confidence(
        self,
        evidence_strength: float,
        category: str,
        historical_context: Dict[str, Any]
    ) -> float:
        """
        Calculate Bayesian confidence score
        
        Uses: P(vuln|evidence) = P(evidence|vuln) * P(vuln) / P(evidence)
        """
        # Prior probability based on category
        prior = self.CATEGORY_PRIORS.get(category, 0.1)
        
        # Likelihood: P(evidence|vuln)
        # Higher evidence strength = more likely if actually vulnerable
        likelihood = evidence_strength
        
        # Historical adjustment
        # If similar findings were confirmed in the past, increase confidence
        historical_boost = 0.0
        if historical_context:
            confirmed_similar = historical_context.get("confirmed_similar", 0)
            total_similar = historical_context.get("total_similar", 0)
            if total_similar > 0:
                historical_boost = (confirmed_similar / total_similar) * 0.1
        
        # Bayesian calculation (simplified)
        # P(vuln|evidence) ∝ P(evidence|vuln) * P(vuln)
        posterior = likelihood * prior
        
        # Normalize and apply historical boost
        confidence = min(1.0, posterior * 3 + historical_boost)
        
        # Apply learned weight adjustments
        confidence = self._apply_learned_adjustments(confidence, category)
        
        return round(confidence, 3)
    
    def _apply_learned_adjustments(self, confidence: float, category: str) -> float:
        """Apply learned weight adjustments from feedback"""
        # This will be enhanced when feedback learning is integrated
        return confidence
    
    def _calculate_exploitability(
        self,
        finding: Dict[str, Any],
        evidence: List[EvidenceIndicator]
    ) -> float:
        """Calculate exploitability score (how easy to exploit)"""
        base_score = 0.5
        
        # Check if there's a PoC
        if finding.get("poc"):
            base_score += 0.2
        
        # Check evidence types that indicate easy exploitation
        easy_exploit_types = {
            "sql_error_pattern": 0.15,
            "xss_reflection": 0.12,
            "command_output": 0.2,
            "auth_bypass": 0.15,
        }
        
        for e in evidence:
            if e.indicator_type in easy_exploit_types:
                base_score += easy_exploit_types[e.indicator_type]
        
        # Check if parameter is identified
        if finding.get("parameter"):
            base_score += 0.1
        
        return min(1.0, round(base_score, 3))
    
    def _calculate_false_positive_probability(
        self,
        evidence: List[EvidenceIndicator],
        finding: Dict[str, Any],
        historical_context: Dict[str, Any]
    ) -> float:
        """Calculate probability of false positive"""
        # Start with base FP probability
        fp_prob = 0.3
        
        # Strong evidence reduces FP probability
        evidence_strength = self._calculate_evidence_strength(evidence)
        fp_prob -= evidence_strength * 0.25
        
        # Multiple evidence indicators reduce FP probability
        if len(evidence) >= 3:
            fp_prob -= 0.1
        
        # Specific high-confidence patterns reduce FP probability
        high_confidence_types = ["sql_error_pattern", "command_output", "xss_reflection"]
        for e in evidence:
            if e.indicator_type in high_confidence_types:
                fp_prob -= 0.1
        
        # Historical false positives increase FP probability
        if historical_context:
            fp_rate = historical_context.get("false_positive_rate", 0)
            fp_prob += fp_rate * 0.2
        
        # Generic evidence increases FP probability
        generic_count = sum(1 for e in evidence if e.indicator_type == "generic_error")
        fp_prob += generic_count * 0.15
        
        return max(0.0, min(1.0, round(fp_prob, 3)))
    
    def _build_reasoning_chain(
        self,
        finding: Dict[str, Any],
        evidence: List[EvidenceIndicator],
        confidence: float
    ) -> List[ReasoningStep]:
        """Build the step-by-step reasoning chain"""
        steps = []
        step_num = 1
        
        # Step 1: Initial observation
        steps.append(ReasoningStep(
            step_number=step_num,
            observation=f"Analyzed {finding.get('title', 'vulnerability')} at {finding.get('url', 'target')}",
            inference="Beginning vulnerability analysis",
            confidence_contribution=0.0
        ))
        step_num += 1
        
        # Step 2+: Evidence-based reasoning
        for e in evidence:
            contribution = e.weight * 0.3  # Each evidence contributes to confidence
            steps.append(ReasoningStep(
                step_number=step_num,
                observation=e.description,
                inference=self._get_evidence_inference(e),
                confidence_contribution=round(contribution, 3)
            ))
            step_num += 1
        
        # Final step: Conclusion
        confidence_level = self._get_confidence_level(confidence)
        steps.append(ReasoningStep(
            step_number=step_num,
            observation=f"Combined evidence strength: {len(evidence)} indicators",
            inference=f"Conclusion: {confidence_level.value} confidence ({confidence:.1%}) that this is a true positive",
            confidence_contribution=0.0
        ))
        
        return steps
    
    def _get_evidence_inference(self, evidence: EvidenceIndicator) -> str:
        """Get inference text for evidence type"""
        inferences = {
            "sql_error_pattern": "Database error confirms SQL injection vulnerability",
            "xss_reflection": "Script reflection confirms XSS vulnerability",
            "command_output": "System command output confirms code execution",
            "header_missing": "Missing security header indicates misconfiguration",
            "version_disclosure": "Version exposure enables targeted attacks",
            "debug_info": "Debug information leakage aids exploitation",
            "ssrf_indicator": "Internal resource access indicates SSRF",
            "path_traversal": "File system access confirms path traversal",
            "auth_bypass": "Authentication bypass confirmed",
            "idor_pattern": "Object reference manipulation possible",
            "generic_error": "Evidence present but requires manual verification",
        }
        return inferences.get(
            evidence.indicator_type, 
            "Evidence contributes to vulnerability confirmation"
        )
    
    def _get_confidence_level(self, confidence: float) -> ConfidenceLevel:
        """Convert numeric confidence to level"""
        if confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif confidence >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW
    
    def _adjust_severity(
        self,
        original_severity: str,
        confidence: float,
        exploitability: float,
        fp_probability: float
    ) -> Tuple[str, Optional[str]]:
        """Adjust severity based on AI analysis"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        current_index = severity_order.index(original_severity.lower())
        
        # High false positive probability = downgrade
        if fp_probability > 0.7:
            if current_index > 0:
                new_severity = severity_order[current_index - 1]
                return new_severity, "Downgraded due to high false positive probability"
        
        # Low confidence = downgrade
        if confidence < 0.3 and current_index > 0:
            new_severity = severity_order[current_index - 1]
            return new_severity, "Downgraded due to low AI confidence"
        
        # Very high confidence + exploitability = upgrade
        if confidence > 0.85 and exploitability > 0.7:
            if current_index < len(severity_order) - 1:
                new_severity = severity_order[current_index + 1]
                return new_severity, "Upgraded due to high confidence and exploitability"
        
        return original_severity, None
    
    def _get_pattern_category(self, indicator_type: str) -> str:
        """Map indicator type to OWASP category"""
        mapping = {
            "sql_error_pattern": "A03",
            "xss_reflection": "A03",
            "command_output": "A03",
            "ssrf_indicator": "A10",
            "path_traversal": "A01",
            "auth_bypass": "A07",
            "idor_pattern": "A01",
            "header_missing": "A05",
            "version_disclosure": "A05",
            "debug_info": "A05",
            "csrf_missing": "A01",
        }
        return mapping.get(indicator_type, "A05")
    
    def _build_reasoning_summary(
        self,
        finding: Dict[str, Any],
        evidence: List[EvidenceIndicator],
        confidence: float,
        reasoning_chain: List[ReasoningStep]
    ) -> str:
        """Build human-readable reasoning summary"""
        confidence_level = self._get_confidence_level(confidence)
        
        summary_parts = [
            f"AI Analysis: {confidence_level.value.replace('_', ' ').title()} confidence ({confidence:.1%})",
            f"",
            f"Evidence found ({len(evidence)} indicators):"
        ]
        
        for e in evidence[:5]:  # Top 5 evidence points
            summary_parts.append(f"  • {e.description}")
        
        if len(evidence) > 5:
            summary_parts.append(f"  ... and {len(evidence) - 5} more indicators")
        
        summary_parts.append("")
        summary_parts.append("Reasoning:")
        for step in reasoning_chain[-2:]:  # Last 2 steps
            summary_parts.append(f"  {step.step_number}. {step.inference}")
        
        return "\n".join(summary_parts)
    
    def batch_analyze(
        self,
        findings: List[Dict[str, Any]],
        responses: Dict[str, Tuple[str, Dict]] = None
    ) -> List[AIAnalysisResult]:
        """
        Analyze multiple findings in batch
        
        Args:
            findings: List of finding dictionaries
            responses: Map of finding_id -> (response_body, response_headers)
            
        Returns:
            List of AIAnalysisResult for each finding
        """
        responses = responses or {}
        results = []
        
        for finding in findings:
            finding_id = finding.get("id", "")
            response_data = responses.get(finding_id, ("", {}))
            
            result = self.analyze_finding(
                finding=finding,
                response_body=response_data[0] if response_data else "",
                response_headers=response_data[1] if len(response_data) > 1 else {}
            )
            results.append(result)
        
        return results
    
    def get_engine_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            "version": self.VERSION,
            "loaded_patterns": len(self.pattern_weights),
            "category_priors": self.CATEGORY_PRIORS,
            "evidence_types": list(self.EVIDENCE_WEIGHTS.keys()),
        }


# Convenience function for quick analysis
def analyze_vulnerability(
    finding: Dict[str, Any],
    response_body: str = "",
    response_headers: Dict[str, str] = None
) -> AIAnalysisResult:
    """Quick analysis without engine instantiation"""
    engine = JarwisAIEngine()
    return engine.analyze_finding(
        finding=finding,
        response_body=response_body,
        response_headers=response_headers or {}
    )
