"""
Jarwis AI Learning Service
============================

Service layer that integrates all AI components:
- AI Engine (Bayesian analysis)
- Pattern Matcher (vulnerability detection)
- Correlation Engine (attack chains)
- Feedback Learner (self-improvement)
- Adaptive Controller (scan optimization)

This provides a unified API for the application to use AI features.

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import logging
import json
import os

# Core AI imports
from core.jarwis_ai_engine import JarwisAIEngine, AIAnalysisResult
from core.pattern_matcher import PatternMatcher, PatternMatchResult
from core.correlation_engine import CorrelationEngine, AttackChain
from core.feedback_learner import FeedbackLearner, FeedbackEvent
from core.adaptive_controller import AdaptiveController, TargetProfile, AdaptiveStrategy

logger = logging.getLogger(__name__)


@dataclass
class EnhancedFinding:
    """A finding enhanced with AI analysis"""
    # Original finding data
    original: Dict[str, Any]
    
    # AI enhancements
    ai_confidence: float = 0.0
    ai_severity: str = ""
    exploitability_score: float = 0.0
    reasoning_chain: List[str] = field(default_factory=list)
    related_vulns: List[str] = field(default_factory=list)
    attack_chains: List[str] = field(default_factory=list)
    
    # Remediation suggestions
    priority_rank: int = 0
    estimated_fix_time: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            **self.original,
            "ai_analysis": {
                "confidence": self.ai_confidence,
                "adjusted_severity": self.ai_severity,
                "exploitability": self.exploitability_score,
                "reasoning": self.reasoning_chain,
                "priority_rank": self.priority_rank
            }
        }


@dataclass
class ScanInsights:
    """AI-generated insights about a scan"""
    total_findings: int
    severity_distribution: Dict[str, int]
    top_vulnerabilities: List[str]
    attack_chains: List[AttackChain]
    risk_score: float
    recommendations: List[str]
    target_profile: Optional[TargetProfile] = None


class AILearningService:
    """
    Unified AI Learning Service
    
    Provides:
    1. Finding enhancement with AI analysis
    2. Attack chain detection
    3. Self-learning from user feedback
    4. Adaptive scan strategies
    5. Scan insights generation
    """
    
    def __init__(self, data_dir: str = "data"):
        """
        Initialize the AI learning service
        
        Args:
            data_dir: Directory for storing learned weights
        """
        self.data_dir = data_dir
        
        # Initialize AI components
        self.ai_engine = JarwisAIEngine()
        self.pattern_matcher = PatternMatcher()
        self.correlation_engine = CorrelationEngine()
        self.feedback_learner = FeedbackLearner()
        self.adaptive_controller = AdaptiveController()
        
        # Load any persisted learning data
        self._load_learned_weights()
    
    # ===== FINDING ENHANCEMENT =====
    
    def enhance_finding(self, finding: Dict[str, Any]) -> EnhancedFinding:
        """
        Enhance a finding with AI analysis
        
        Args:
            finding: Raw finding dictionary
            
        Returns:
            EnhancedFinding with AI insights
        """
        # Run AI analysis
        analysis = self.ai_engine.analyze_finding(finding)
        
        # Get pattern matches for additional context
        evidence = finding.get("evidence", "") or finding.get("description", "")
        patterns = self.pattern_matcher.analyze(evidence)
        
        return EnhancedFinding(
            original=finding,
            ai_confidence=analysis.confidence,
            ai_severity=analysis.adjusted_severity,
            exploitability_score=analysis.exploitability_score,
            reasoning_chain=[step.explanation for step in analysis.reasoning_chain],
            related_vulns=patterns.top_matches[:3] if patterns.top_matches else []
        )
    
    def enhance_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[EnhancedFinding]:
        """
        Enhance multiple findings with AI analysis
        
        Args:
            findings: List of raw findings
            
        Returns:
            List of EnhancedFinding with AI insights
        """
        enhanced = []
        
        for finding in findings:
            try:
                enhanced_finding = self.enhance_finding(finding)
                enhanced.append(enhanced_finding)
            except Exception as e:
                logger.warning(f"Failed to enhance finding: {e}")
                enhanced.append(EnhancedFinding(original=finding))
        
        # Detect attack chains
        chains = self.correlation_engine.detect_chains(findings)
        
        # Add chain info to relevant findings
        for chain in chains:
            for vuln_node in chain.vulnerabilities:
                for ef in enhanced:
                    if ef.original.get("id") == vuln_node.finding_id:
                        ef.attack_chains.append(chain.chain_type.value)
        
        # Rank by priority
        enhanced = self._rank_findings(enhanced)
        
        return enhanced
    
    def _rank_findings(
        self,
        findings: List[EnhancedFinding]
    ) -> List[EnhancedFinding]:
        """Rank findings by priority"""
        severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        
        # Sort by: has_attack_chain, severity, confidence
        def sort_key(f: EnhancedFinding) -> Tuple[int, int, float]:
            has_chain = 0 if f.attack_chains else 1
            sev = severity_order.get(f.ai_severity.lower(), 5)
            conf = 1 - f.ai_confidence  # Higher confidence = lower value = higher priority
            return (has_chain, sev, conf)
        
        sorted_findings = sorted(findings, key=sort_key)
        
        for rank, finding in enumerate(sorted_findings, 1):
            finding.priority_rank = rank
        
        return sorted_findings
    
    # ===== SCAN INSIGHTS =====
    
    def generate_scan_insights(
        self,
        findings: List[Dict[str, Any]],
        target_url: Optional[str] = None
    ) -> ScanInsights:
        """
        Generate AI insights about a scan
        
        Args:
            findings: List of findings
            target_url: Optional target URL for profiling
            
        Returns:
            ScanInsights with analysis
        """
        # Get severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Get top vulnerability types
        vuln_types: Dict[str, int] = {}
        for finding in findings:
            category = finding.get("category", "Unknown")
            vuln_types[category] = vuln_types.get(category, 0) + 1
        
        top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Detect attack chains
        chains = self.correlation_engine.detect_chains(findings)
        
        # Calculate risk score (0-100)
        risk_score = self._calculate_risk_score(findings, chains)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            severity_counts, top_vulns, chains
        )
        
        # Profile target if URL provided
        target_profile = None
        if target_url:
            target_profile = self.adaptive_controller.profile_target(
                target_url, findings
            )
        
        return ScanInsights(
            total_findings=len(findings),
            severity_distribution=severity_counts,
            top_vulnerabilities=[v[0] for v in top_vulns],
            attack_chains=chains,
            risk_score=risk_score,
            recommendations=recommendations,
            target_profile=target_profile
        )
    
    def _calculate_risk_score(
        self,
        findings: List[Dict],
        chains: List[AttackChain]
    ) -> float:
        """Calculate overall risk score (0-100)"""
        if not findings:
            return 0.0
        
        # Base score from severities
        severity_weights = {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 3,
            "info": 1
        }
        
        base_score = 0
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            base_score += severity_weights.get(sev, 1)
        
        # Cap base score at 80
        base_score = min(80, base_score)
        
        # Add chain bonus (up to 20)
        chain_bonus = min(20, len(chains) * 10)
        
        return min(100, base_score + chain_bonus)
    
    def _generate_recommendations(
        self,
        severity_counts: Dict[str, int],
        top_vulns: List[Tuple[str, int]],
        chains: List[AttackChain]
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Priority recommendations
        if severity_counts.get("critical", 0) > 0:
            recommendations.append(
                f"⚠️ URGENT: Fix {severity_counts['critical']} critical "
                f"vulnerabilities immediately - these pose immediate risk"
            )
        
        if severity_counts.get("high", 0) > 0:
            recommendations.append(
                f"🔴 Address {severity_counts['high']} high-severity issues "
                f"before production deployment"
            )
        
        # Attack chain recommendations
        if chains:
            recommendations.append(
                f"🔗 {len(chains)} attack chain(s) detected - these show how "
                f"vulnerabilities can be combined for greater impact"
            )
        
        # Category-specific recommendations
        for vuln_type, count in top_vulns[:3]:
            if "injection" in vuln_type.lower():
                recommendations.append(
                    f"💉 {count} injection vulnerabilities found - implement "
                    f"parameterized queries and input validation"
                )
            elif "xss" in vuln_type.lower():
                recommendations.append(
                    f"📝 {count} XSS issues found - implement output encoding "
                    f"and Content Security Policy"
                )
            elif "access" in vuln_type.lower() or "idor" in vuln_type.lower():
                recommendations.append(
                    f"🔐 {count} access control issues - implement proper "
                    f"authorization checks on all endpoints"
                )
        
        # General recommendation
        if not recommendations:
            recommendations.append(
                "✅ Review all findings and prioritize fixes based on "
                "severity and business impact"
            )
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    # ===== FEEDBACK & LEARNING =====
    
    def record_feedback(
        self,
        finding_id: str,
        feedback_type: str,  # "confirmed" or "false_positive"
        finding: Dict[str, Any],
        user_notes: str = ""
    ) -> bool:
        """
        Record user feedback for a finding
        
        Args:
            finding_id: ID of the finding
            feedback_type: "confirmed" or "false_positive"
            finding: The finding data
            user_notes: Optional user notes
            
        Returns:
            True if feedback recorded successfully
        """
        try:
            # Extract pattern and scanner info
            evidence = finding.get("evidence", "") or finding.get("description", "")
            scanner = finding.get("scanner", "unknown")
            target_url = finding.get("url", "")
            
            # Get matched patterns
            pattern_matches = self.pattern_matcher.analyze(evidence)
            patterns_matched = pattern_matches.top_matches[:3] if pattern_matches.top_matches else []
            
            # Create feedback event
            event = FeedbackEvent(
                finding_id=finding_id,
                feedback_type=feedback_type,
                scanner=scanner,
                patterns_matched=patterns_matched,
                target_type=self._classify_target(target_url),
                user_notes=user_notes
            )
            
            # Process feedback
            self.feedback_learner.process_feedback(event)
            
            # Persist learned weights
            self._save_learned_weights()
            
            logger.info(f"Recorded {feedback_type} feedback for finding {finding_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record feedback: {e}")
            return False
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get statistics about what the AI has learned"""
        return self.feedback_learner.get_stats()
    
    def _classify_target(self, url: str) -> str:
        """Classify target type from URL"""
        url_lower = url.lower()
        
        if "api" in url_lower or "/v1/" in url_lower or "/v2/" in url_lower:
            return "api"
        elif "admin" in url_lower:
            return "admin_panel"
        elif "login" in url_lower or "auth" in url_lower:
            return "auth"
        else:
            return "web"
    
    # ===== ADAPTIVE SCANNING =====
    
    def get_scan_strategy(
        self,
        target_url: str,
        scan_type: str = "web"
    ) -> AdaptiveStrategy:
        """
        Get adaptive scan strategy for a target
        
        Args:
            target_url: Target URL to scan
            scan_type: Type of scan (web, api, etc.)
            
        Returns:
            AdaptiveStrategy with optimized settings
        """
        # Profile the target
        profile = self.adaptive_controller.profile_target(target_url)
        
        # Build strategy
        strategy = self.adaptive_controller.build_strategy(
            profile,
            {"scan_type": scan_type}
        )
        
        return strategy
    
    def update_strategy_metrics(
        self,
        target_url: str,
        metrics: Dict[str, Any]
    ) -> AdaptiveStrategy:
        """
        Update scan strategy based on real-time metrics
        
        Args:
            target_url: Target being scanned
            metrics: Current scan metrics
            
        Returns:
            Updated AdaptiveStrategy
        """
        return self.adaptive_controller.update_strategy(target_url, metrics)
    
    # ===== PERSISTENCE =====
    
    def _load_learned_weights(self):
        """Load persisted learning weights"""
        weights_file = os.path.join(self.data_dir, "ai_weights.json")
        
        if os.path.exists(weights_file):
            try:
                with open(weights_file, "r") as f:
                    weights = json.load(f)
                
                # Apply to pattern matcher
                if "pattern_weights" in weights:
                    self.pattern_matcher.learned_weights = weights["pattern_weights"]
                
                # Apply to feedback learner
                if "feedback_stats" in weights:
                    self.feedback_learner.load_stats(weights["feedback_stats"])
                
                logger.info("Loaded AI learning weights from disk")
                
            except Exception as e:
                logger.warning(f"Failed to load learning weights: {e}")
    
    def _save_learned_weights(self):
        """Persist learning weights to disk"""
        weights_file = os.path.join(self.data_dir, "ai_weights.json")
        
        try:
            os.makedirs(self.data_dir, exist_ok=True)
            
            weights = {
                "pattern_weights": self.pattern_matcher.learned_weights,
                "feedback_stats": self.feedback_learner.export_stats(),
                "last_updated": datetime.now().isoformat()
            }
            
            with open(weights_file, "w") as f:
                json.dump(weights, f, indent=2)
            
            logger.info("Saved AI learning weights to disk")
            
        except Exception as e:
            logger.warning(f"Failed to save learning weights: {e}")
    
    # ===== PATTERN ANALYSIS =====
    
    def analyze_text(self, text: str) -> PatternMatchResult:
        """
        Analyze text for vulnerability patterns
        
        Args:
            text: Text to analyze (response body, code, etc.)
            
        Returns:
            PatternMatchResult with detected patterns
        """
        return self.pattern_matcher.analyze(text)
    
    def detect_vulnerabilities(
        self,
        response_body: str,
        response_headers: Dict[str, str] = None
    ) -> List[Dict[str, Any]]:
        """
        Detect potential vulnerabilities in a response
        
        Args:
            response_body: HTTP response body
            response_headers: Optional response headers
            
        Returns:
            List of detected vulnerability indicators
        """
        result = self.pattern_matcher.analyze(response_body)
        
        detections = []
        
        for match in result.matches:
            if match.confidence >= 0.5:
                detections.append({
                    "pattern": match.pattern_name,
                    "category": match.category,
                    "confidence": match.confidence,
                    "matched_text": match.matched_text[:100]
                })
        
        # Check headers if provided
        if response_headers:
            header_issues = self._check_security_headers(response_headers)
            detections.extend(header_issues)
        
        return detections
    
    def _check_security_headers(
        self,
        headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        issues = []
        
        required_headers = {
            "content-security-policy": "CSP protects against XSS",
            "x-frame-options": "Prevents clickjacking",
            "x-content-type-options": "Prevents MIME sniffing",
            "strict-transport-security": "Enforces HTTPS"
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, description in required_headers.items():
            if header not in headers_lower:
                issues.append({
                    "pattern": f"missing_{header.replace('-', '_')}",
                    "category": "security_headers",
                    "confidence": 0.9,
                    "matched_text": f"Missing {header} - {description}"
                })
        
        return issues


# ===== SINGLETON INSTANCE =====

_service_instance: Optional[AILearningService] = None


def get_ai_service() -> AILearningService:
    """Get or create the AI learning service singleton"""
    global _service_instance
    
    if _service_instance is None:
        _service_instance = AILearningService()
    
    return _service_instance


# ===== CONVENIENCE FUNCTIONS =====

def enhance_findings(findings: List[Dict]) -> List[Dict]:
    """Quick function to enhance findings"""
    service = get_ai_service()
    enhanced = service.enhance_findings(findings)
    return [ef.to_dict() for ef in enhanced]


def get_scan_insights(findings: List[Dict], target_url: str = None) -> Dict:
    """Quick function to get scan insights"""
    service = get_ai_service()
    insights = service.generate_scan_insights(findings, target_url)
    
    return {
        "total_findings": insights.total_findings,
        "severity_distribution": insights.severity_distribution,
        "top_vulnerabilities": insights.top_vulnerabilities,
        "attack_chain_count": len(insights.attack_chains),
        "risk_score": insights.risk_score,
        "recommendations": insights.recommendations
    }


def record_finding_feedback(
    finding_id: str,
    feedback_type: str,
    finding: Dict
) -> bool:
    """Quick function to record feedback"""
    service = get_ai_service()
    return service.record_feedback(finding_id, feedback_type, finding)
