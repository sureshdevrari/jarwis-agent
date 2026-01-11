"""
Jarwis Intent Classifier - Natural Language Understanding
===========================================================

Classifies user queries to route them to the appropriate handler
without needing an LLM. Uses pattern matching and keyword extraction.

Features:
- Multi-intent classification
- Entity extraction (vuln types, endpoints, severities)
- Context-aware routing
- Fallback handling

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class Intent(Enum):
    """User intent categories"""
    # Brand/Identity
    BRAND_INFO = "brand_info"           # "What is Jarwis?"
    FOUNDER_INFO = "founder_info"       # "Who made Jarwis?"
    CAPABILITIES = "capabilities"       # "What can you do?"
    
    # Vulnerability Information
    VULN_DEFINITION = "vuln_definition"  # "What is SQL injection?"
    VULN_EXPLANATION = "vuln_explanation"  # "Explain this XSS finding"
    OWASP_INFO = "owasp_info"           # "What is A01?"
    
    # Remediation
    FIX_GUIDANCE = "fix_guidance"       # "How do I fix this?"
    CODE_EXAMPLE = "code_example"       # "Show me code to prevent XSS"
    BEST_PRACTICE = "best_practice"     # "Best practices for auth"
    
    # Scan Analysis
    SCAN_SUMMARY = "scan_summary"       # "Summarize my scan"
    FINDING_LIST = "finding_list"       # "What vulnerabilities were found?"
    SEVERITY_BREAKDOWN = "severity_breakdown"  # "How many critical findings?"
    MOST_CRITICAL = "most_critical"     # "What's the most critical issue?"
    
    # Specific Finding
    FINDING_DETAILS = "finding_details"  # "Tell me about finding X"
    FINDING_IMPACT = "finding_impact"    # "What's the impact of this?"
    FINDING_PRIORITY = "finding_priority"  # "Should I fix this first?"
    
    # Attack Chains
    ATTACK_CHAIN = "attack_chain"       # "Are there attack chains?"
    EXPLOITATION = "exploitation"       # "How could this be exploited?"
    
    # Security Concepts
    SECURITY_CONCEPT = "security_concept"  # "What is defense in depth?"
    COMPLIANCE = "compliance"           # "Is this PCI compliant?"
    
    # Off-topic
    OFF_TOPIC = "off_topic"             # Weather, jokes, etc.
    
    # Fallback
    UNKNOWN = "unknown"                 # Can't classify


class EntityType(Enum):
    """Types of entities to extract"""
    VULNERABILITY = "vulnerability"
    SEVERITY = "severity"
    OWASP_CATEGORY = "owasp_category"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    FINDING_ID = "finding_id"


@dataclass
class Entity:
    """An extracted entity"""
    entity_type: EntityType
    value: str
    confidence: float
    start: int = 0
    end: int = 0


@dataclass
class ClassificationResult:
    """Result of intent classification"""
    primary_intent: Intent
    confidence: float
    
    # Secondary intents (for complex queries)
    secondary_intents: List[Intent] = field(default_factory=list)
    
    # Extracted entities
    entities: List[Entity] = field(default_factory=list)
    
    # Handler routing
    suggested_handler: str = ""
    requires_context: bool = False
    requires_scan_data: bool = False
    
    # Response hints
    response_type: str = "text"  # text, code, list, chart


class IntentClassifier:
    """
    Intent Classification Engine
    
    Routes user queries to appropriate handlers using
    pattern matching and keyword extraction.
    """
    
    # Intent patterns: (intent, patterns, keywords, priority)
    INTENT_PATTERNS: List[Tuple[Intent, List[str], List[str], int]] = [
        # Brand/Identity (highest priority for exact matches)
        (Intent.BRAND_INFO, 
         [r"what is jarwis", r"who is jarwis", r"tell me about jarwis", r"what are you",
          r"what does jarwis do", r"how does jarwis work", r"jarwis agi"],
         ["jarwis", "about you", "who are you", "agi security", "security engineer"],
         100),
        
        (Intent.FOUNDER_INFO,
         [r"who (made|created|built|founded)", r"founder", r"creator", r"suresh",
          r"who started jarwis", r"who is behind jarwis"],
         ["founder", "creator", "made you", "built you", "suresh", "devrari", "ceo"],
         100),
        
        (Intent.CAPABILITIES,
         [r"what can you do", r"capabilities", r"features", r"help me with",
          r"what do you support", r"what types of scans"],
         ["can you do", "help", "capabilities", "features", "abilities", "support"],
         90),
        
        # Target audience
        (Intent.BRAND_INFO,
         [r"who (is|are) jarwis for", r"who uses jarwis", r"target (audience|users)",
          r"who should use", r"is jarwis for (developers|engineers|security)"],
         ["who uses", "for developers", "for engineers", "for security", "target"],
         90),
        
        # AI vs humans
        (Intent.BRAND_INFO,
         [r"(replacing|replace) (humans|engineers|developers|people)",
          r"will (you|jarwis|ai) replace", r"job replacement", r"ai vs human"],
         ["replace humans", "replace engineers", "ai replace", "job replacement"],
         95),
        
        # Vulnerability definitions
        (Intent.VULN_DEFINITION,
         [r"what is (an? )?(sql|xss|csrf|ssrf|idor|xxe|ssti|ldap|xpath)",
          r"explain (sql|xss|csrf|ssrf|idor|xxe|ssti)",
          r"define (sql|xss|csrf|ssrf|idor)"],
         ["what is sql", "what is xss", "what is csrf", "what is ssrf", 
          "what is idor", "what is xxe", "what is injection", "define"],
         85),
        
        (Intent.OWASP_INFO,
         [r"what is (owasp|a0[1-9]|a10)", r"owasp top", r"owasp category"],
         ["owasp", "a01", "a02", "a03", "a04", "a05", "a06", "a07", "a08", "a09", "a10"],
         85),
        
        # Remediation (high priority - users often ask for fixes)
        (Intent.FIX_GUIDANCE,
         [r"how (do i|can i|to) fix", r"how (do i|can i|to) remediate",
          r"remediation", r"fix this", r"patch this", r"resolve this"],
         ["fix", "remediate", "patch", "resolve", "mitigate", "prevent"],
         90),
        
        (Intent.CODE_EXAMPLE,
         [r"show (me )?(code|example)", r"code (example|sample|snippet)",
          r"how to (implement|write|code)"],
         ["code", "example", "snippet", "implementation", "sample code"],
         85),
        
        (Intent.BEST_PRACTICE,
         [r"best practice", r"secure way", r"recommended", r"should i"],
         ["best practice", "recommended", "secure way", "guidelines", "standard"],
         80),
        
        # Scan analysis
        (Intent.SCAN_SUMMARY,
         [r"summarize (my |the )?scan", r"scan (summary|results|overview)",
          r"what did (you|the scan) find"],
         ["summarize", "summary", "overview", "results", "scan found"],
         85),
        
        (Intent.FINDING_LIST,
         [r"(list|show) (all )?(vulnerabilities|findings|issues)",
          r"what (vulnerabilities|findings|issues)"],
         ["list", "vulnerabilities", "findings", "issues", "all findings"],
         80),
        
        (Intent.SEVERITY_BREAKDOWN,
         [r"how many (critical|high|medium|low)",
          r"severity (breakdown|distribution|count)",
          r"(critical|high) (count|number)"],
         ["how many", "count", "severity", "breakdown", "distribution"],
         80),
        
        (Intent.MOST_CRITICAL,
         [r"most (critical|important|urgent|severe)",
          r"(biggest|worst|top) (issue|vulnerability|risk)",
          r"priority (issue|finding)"],
         ["most critical", "most important", "worst", "priority", "urgent"],
         85),
        
        # Specific finding
        (Intent.FINDING_DETAILS,
         [r"tell me about (finding|vulnerability|issue)",
          r"details (of|about|for) (finding|vulnerability)",
          r"explain (this |the )?(finding|vulnerability)"],
         ["tell me about", "details", "explain finding", "more about"],
         75),
        
        (Intent.FINDING_IMPACT,
         [r"what('s| is) the impact", r"impact of (this|the)",
          r"how (bad|serious|severe) is"],
         ["impact", "how bad", "serious", "damage", "consequences"],
         80),
        
        (Intent.FINDING_PRIORITY,
         [r"should i fix (this )?first", r"priority", r"fix first",
          r"which (one|vulnerability) first"],
         ["fix first", "priority", "which first", "order", "triage"],
         80),
        
        # Attack chains
        (Intent.ATTACK_CHAIN,
         [r"attack chain", r"chain of (vulnerabilities|attacks)",
          r"combined (attack|impact)", r"related (vulnerabilities|findings)"],
         ["attack chain", "chain", "combined", "related", "linked"],
         85),
        
        (Intent.EXPLOITATION,
         [r"how (could|can|would) .* (exploit|attack|abuse)",
          r"exploitation", r"attack (scenario|vector|path)"],
         ["exploit", "attack", "abuse", "scenario", "vector"],
         85),
        
        # Security concepts
        (Intent.SECURITY_CONCEPT,
         [r"what is (defense|security|zero trust|principle of least)",
          r"explain (security|defense|zero trust)"],
         ["defense in depth", "zero trust", "least privilege", "security model"],
         70),
        
        (Intent.COMPLIANCE,
         [r"(pci|hipaa|gdpr|soc2|iso) compliant",
          r"compliance", r"regulatory", r"audit"],
         ["pci", "hipaa", "gdpr", "soc2", "iso", "compliant", "compliance"],
         75),
        
        # Off-topic detection
        (Intent.OFF_TOPIC,
         [r"weather", r"joke", r"recipe", r"(play|tell) me (a |)(song|joke|story)",
          r"who is (the president|elon|trump|biden)"],
         ["weather", "joke", "recipe", "song", "story", "movie", "sports", "news"],
         100),
    ]
    
    # Vulnerability type patterns for entity extraction
    VULN_PATTERNS: Dict[str, List[str]] = {
        "sql_injection": ["sql injection", "sqli", "sql", "database injection"],
        "xss": ["xss", "cross-site scripting", "cross site scripting", "script injection"],
        "csrf": ["csrf", "cross-site request forgery", "request forgery"],
        "ssrf": ["ssrf", "server-side request forgery", "server side request"],
        "idor": ["idor", "insecure direct object", "object reference"],
        "xxe": ["xxe", "xml external entity", "xml injection"],
        "ssti": ["ssti", "server-side template", "template injection"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi"],
        "command_injection": ["command injection", "os command", "rce", "code execution"],
        "auth_bypass": ["authentication bypass", "auth bypass", "broken auth"],
        "broken_access": ["broken access", "access control", "authorization"],
        "sensitive_data": ["sensitive data", "data exposure", "information disclosure"],
        "security_headers": ["security headers", "missing headers", "csp", "hsts"],
        "jwt": ["jwt", "json web token", "token manipulation"],
        "file_upload": ["file upload", "unrestricted upload", "upload vulnerability"],
    }
    
    # Severity patterns
    SEVERITY_PATTERNS: Dict[str, List[str]] = {
        "critical": ["critical", "crit", "p0", "severity 1"],
        "high": ["high", "severe", "p1", "severity 2"],
        "medium": ["medium", "moderate", "p2", "severity 3"],
        "low": ["low", "minor", "p3", "severity 4"],
        "info": ["info", "informational", "note"],
    }
    
    # Technology patterns
    TECH_PATTERNS: Dict[str, List[str]] = {
        "python": ["python", "django", "flask", "fastapi"],
        "javascript": ["javascript", "js", "node", "nodejs", "react", "vue", "angular"],
        "php": ["php", "laravel", "wordpress", "drupal"],
        "java": ["java", "spring", "springboot", "tomcat"],
        "csharp": ["c#", "csharp", ".net", "dotnet", "asp.net"],
        "ruby": ["ruby", "rails", "ruby on rails"],
        "go": ["go", "golang"],
    }
    
    def __init__(self, knowledge_base=None):
        """
        Initialize the intent classifier
        
        Args:
            knowledge_base: Optional knowledge base for enhanced classification
        """
        self.knowledge_base = knowledge_base
        
        # Compile patterns for faster matching
        self._compiled_patterns: Dict[Intent, List[re.Pattern]] = {}
        for intent, patterns, _, _ in self.INTENT_PATTERNS:
            self._compiled_patterns[intent] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    def classify(
        self,
        query: str,
        context: Dict[str, Any] = None
    ) -> ClassificationResult:
        """
        Classify user query intent
        
        Args:
            query: User's question/query
            context: Optional context (current scan, previous queries, etc.)
            
        Returns:
            ClassificationResult with intent and entities
        """
        context = context or {}
        query_lower = query.lower().strip()
        
        # Score each intent
        intent_scores: Dict[Intent, float] = {}
        
        for intent, patterns, keywords, priority in self.INTENT_PATTERNS:
            score = 0.0
            
            # Pattern matching
            compiled = self._compiled_patterns.get(intent, [])
            for pattern in compiled:
                if pattern.search(query_lower):
                    score += 0.5
            
            # Keyword matching
            keyword_matches = sum(1 for kw in keywords if kw in query_lower)
            if keyword_matches > 0:
                score += 0.3 * min(1.0, keyword_matches / 2)
            
            # Priority boost
            score *= (priority / 100)
            
            if score > 0:
                intent_scores[intent] = score
        
        # Get primary intent
        if intent_scores:
            primary_intent = max(intent_scores, key=intent_scores.get)
            confidence = min(0.95, intent_scores[primary_intent])
        else:
            primary_intent = Intent.UNKNOWN
            confidence = 0.2
        
        # Get secondary intents (above threshold)
        secondary = [
            intent for intent, score in intent_scores.items()
            if intent != primary_intent and score > 0.3
        ]
        
        # Extract entities
        entities = self._extract_entities(query_lower)
        
        # Determine handler and requirements
        handler, requires_context, requires_scan, response_type = self._get_handler_info(
            primary_intent, entities, context
        )
        
        return ClassificationResult(
            primary_intent=primary_intent,
            confidence=round(confidence, 3),
            secondary_intents=secondary[:3],
            entities=entities,
            suggested_handler=handler,
            requires_context=requires_context,
            requires_scan_data=requires_scan,
            response_type=response_type
        )
    
    def _extract_entities(self, query: str) -> List[Entity]:
        """Extract entities from query"""
        entities = []
        
        # Extract vulnerability types
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern in patterns:
                if pattern in query:
                    match = re.search(re.escape(pattern), query, re.IGNORECASE)
                    if match:
                        entities.append(Entity(
                            entity_type=EntityType.VULNERABILITY,
                            value=vuln_type,
                            confidence=0.9,
                            start=match.start(),
                            end=match.end()
                        ))
                        break  # Only add once per type
        
        # Extract severities
        for severity, patterns in self.SEVERITY_PATTERNS.items():
            for pattern in patterns:
                if pattern in query:
                    entities.append(Entity(
                        entity_type=EntityType.SEVERITY,
                        value=severity,
                        confidence=0.9
                    ))
                    break
        
        # Extract OWASP categories
        owasp_pattern = r"\b(a0[1-9]|a10)\b"
        for match in re.finditer(owasp_pattern, query, re.IGNORECASE):
            entities.append(Entity(
                entity_type=EntityType.OWASP_CATEGORY,
                value=match.group(1).upper(),
                confidence=0.95,
                start=match.start(),
                end=match.end()
            ))
        
        # Extract technologies
        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if pattern in query:
                    entities.append(Entity(
                        entity_type=EntityType.TECHNOLOGY,
                        value=tech,
                        confidence=0.85
                    ))
                    break
        
        # Extract URLs/endpoints
        url_pattern = r"(https?://[^\s]+|/[a-zA-Z0-9/_-]+)"
        for match in re.finditer(url_pattern, query):
            entities.append(Entity(
                entity_type=EntityType.ENDPOINT,
                value=match.group(1),
                confidence=0.8,
                start=match.start(),
                end=match.end()
            ))
        
        return entities
    
    def _get_handler_info(
        self,
        intent: Intent,
        entities: List[Entity],
        context: Dict[str, Any]
    ) -> Tuple[str, bool, bool, str]:
        """
        Get handler routing information
        
        Returns:
            (handler_name, requires_context, requires_scan_data, response_type)
        """
        handler_map = {
            # Brand handlers
            Intent.BRAND_INFO: ("brand_handler", False, False, "text"),
            Intent.FOUNDER_INFO: ("brand_handler", False, False, "text"),
            Intent.CAPABILITIES: ("brand_handler", False, False, "list"),
            
            # Vulnerability info handlers
            Intent.VULN_DEFINITION: ("knowledge_handler", False, False, "text"),
            Intent.VULN_EXPLANATION: ("knowledge_handler", True, True, "text"),
            Intent.OWASP_INFO: ("knowledge_handler", False, False, "text"),
            
            # Remediation handlers
            Intent.FIX_GUIDANCE: ("remediation_handler", True, True, "text"),
            Intent.CODE_EXAMPLE: ("remediation_handler", True, False, "code"),
            Intent.BEST_PRACTICE: ("knowledge_handler", False, False, "list"),
            
            # Scan analysis handlers
            Intent.SCAN_SUMMARY: ("scan_handler", True, True, "text"),
            Intent.FINDING_LIST: ("scan_handler", True, True, "list"),
            Intent.SEVERITY_BREAKDOWN: ("scan_handler", True, True, "chart"),
            Intent.MOST_CRITICAL: ("scan_handler", True, True, "text"),
            
            # Specific finding handlers
            Intent.FINDING_DETAILS: ("finding_handler", True, True, "text"),
            Intent.FINDING_IMPACT: ("finding_handler", True, True, "text"),
            Intent.FINDING_PRIORITY: ("finding_handler", True, True, "list"),
            
            # Attack chain handlers
            Intent.ATTACK_CHAIN: ("correlation_handler", True, True, "chart"),
            Intent.EXPLOITATION: ("correlation_handler", True, True, "text"),
            
            # Security concept handlers
            Intent.SECURITY_CONCEPT: ("knowledge_handler", False, False, "text"),
            Intent.COMPLIANCE: ("knowledge_handler", False, False, "text"),
            
            # Special handlers
            Intent.OFF_TOPIC: ("off_topic_handler", False, False, "text"),
            Intent.UNKNOWN: ("fallback_handler", True, False, "text"),
        }
        
        return handler_map.get(intent, ("fallback_handler", True, False, "text"))
    
    def get_clarifying_question(
        self,
        result: ClassificationResult
    ) -> Optional[str]:
        """
        Get a clarifying question if intent is ambiguous
        
        Args:
            result: Classification result
            
        Returns:
            Optional clarifying question
        """
        if result.confidence > 0.6:
            return None
        
        if result.primary_intent == Intent.UNKNOWN:
            return "I'm not sure I understood. Are you asking about:\n" \
                   "1. A specific vulnerability or finding?\n" \
                   "2. Your scan results?\n" \
                   "3. Security best practices?"
        
        if result.secondary_intents:
            options = [result.primary_intent] + result.secondary_intents[:2]
            option_text = self._format_intent_options(options)
            return f"Did you mean:\n{option_text}"
        
        # Missing entities
        if result.primary_intent in [Intent.VULN_DEFINITION, Intent.FIX_GUIDANCE]:
            vuln_entities = [e for e in result.entities if e.entity_type == EntityType.VULNERABILITY]
            if not vuln_entities:
                return "Which vulnerability type are you asking about? " \
                       "(e.g., SQL injection, XSS, CSRF, IDOR)"
        
        return None
    
    def _format_intent_options(self, intents: List[Intent]) -> str:
        """Format intent options for clarification"""
        descriptions = {
            Intent.VULN_DEFINITION: "Learn about a vulnerability type",
            Intent.FIX_GUIDANCE: "Get remediation guidance",
            Intent.SCAN_SUMMARY: "See your scan results",
            Intent.FINDING_DETAILS: "Learn about a specific finding",
            Intent.ATTACK_CHAIN: "See attack chains",
        }
        
        lines = []
        for i, intent in enumerate(intents, 1):
            desc = descriptions.get(intent, intent.value.replace("_", " ").title())
            lines.append(f"{i}. {desc}")
        
        return "\n".join(lines)
    
    def is_off_topic(self, query: str) -> bool:
        """Quick check if query is off-topic"""
        result = self.classify(query)
        return result.primary_intent == Intent.OFF_TOPIC
    
    def extract_vuln_type(self, query: str) -> Optional[str]:
        """Quick extraction of vulnerability type from query"""
        query_lower = query.lower()
        
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            for pattern in patterns:
                if pattern in query_lower:
                    return vuln_type
        
        return None


# Convenience functions
def classify_query(query: str) -> Dict[str, Any]:
    """Quick query classification"""
    classifier = IntentClassifier()
    result = classifier.classify(query)
    
    return {
        "intent": result.primary_intent.value,
        "confidence": result.confidence,
        "entities": [
            {"type": e.entity_type.value, "value": e.value}
            for e in result.entities
        ],
        "handler": result.suggested_handler,
        "requires_scan_data": result.requires_scan_data
    }


def is_security_related(query: str) -> bool:
    """Check if query is security-related"""
    classifier = IntentClassifier()
    result = classifier.classify(query)
    return result.primary_intent != Intent.OFF_TOPIC
