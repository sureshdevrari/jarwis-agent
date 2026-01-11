"""
Jarwis AI Chatbot Handler
==========================

The main chatbot handler that brings together:
- Intent Classification (understanding what user wants)
- Knowledge Service (vulnerability info, remediations)
- Scan Analysis (summarizing findings)
- Attack Chain Detection (correlation analysis)

This replaces the LLM-based chatbot with pure algorithmic intelligence.

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import logging
import re

# Core AI imports
from core.intent_classifier import IntentClassifier, ClassificationResult, Intent, EntityType
from core.jarwis_ai_engine import JarwisAIEngine
from core.correlation_engine import CorrelationEngine

# Services
from services.knowledge_service import KnowledgeService, KnowledgeResponse

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    """A chat message"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChatContext:
    """Context for chat session"""
    user_id: Optional[str] = None
    scan_id: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    conversation_history: List[ChatMessage] = field(default_factory=list)
    current_topic: Optional[str] = None
    mentioned_vulns: List[str] = field(default_factory=list)


@dataclass
class ChatResponse:
    """Response from chatbot"""
    message: str
    response_type: str = "text"  # text, code, list, chart
    confidence: float = 1.0
    suggested_questions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    requires_llm_fallback: bool = False  # True if query couldn't be handled


class JarwisAIChatbot:
    """
    Jarwis AI Chatbot - No LLM Required
    
    Handles user queries using:
    1. Intent classification (pattern matching)
    2. Knowledge base lookups
    3. Scan data analysis
    4. Template-based responses
    """
    
    def __init__(self):
        """Initialize the chatbot"""
        self.intent_classifier = IntentClassifier()
        self.knowledge_service = KnowledgeService()
        self.ai_engine = JarwisAIEngine()
        self.correlation_engine = CorrelationEngine()
    
    def chat(
        self,
        query: str,
        context: Optional[ChatContext] = None
    ) -> ChatResponse:
        """
        Process a user query and return a response
        
        Args:
            query: User's question
            context: Optional chat context (scan data, history)
            
        Returns:
            ChatResponse with answer
        """
        context = context or ChatContext()
        
        # Classify intent
        classification = self.intent_classifier.classify(
            query,
            context={"scan_id": context.scan_id, "history": context.conversation_history[-3:]}
        )
        
        logger.info(f"Intent: {classification.primary_intent.value} "
                   f"(confidence: {classification.confidence})")
        
        # Check for clarification needed
        if classification.confidence < 0.4:
            clarification = self.intent_classifier.get_clarifying_question(classification)
            if clarification:
                return ChatResponse(
                    message=clarification,
                    confidence=classification.confidence,
                    suggested_questions=self._get_suggested_questions(classification)
                )
        
        # Route to handler
        handler_name = classification.suggested_handler
        handler = getattr(self, f"_handle_{handler_name}", self._handle_fallback)
        
        try:
            response = handler(query, classification, context)
            
            # Add conversation tracking
            if context:
                context.conversation_history.append(ChatMessage(role="user", content=query))
                context.conversation_history.append(ChatMessage(role="assistant", content=response.message))
            
            return response
            
        except Exception as e:
            logger.error(f"Handler error: {e}")
            return self._handle_fallback(query, classification, context)
    
    # ===== BRAND HANDLERS =====
    
    def _handle_brand_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle brand-related queries"""
        intent = classification.primary_intent
        
        if intent == Intent.BRAND_INFO:
            result = self.knowledge_service.get_brand_response("brand_info")
        elif intent == Intent.FOUNDER_INFO:
            result = self.knowledge_service.get_brand_response("founder_info")
        elif intent == Intent.CAPABILITIES:
            result = self.knowledge_service.get_brand_response("capabilities")
        else:
            result = self.knowledge_service.get_brand_response("brand_info")
        
        return ChatResponse(
            message=result.content,
            response_type=result.response_type,
            confidence=1.0,
            suggested_questions=[
                "What vulnerabilities can you detect?",
                "How do you analyze my scan results?",
                "What is your approach to security testing?"
            ]
        )
    
    # ===== KNOWLEDGE HANDLERS =====
    
    def _handle_knowledge_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle vulnerability definitions and security concepts"""
        intent = classification.primary_intent
        entities = classification.entities
        
        # Extract vulnerability type from entities
        vuln_entity = next(
            (e for e in entities if e.entity_type == EntityType.VULNERABILITY),
            None
        )
        
        # Extract OWASP category
        owasp_entity = next(
            (e for e in entities if e.entity_type == EntityType.OWASP_CATEGORY),
            None
        )
        
        if intent == Intent.VULN_DEFINITION:
            if vuln_entity:
                result = self.knowledge_service.get_vulnerability_definition(vuln_entity.value)
            else:
                # Try to extract from query directly
                vuln_type = self.intent_classifier.extract_vuln_type(query)
                if vuln_type:
                    result = self.knowledge_service.get_vulnerability_definition(vuln_type)
                else:
                    return ChatResponse(
                        message="Which vulnerability would you like to learn about?\n\n"
                                "I can explain: SQL Injection, XSS, CSRF, SSRF, IDOR, XXE, "
                                "SSTI, Path Traversal, Command Injection, and more.",
                        confidence=0.6,
                        suggested_questions=[
                            "What is SQL injection?",
                            "Explain XSS vulnerabilities",
                            "What is SSRF?"
                        ]
                    )
        
        elif intent == Intent.OWASP_INFO:
            if owasp_entity:
                result = self.knowledge_service.get_owasp_info(owasp_entity.value)
            else:
                # Try to extract from query
                owasp_match = re.search(r"(a0?[1-9]|a10)", query.lower())
                if owasp_match:
                    result = self.knowledge_service.get_owasp_info(owasp_match.group(1))
                else:
                    return ChatResponse(
                        message="Which OWASP Top 10 category would you like to know about?\n\n"
                                "- **A01** - Broken Access Control\n"
                                "- **A02** - Cryptographic Failures\n"
                                "- **A03** - Injection\n"
                                "- **A04** - Insecure Design\n"
                                "- **A05** - Security Misconfiguration\n"
                                "- **A06** - Vulnerable Components\n"
                                "- **A07** - Auth Failures\n"
                                "- **A08** - Integrity Failures\n"
                                "- **A09** - Logging Failures\n"
                                "- **A10** - SSRF",
                        confidence=0.8,
                        suggested_questions=[
                            "What is A01 Broken Access Control?",
                            "Tell me about A03 Injection",
                            "Explain A07 Authentication Failures"
                        ]
                    )
        
        elif intent == Intent.SECURITY_CONCEPT:
            concept = self._extract_concept(query)
            result = self.knowledge_service.get_security_concept(concept)
        
        elif intent == Intent.BEST_PRACTICE:
            # Extract topic
            if vuln_entity:
                result = self.knowledge_service.get_remediation(vuln_entity.value)
            else:
                return ChatResponse(
                    message="What security best practices are you looking for?\n\n"
                            "I can help with: authentication, input validation, "
                            "encryption, access control, and more.",
                    confidence=0.6
                )
        
        else:
            result = KnowledgeResponse(content="Let me help you with that.", confidence=0.5)
        
        return ChatResponse(
            message=result.content,
            response_type=result.response_type,
            confidence=result.confidence,
            suggested_questions=self._get_related_questions(result.related_topics)
        )
    
    # ===== REMEDIATION HANDLERS =====
    
    def _handle_remediation_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle fix guidance and code examples"""
        intent = classification.primary_intent
        entities = classification.entities
        
        # Get vulnerability type
        vuln_entity = next(
            (e for e in entities if e.entity_type == EntityType.VULNERABILITY),
            None
        )
        
        # Get technology preference
        tech_entity = next(
            (e for e in entities if e.entity_type == EntityType.TECHNOLOGY),
            None
        )
        
        vuln_type = None
        
        if vuln_entity:
            vuln_type = vuln_entity.value
        elif context.current_topic:
            vuln_type = context.current_topic
        elif context.findings:
            # Use most recent/critical finding
            vuln_type = self._extract_vuln_from_findings(context.findings)
        
        if not vuln_type:
            vuln_type = self.intent_classifier.extract_vuln_type(query)
        
        if not vuln_type:
            return ChatResponse(
                message="Which vulnerability would you like remediation guidance for?\n\n"
                        "You can ask about specific vulnerabilities like:\n"
                        "- 'How do I fix SQL injection?'\n"
                        "- 'Show me code to prevent XSS'\n"
                        "- 'Best practices for CSRF protection'",
                confidence=0.6,
                suggested_questions=[
                    "How do I fix SQL injection?",
                    "Show me XSS prevention code",
                    "How to prevent CSRF attacks?"
                ]
            )
        
        language = tech_entity.value if tech_entity else None
        result = self.knowledge_service.get_remediation(vuln_type, language)
        
        return ChatResponse(
            message=result.content,
            response_type="code" if intent == Intent.CODE_EXAMPLE else "text",
            confidence=result.confidence,
            suggested_questions=self._get_related_questions(result.related_topics)
        )
    
    # ===== SCAN ANALYSIS HANDLERS =====
    
    def _handle_scan_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle scan summary and finding list queries"""
        intent = classification.primary_intent
        
        if not context.findings and not context.scan_id:
            return ChatResponse(
                message="I don't have access to any scan data in this conversation.\n\n"
                        "Please:\n"
                        "1. Run a scan first, or\n"
                        "2. Open a specific scan from your dashboard\n\n"
                        "Then I can help analyze your results!",
                confidence=0.9,
                suggested_questions=[
                    "How do I start a new scan?",
                    "What types of scans are available?",
                    "What is Jarwis?"
                ]
            )
        
        findings = context.findings
        
        if intent == Intent.SCAN_SUMMARY:
            return self._generate_scan_summary(findings)
        
        elif intent == Intent.FINDING_LIST:
            return self._generate_finding_list(findings, classification.entities)
        
        elif intent == Intent.SEVERITY_BREAKDOWN:
            return self._generate_severity_breakdown(findings)
        
        elif intent == Intent.MOST_CRITICAL:
            return self._get_most_critical(findings)
        
        return self._generate_scan_summary(findings)
    
    def _generate_scan_summary(self, findings: List[Dict]) -> ChatResponse:
        """Generate scan summary"""
        if not findings:
            return ChatResponse(
                message="No vulnerabilities were found in this scan! 🎉\n\n"
                        "This could mean:\n"
                        "- Your application has good security practices\n"
                        "- The scope was limited\n"
                        "- Some vulnerabilities may require authenticated testing",
                confidence=1.0
            )
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        total = len(findings)
        
        # Get top categories
        category_counts: Dict[str, int] = {}
        for finding in findings:
            cat = finding.get("category", "Unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        
        # Build summary
        summary = f"## Scan Summary\n\n"
        summary += f"**Total Findings:** {total}\n\n"
        
        summary += "### Severity Distribution\n"
        if severity_counts["critical"] > 0:
            summary += f"🔴 **Critical:** {severity_counts['critical']}\n"
        if severity_counts["high"] > 0:
            summary += f"🟠 **High:** {severity_counts['high']}\n"
        if severity_counts["medium"] > 0:
            summary += f"🟡 **Medium:** {severity_counts['medium']}\n"
        if severity_counts["low"] > 0:
            summary += f"🔵 **Low:** {severity_counts['low']}\n"
        if severity_counts["info"] > 0:
            summary += f"⚪ **Info:** {severity_counts['info']}\n"
        
        summary += "\n### Top Vulnerability Categories\n"
        for cat, count in top_categories:
            summary += f"- {cat}: {count} finding(s)\n"
        
        # Add recommendation
        if severity_counts["critical"] > 0:
            summary += "\n⚠️ **Immediate action required!** "
            summary += "You have critical vulnerabilities that should be fixed ASAP."
        elif severity_counts["high"] > 0:
            summary += "\n⚠️ **High-priority fixes needed.** "
            summary += "Address high-severity issues before deployment."
        
        return ChatResponse(
            message=summary,
            response_type="text",
            confidence=1.0,
            metadata={"severity_counts": severity_counts, "total": total},
            suggested_questions=[
                "What is the most critical issue?",
                "How do I fix the SQL injection?",
                "Are there any attack chains?"
            ]
        )
    
    def _generate_finding_list(
        self,
        findings: List[Dict],
        entities: List
    ) -> ChatResponse:
        """Generate finding list"""
        # Filter by severity if specified
        severity_filter = next(
            (e.value for e in entities if e.entity_type == EntityType.SEVERITY),
            None
        )
        
        if severity_filter:
            findings = [f for f in findings if f.get("severity", "").lower() == severity_filter]
        
        if not findings:
            return ChatResponse(
                message=f"No {severity_filter or ''} findings to display.",
                confidence=1.0
            )
        
        # Limit to 10 findings
        display_findings = findings[:10]
        
        result = "## Vulnerability Findings\n\n"
        
        for i, finding in enumerate(display_findings, 1):
            sev_icon = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(finding.get("severity", "").lower(), "⚪")
            
            result += f"{i}. {sev_icon} **{finding.get('title', 'Unknown')}**\n"
            result += f"   - Severity: {finding.get('severity', 'Unknown')}\n"
            result += f"   - URL: `{finding.get('url', 'N/A')}`\n\n"
        
        if len(findings) > 10:
            result += f"\n*...and {len(findings) - 10} more findings.*"
        
        return ChatResponse(
            message=result,
            response_type="list",
            confidence=1.0
        )
    
    def _generate_severity_breakdown(self, findings: List[Dict]) -> ChatResponse:
        """Generate severity breakdown"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            sev = finding.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        result = "## Severity Breakdown\n\n"
        result += "| Severity | Count | Bar |\n"
        result += "|----------|-------|-----|\n"
        
        max_count = max(severity_counts.values()) if severity_counts else 1
        
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[sev]
            bar_length = int((count / max_count) * 20) if max_count > 0 else 0
            bar = "█" * bar_length
            result += f"| {sev.title()} | {count} | {bar} |\n"
        
        return ChatResponse(
            message=result,
            response_type="chart",
            confidence=1.0,
            metadata={"severity_counts": severity_counts}
        )
    
    def _get_most_critical(self, findings: List[Dict]) -> ChatResponse:
        """Get most critical finding"""
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for sev in severity_order:
            critical_findings = [
                f for f in findings
                if f.get("severity", "").lower() == sev
            ]
            if critical_findings:
                finding = critical_findings[0]
                
                result = f"## Most Critical Issue\n\n"
                result += f"**{finding.get('title', 'Unknown')}**\n\n"
                result += f"- **Severity:** {finding.get('severity', 'Unknown')}\n"
                result += f"- **Category:** {finding.get('category', 'Unknown')}\n"
                result += f"- **URL:** `{finding.get('url', 'N/A')}`\n\n"
                
                if finding.get("description"):
                    result += f"### Description\n{finding.get('description')}\n\n"
                
                result += "Would you like remediation guidance for this issue?"
                
                return ChatResponse(
                    message=result,
                    response_type="text",
                    confidence=1.0,
                    suggested_questions=[
                        f"How do I fix this {finding.get('title', 'vulnerability')}?",
                        "Show me the attack chain",
                        "What's the impact of this vulnerability?"
                    ]
                )
        
        return ChatResponse(
            message="No critical findings found in this scan.",
            confidence=1.0
        )
    
    # ===== FINDING DETAIL HANDLERS =====
    
    def _handle_finding_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle specific finding queries"""
        intent = classification.primary_intent
        
        if not context.findings:
            return ChatResponse(
                message="I need access to your scan findings to provide details.\n\n"
                        "Please run a scan or select a scan from your dashboard.",
                confidence=0.9
            )
        
        # Try to identify which finding user is asking about
        finding = self._identify_finding(query, context.findings)
        
        if not finding:
            return ChatResponse(
                message="Which finding would you like to know more about?\n\n"
                        "You can ask about a specific vulnerability by name or number.",
                confidence=0.6
            )
        
        if intent == Intent.FINDING_DETAILS:
            return self._explain_finding(finding)
        elif intent == Intent.FINDING_IMPACT:
            return self._explain_impact(finding)
        elif intent == Intent.FINDING_PRIORITY:
            return self._explain_priority(finding, context.findings)
        
        return self._explain_finding(finding)
    
    def _identify_finding(
        self,
        query: str,
        findings: List[Dict]
    ) -> Optional[Dict]:
        """Try to identify which finding user is asking about"""
        query_lower = query.lower()
        
        # Check for finding number
        num_match = re.search(r"finding\s*#?(\d+)|#(\d+)", query_lower)
        if num_match:
            idx = int(num_match.group(1) or num_match.group(2)) - 1
            if 0 <= idx < len(findings):
                return findings[idx]
        
        # Check for vulnerability type match
        vuln_type = self.intent_classifier.extract_vuln_type(query)
        if vuln_type:
            for finding in findings:
                if vuln_type.replace("_", " ") in finding.get("title", "").lower():
                    return finding
        
        # Check for URL match
        for finding in findings:
            if finding.get("url", "") and finding["url"] in query:
                return finding
        
        return None
    
    def _explain_finding(self, finding: Dict) -> ChatResponse:
        """Explain a specific finding"""
        result = f"## {finding.get('title', 'Vulnerability')}\n\n"
        result += f"- **Severity:** {finding.get('severity', 'Unknown')}\n"
        result += f"- **Category:** {finding.get('category', 'Unknown')}\n"
        result += f"- **URL:** `{finding.get('url', 'N/A')}`\n"
        
        if finding.get("parameter"):
            result += f"- **Parameter:** `{finding.get('parameter')}`\n"
        
        if finding.get("description"):
            result += f"\n### Description\n{finding.get('description')}\n"
        
        if finding.get("evidence"):
            result += f"\n### Evidence\n```\n{finding.get('evidence')[:500]}\n```\n"
        
        if finding.get("poc"):
            result += f"\n### Proof of Concept\n```\n{finding.get('poc')}\n```\n"
        
        return ChatResponse(
            message=result,
            response_type="text",
            confidence=1.0,
            suggested_questions=[
                f"How do I fix this?",
                "What's the impact?",
                "Is this related to other findings?"
            ]
        )
    
    def _explain_impact(self, finding: Dict) -> ChatResponse:
        """Explain the impact of a finding"""
        # Get vulnerability type info
        vuln_type = self._extract_vuln_type_from_finding(finding)
        vuln_info = self.knowledge_service.vuln_definitions.get(vuln_type, {})
        
        result = f"## Impact of {finding.get('title', 'This Vulnerability')}\n\n"
        
        if vuln_info.get("impact"):
            result += "### Potential Impact\n"
            for impact in vuln_info["impact"]:
                result += f"- {impact}\n"
        else:
            # Generic impact based on severity
            sev = finding.get("severity", "").lower()
            if sev == "critical":
                result += "This is a **CRITICAL** vulnerability that could lead to:\n"
                result += "- Complete system compromise\n"
                result += "- Data breach\n"
                result += "- Service disruption\n"
            elif sev == "high":
                result += "This is a **HIGH** severity issue that could:\n"
                result += "- Allow unauthorized data access\n"
                result += "- Enable privilege escalation\n"
            elif sev == "medium":
                result += "This is a **MEDIUM** severity issue that may:\n"
                result += "- Allow limited unauthorized access\n"
                result += "- Lead to information disclosure\n"
            else:
                result += "This is a lower severity issue but should still be addressed.\n"
        
        return ChatResponse(
            message=result,
            response_type="text",
            confidence=0.9
        )
    
    def _explain_priority(
        self,
        finding: Dict,
        all_findings: List[Dict]
    ) -> ChatResponse:
        """Explain fix priority for a finding"""
        severity_order = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        
        sev = finding.get("severity", "info").lower()
        position = severity_order.get(sev, 5)
        
        result = f"## Priority Assessment: {finding.get('title', 'This Finding')}\n\n"
        
        if position <= 2:
            result += f"**Priority: HIGH** 🔴\n\n"
            result += "This should be fixed **immediately** because:\n"
            result += f"- Severity is {sev.upper()}\n"
            result += "- Could lead to significant security impact\n"
        elif position == 3:
            result += f"**Priority: MEDIUM** 🟡\n\n"
            result += "This should be addressed **soon** but after critical/high issues:\n"
        else:
            result += f"**Priority: LOW** 🔵\n\n"
            result += "Address this in your regular security maintenance cycle.\n"
        
        # Show where it ranks
        higher_priority = [f for f in all_findings if severity_order.get(f.get("severity", "").lower(), 5) < position]
        
        if higher_priority:
            result += f"\nThere are {len(higher_priority)} findings with higher priority.\n"
        else:
            result += "\nThis is among your highest priority findings!\n"
        
        return ChatResponse(
            message=result,
            response_type="text",
            confidence=0.9
        )
    
    # ===== CORRELATION HANDLERS =====
    
    def _handle_correlation_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle attack chain queries"""
        if not context.findings:
            return ChatResponse(
                message="I need access to scan findings to detect attack chains.\n\n"
                        "Please run a scan or select one from your dashboard.",
                confidence=0.9
            )
        
        intent = classification.primary_intent
        
        if intent == Intent.ATTACK_CHAIN:
            return self._detect_attack_chains(context.findings)
        elif intent == Intent.EXPLOITATION:
            return self._explain_exploitation(context.findings)
        
        return self._detect_attack_chains(context.findings)
    
    def _detect_attack_chains(self, findings: List[Dict]) -> ChatResponse:
        """Detect attack chains from findings"""
        # Use correlation engine
        chains = self.correlation_engine.detect_chains(findings)
        
        if not chains:
            return ChatResponse(
                message="## Attack Chain Analysis\n\n"
                        "No significant attack chains were detected.\n\n"
                        "This means the vulnerabilities found don't appear to combine "
                        "in a way that amplifies their impact. However, each vulnerability "
                        "should still be addressed individually.",
                confidence=0.9
            )
        
        result = "## Attack Chain Analysis\n\n"
        result += f"**{len(chains)} attack chain(s) detected!**\n\n"
        
        for i, chain in enumerate(chains[:3], 1):
            result += f"### Chain {i}: {chain.chain_type.value.replace('_', ' ').title()}\n"
            result += f"- **Combined Severity:** {chain.combined_severity}\n"
            result += f"- **Confidence:** {chain.confidence:.0%}\n"
            result += f"- **Involved Vulnerabilities:** {len(chain.vulnerabilities)}\n\n"
            
            for vuln in chain.vulnerabilities[:3]:
                result += f"  → {vuln.title}\n"
            
            result += "\n"
        
        result += "\n⚠️ **Attack chains are especially dangerous** because they show how "
        result += "an attacker could combine multiple vulnerabilities for greater impact."
        
        return ChatResponse(
            message=result,
            response_type="chart",
            confidence=0.95,
            metadata={"chain_count": len(chains)}
        )
    
    def _explain_exploitation(self, findings: List[Dict]) -> ChatResponse:
        """Explain how vulnerabilities could be exploited"""
        if not findings:
            return ChatResponse(
                message="No findings available to analyze.",
                confidence=0.5
            )
        
        # Get most critical finding
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for sev in severity_order:
            matching = [f for f in findings if f.get("severity", "").lower() == sev]
            if matching:
                finding = matching[0]
                break
        else:
            finding = findings[0]
        
        vuln_type = self._extract_vuln_type_from_finding(finding)
        vuln_info = self.knowledge_service.vuln_definitions.get(vuln_type, {})
        
        result = f"## Exploitation Scenario: {finding.get('title', 'Vulnerability')}\n\n"
        result += f"**Target:** `{finding.get('url', 'Unknown')}`\n\n"
        
        result += "### Attack Steps\n"
        
        # Generate generic exploitation steps based on vulnerability type
        if "sql" in vuln_type:
            result += "1. Attacker identifies injectable parameter\n"
            result += "2. Tests for SQL syntax errors\n"
            result += "3. Uses UNION-based or blind techniques\n"
            result += "4. Extracts sensitive data or escalates privileges\n"
        elif "xss" in vuln_type:
            result += "1. Attacker injects malicious JavaScript\n"
            result += "2. Victim visits the affected page\n"
            result += "3. Script executes in victim's browser\n"
            result += "4. Session cookies or credentials are stolen\n"
        else:
            result += "1. Attacker identifies the vulnerability\n"
            result += "2. Crafts appropriate payload\n"
            result += "3. Exploits the weakness\n"
            result += "4. Achieves unauthorized access or impact\n"
        
        if vuln_info.get("impact"):
            result += "\n### Potential Outcomes\n"
            for impact in vuln_info["impact"][:3]:
                result += f"- {impact}\n"
        
        return ChatResponse(
            message=result,
            response_type="text",
            confidence=0.85
        )
    
    # ===== SPECIAL HANDLERS =====
    
    def _handle_off_topic_handler(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle off-topic queries"""
        result = self.knowledge_service.get_off_topic_response()
        
        return ChatResponse(
            message=result.content,
            response_type="text",
            confidence=1.0,
            suggested_questions=[
                "What vulnerabilities can you explain?",
                "How do I analyze my scan results?",
                "What is Jarwis?"
            ]
        )
    
    def _handle_fallback(
        self,
        query: str,
        classification: ClassificationResult,
        context: ChatContext
    ) -> ChatResponse:
        """Handle unclassified queries"""
        # Check if we can still provide value
        vuln_type = self.intent_classifier.extract_vuln_type(query)
        
        if vuln_type:
            result = self.knowledge_service.get_vulnerability_definition(vuln_type)
            return ChatResponse(
                message=result.content,
                response_type="text",
                confidence=result.confidence
            )
        
        # Check for security keywords
        security_keywords = ["security", "secure", "protect", "hack", "attack", "vulnerability"]
        if any(kw in query.lower() for kw in security_keywords):
            return ChatResponse(
                message="I'd be happy to help with your security question!\n\n"
                        "Could you be more specific? For example:\n"
                        "- Ask about a specific vulnerability type\n"
                        "- Request remediation guidance\n"
                        "- Ask about your scan results",
                confidence=0.6,
                suggested_questions=[
                    "What is SQL injection?",
                    "How do I secure my application?",
                    "Explain my scan results"
                ]
            )
        
        # True fallback - might need LLM
        return ChatResponse(
            message="I'm not sure I understood your question.\n\n"
                    "I can help with:\n"
                    "🔹 Vulnerability explanations\n"
                    "🔹 Remediation guidance\n"
                    "🔹 Scan result analysis\n"
                    "🔹 Security best practices\n\n"
                    "Try rephrasing or ask one of the suggested questions below.",
            confidence=0.3,
            requires_llm_fallback=True,
            suggested_questions=[
                "What is Jarwis?",
                "Explain SQL injection",
                "Summarize my scan"
            ]
        )
    
    # ===== HELPER METHODS =====
    
    def _extract_concept(self, query: str) -> str:
        """Extract security concept from query"""
        concepts = ["defense in depth", "least privilege", "zero trust", 
                   "secure by design", "shift left"]
        
        query_lower = query.lower()
        for concept in concepts:
            if concept in query_lower:
                return concept
        
        return "security"
    
    def _extract_vuln_type_from_finding(self, finding: Dict) -> str:
        """Extract vulnerability type from finding data"""
        title = finding.get("title", "").lower()
        
        type_mapping = {
            "sql injection": "sql_injection",
            "xss": "xss",
            "cross-site scripting": "xss",
            "csrf": "csrf",
            "ssrf": "ssrf",
            "idor": "idor",
            "xxe": "xxe",
            "ssti": "ssti",
            "path traversal": "path_traversal",
            "command injection": "command_injection",
            "authentication": "auth_bypass",
            "jwt": "jwt",
            "security header": "security_headers"
        }
        
        for key, value in type_mapping.items():
            if key in title:
                return value
        
        return "vulnerability"
    
    def _extract_vuln_from_findings(self, findings: List[Dict]) -> Optional[str]:
        """Extract vuln type from most critical finding"""
        if not findings:
            return None
        
        severity_order = ["critical", "high", "medium", "low", "info"]
        
        for sev in severity_order:
            for finding in findings:
                if finding.get("severity", "").lower() == sev:
                    return self._extract_vuln_type_from_finding(finding)
        
        return None
    
    def _get_suggested_questions(
        self,
        classification: ClassificationResult
    ) -> List[str]:
        """Get suggested follow-up questions"""
        intent = classification.primary_intent
        
        suggestions = {
            Intent.UNKNOWN: [
                "What is Jarwis?",
                "Explain SQL injection",
                "Summarize my scan results"
            ],
            Intent.VULN_DEFINITION: [
                "How do I fix this vulnerability?",
                "What's the impact?",
                "Show me a code example"
            ],
            Intent.FIX_GUIDANCE: [
                "Show me more code examples",
                "What are the best practices?",
                "Are there related vulnerabilities?"
            ],
            Intent.SCAN_SUMMARY: [
                "What's the most critical issue?",
                "Are there attack chains?",
                "How do I fix the top vulnerability?"
            ]
        }
        
        return suggestions.get(intent, [
            "What is Jarwis?",
            "How can you help me?",
            "What vulnerabilities can you explain?"
        ])
    
    def _get_related_questions(self, related_topics: List[str]) -> List[str]:
        """Generate questions from related topics"""
        questions = []
        
        for topic in related_topics[:3]:
            topic_title = topic.replace("_", " ").title()
            questions.append(f"What is {topic_title}?")
        
        if not questions:
            questions = [
                "What other vulnerabilities should I know about?",
                "How do I prevent similar issues?",
                "What are security best practices?"
            ]
        
        return questions


# ===== CONVENIENCE FUNCTIONS =====

def chat(query: str, scan_findings: List[Dict] = None) -> str:
    """Quick chat function"""
    chatbot = JarwisAIChatbot()
    context = ChatContext(findings=scan_findings or [])
    response = chatbot.chat(query, context)
    return response.message


def get_chatbot() -> JarwisAIChatbot:
    """Get chatbot instance"""
    return JarwisAIChatbot()
