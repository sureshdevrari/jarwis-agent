"""
JARWIS AGI PEN TEST - AI-Powered Vulnerability Verifier
Uses AI to verify and analyze detected vulnerabilities
Reduces false positives through intelligent contextual analysis
"""

import json
import logging
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    """Result of AI vulnerability verification"""
    is_verified: bool
    confidence: float  # 0.0 to 1.0
    reasoning: str
    severity_adjustment: str  # "upgrade", "downgrade", "unchanged"
    false_positive_indicators: List[str]
    true_positive_indicators: List[str]
    recommended_action: str


@dataclass
class RequestAnalysis:
    """AI analysis of request/response for vulnerabilities"""
    has_vulnerability: bool
    vulnerability_type: str
    confidence: float
    evidence: List[str]
    modified_headers: Dict[str, str]
    suggested_payloads: List[str]
    reasoning: str


class AIVerifier:
    """AI-powered vulnerability verification and request analysis"""
    
    VERIFICATION_PROMPT = """You are Jarwis, an expert security analyst. Analyze this potential vulnerability finding and verify if it's a TRUE positive or FALSE positive.

## Finding Details:
- Category: {category}
- Severity: {severity}
- Title: {title}
- URL: {url}
- Parameter: {parameter}
- Evidence: {evidence}
- Payload Used: {poc}

## Request/Response:
{request_data}

{response_data}

## Your Task:
Analyze the evidence and determine if this is a real vulnerability. Consider:
1. Is the payload actually reflected/executed or just in comments/logs?
2. Are there WAF blocks or encoding that prevents exploitation?
3. Is the context exploitable (script tags in HTML vs JSON response)?
4. Could this be a honeypot or intentional test endpoint?

Respond in JSON format ONLY:
{{
    "is_verified": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation",
    "severity_adjustment": "upgrade/downgrade/unchanged",
    "false_positive_indicators": ["list", "of", "indicators"],
    "true_positive_indicators": ["list", "of", "indicators"],
    "recommended_action": "what to do next"
}}"""

    REQUEST_ANALYSIS_PROMPT = """You are Jarwis, an expert penetration tester. Analyze this HTTP request/response and identify potential vulnerabilities.

## Request Details:
- Method: {method}
- URL: {url}
- Headers: {headers}
- Body: {body}

## Response Details:
- Status: {status}
- Headers: {response_headers}
- Body (first 2000 chars): {response_body}

## Your Task:
1. Identify any security vulnerabilities or misconfigurations
2. Suggest modified headers that might reveal vulnerabilities
3. Recommend payloads to test based on the response

Consider OWASP Top 10:
- A01: Broken Access Control (missing auth headers, IDOR patterns)
- A02: Cryptographic Failures (sensitive data exposure, weak headers)
- A03: Injection (reflection points, error messages)
- A05: Security Misconfiguration (verbose errors, exposed headers)
- A07: XSS (reflection without encoding)

Respond in JSON format ONLY:
{{
    "has_vulnerability": true/false,
    "vulnerability_type": "sqli/xss/idor/misconfig/none",
    "confidence": 0.0-1.0,
    "evidence": ["list", "of", "evidence"],
    "modified_headers": {{"Header-Name": "value to test"}},
    "suggested_payloads": ["payload1", "payload2"],
    "reasoning": "explanation"
}}"""

    def __init__(self, config: dict):
        self.config = config
        self.ai_config = config.get('ai', {})
        self.provider = self.ai_config.get('provider', 'gemini')
        self.model = self.ai_config.get('model', 'gemini-1.5-flash')
        self.base_url = self.ai_config.get('base_url', '')
        self._client = None
        self._available = False
        self._init_client()
    
    def _init_client(self):
        """Initialize the AI client"""
        if self.provider == "ollama":
            try:
                import ollama
                self._client = ollama.Client(host=self.base_url)
                # Test connection
                self._client.list()
                self._available = True
                logger.info(f"AI Verifier connected to Ollama at {self.base_url}")
            except Exception as e:
                logger.warning(f"Ollama not available for verification: {e}")
                self._available = False
    
    @property
    def is_available(self) -> bool:
        return self._available
    
    def _query_llm(self, prompt: str) -> Optional[str]:
        """Query the LLM and return response"""
        if not self._available or not self._client:
            return None
        
        try:
            response = self._client.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.3}
            )
            
            # Handle both old and new ollama library formats
            if hasattr(response, 'message'):
                return response.message.content
            elif isinstance(response, dict):
                return response.get('message', {}).get('content', '')
            return None
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return None
    
    def _parse_json_response(self, response: str) -> Optional[dict]:
        """Parse JSON from LLM response"""
        if not response:
            return None
        
        try:
            # Try direct parse first
            return json.loads(response)
        except:
            pass
        
        # Try to extract JSON from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', response)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except:
                pass
        
        # Try to find JSON object in response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except:
                pass
        
        return None
    
    async def verify_finding(self, finding: dict) -> VerificationResult:
        """Verify a vulnerability finding using AI"""
        if not self._available:
            # Return unverified result if AI not available
            return VerificationResult(
                is_verified=True,  # Assume true if can't verify
                confidence=0.5,
                reasoning="AI verification unavailable - manual review recommended",
                severity_adjustment="unchanged",
                false_positive_indicators=[],
                true_positive_indicators=[],
                recommended_action="Manually verify this finding"
            )
        
        prompt = self.VERIFICATION_PROMPT.format(
            category=finding.get('category', 'Unknown'),
            severity=finding.get('severity', 'medium'),
            title=finding.get('title', 'Unknown'),
            url=finding.get('url', ''),
            parameter=finding.get('parameter', ''),
            evidence=finding.get('evidence', ''),
            poc=finding.get('poc', ''),
            request_data=finding.get('request_data', 'Not available'),
            response_data=finding.get('response_data', 'Not available')[:2000]
        )
        
        response = self._query_llm(prompt)
        parsed = self._parse_json_response(response)
        
        if parsed:
            return VerificationResult(
                is_verified=parsed.get('is_verified', True),
                confidence=float(parsed.get('confidence', 0.5)),
                reasoning=parsed.get('reasoning', ''),
                severity_adjustment=parsed.get('severity_adjustment', 'unchanged'),
                false_positive_indicators=parsed.get('false_positive_indicators', []),
                true_positive_indicators=parsed.get('true_positive_indicators', []),
                recommended_action=parsed.get('recommended_action', '')
            )
        
        return VerificationResult(
            is_verified=True,
            confidence=0.5,
            reasoning="AI response parsing failed - manual review recommended",
            severity_adjustment="unchanged",
            false_positive_indicators=[],
            true_positive_indicators=[],
            recommended_action="Manually verify this finding"
        )
    
    async def analyze_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: str
    ) -> RequestAnalysis:
        """Analyze a request/response pair for vulnerabilities"""
        if not self._available:
            return RequestAnalysis(
                has_vulnerability=False,
                vulnerability_type="none",
                confidence=0.0,
                evidence=[],
                modified_headers={},
                suggested_payloads=[],
                reasoning="AI analysis unavailable"
            )
        
        prompt = self.REQUEST_ANALYSIS_PROMPT.format(
            method=method,
            url=url,
            headers=json.dumps(headers, indent=2),
            body=body[:1000] if body else "Empty",
            status=response_status,
            response_headers=json.dumps(response_headers, indent=2),
            response_body=response_body[:2000] if response_body else "Empty"
        )
        
        response = self._query_llm(prompt)
        parsed = self._parse_json_response(response)
        
        if parsed:
            return RequestAnalysis(
                has_vulnerability=parsed.get('has_vulnerability', False),
                vulnerability_type=parsed.get('vulnerability_type', 'none'),
                confidence=float(parsed.get('confidence', 0.0)),
                evidence=parsed.get('evidence', []),
                modified_headers=parsed.get('modified_headers', {}),
                suggested_payloads=parsed.get('suggested_payloads', []),
                reasoning=parsed.get('reasoning', '')
            )
        
        return RequestAnalysis(
            has_vulnerability=False,
            vulnerability_type="none",
            confidence=0.0,
            evidence=[],
            modified_headers={},
            suggested_payloads=[],
            reasoning="AI response parsing failed"
        )
    
    async def suggest_header_modifications(
        self,
        url: str,
        current_headers: Dict[str, str],
        endpoint_type: str = "unknown"
    ) -> Dict[str, str]:
        """Suggest header modifications to test for vulnerabilities"""
        
        # Common security testing headers
        test_headers = {}
        
        # Test for host header injection
        test_headers['X-Forwarded-Host'] = 'evil.com'
        test_headers['X-Original-URL'] = '/admin'
        test_headers['X-Rewrite-URL'] = '/admin'
        
        # Test for access control bypass
        test_headers['X-Forwarded-For'] = '127.0.0.1'
        test_headers['X-Remote-IP'] = '127.0.0.1'
        test_headers['X-Client-IP'] = '127.0.0.1'
        
        # Test for method override
        test_headers['X-HTTP-Method-Override'] = 'PUT'
        
        if self._available:
            # Get AI suggestions for additional headers
            prompt = f"""Suggest HTTP headers to test for vulnerabilities on this endpoint:
URL: {url}
Current Headers: {json.dumps(current_headers)}
Endpoint Type: {endpoint_type}

Respond with JSON only: {{"headers": {{"Header-Name": "test-value"}}}}"""
            
            response = self._query_llm(prompt)
            parsed = self._parse_json_response(response)
            if parsed and 'headers' in parsed:
                test_headers.update(parsed['headers'])
        
        return test_headers


class AIRequestWatcher:
    """Watches and analyzes all HTTP requests during crawling"""
    
    def __init__(self, config: dict):
        self.verifier = AIVerifier(config)
        self.analyzed_requests: List[dict] = []
        self.potential_vulns: List[dict] = []
        self._analysis_enabled = config.get('ai', {}).get('request_analysis', True)
    
    async def watch_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str = ""
    ) -> Tuple[Dict[str, str], List[str]]:
        """
        Watch a request and return modified headers + suggested payloads
        
        Returns:
            Tuple of (modified_headers, suggested_payloads)
        """
        if not self._analysis_enabled or not self.verifier.is_available:
            return headers, []
        
        # Get AI-suggested header modifications
        modified = await self.verifier.suggest_header_modifications(url, headers)
        
        return {**headers, **modified}, []
    
    async def analyze_response(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: str
    ) -> Optional[RequestAnalysis]:
        """Analyze a response for vulnerabilities"""
        if not self._analysis_enabled or not self.verifier.is_available:
            return None
        
        analysis = await self.verifier.analyze_request(
            method, url, headers, body,
            response_status, response_headers, response_body
        )
        
        # Store for later reference
        self.analyzed_requests.append({
            'url': url,
            'method': method,
            'analysis': analysis
        })
        
        if analysis.has_vulnerability:
            self.potential_vulns.append({
                'url': url,
                'method': method,
                'type': analysis.vulnerability_type,
                'confidence': analysis.confidence,
                'evidence': analysis.evidence,
                'reasoning': analysis.reasoning
            })
        
        return analysis
    
    def get_findings(self) -> List[dict]:
        """Get all potential vulnerabilities found during watching"""
        return self.potential_vulns
