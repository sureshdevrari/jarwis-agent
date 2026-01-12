"""
Jarwis AGI - Mobile Security LLM Analyzer
Uses Jarwis LLM for intelligent mobile security analysis

Features:
- Code pattern analysis for vulnerabilities
- Attack vector recommendation
- Finding prioritization based on exploitability
- Natural language vulnerability descriptions
- Remediation suggestions
"""

import json
import logging
import asyncio
import aiohttp
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
from shared.ai_config import get_ai_config

logger = logging.getLogger(__name__)


@dataclass
class LLMAnalysisResult:
    """Result from LLM analysis"""
    finding_id: str
    original_severity: str
    adjusted_severity: str
    exploitability_score: float  # 0-1
    impact_score: float  # 0-1
    confidence: float  # 0-1
    
    # LLM-generated content
    attack_scenario: str = ""
    step_by_step_exploit: List[str] = field(default_factory=list)
    business_impact: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    code_fix_example: str = ""
    
    # Related findings
    related_findings: List[str] = field(default_factory=list)
    attack_chain: List[str] = field(default_factory=list)


@dataclass
class MobileSecurityReport:
    """Comprehensive mobile security report with LLM analysis"""
    app_name: str
    platform: str
    scan_id: str
    generated_at: str
    
    # Summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # LLM insights
    executive_summary: str = ""
    top_risks: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    
    # Detailed findings with LLM analysis
    findings: List[Dict] = field(default_factory=list)


class MobileLLMAnalyzer:
    """
    LLM-powered mobile security analyzer
    Uses Jarwis model for intelligent analysis
    """
    
    SYSTEM_PROMPT = """You are Jarwis, an expert mobile application security analyst AI.
Your role is to analyze mobile security findings and provide:
1. Accurate severity assessment based on exploitability and impact
2. Real-world attack scenarios showing how vulnerabilities can be exploited
3. Step-by-step exploitation paths for penetration testers
4. Clear business impact explanations for executives
5. Practical remediation steps with code examples

Focus on OWASP Mobile Top 10:
M1: Improper Platform Usage
M2: Insecure Data Storage
M3: Insecure Communication
M4: Insecure Authentication
M5: Insufficient Cryptography
M6: Insecure Authorization
M7: Client Code Quality
M8: Code Tampering
M9: Reverse Engineering
M10: Extraneous Functionality

Always respond in valid JSON format."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        # Use centralized AI config for defaults
        central_config = get_ai_config()
        self.provider = config.get('ai', {}).get('provider', central_config.provider)
        self.model = config.get('ai', {}).get('model', central_config.model)
        self.base_url = config.get('ai', {}).get('base_url', central_config.base_url or '')
        self.api_key = config.get('ai', {}).get('api_key', central_config.api_key)
        self._session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def analyze_findings(
        self,
        findings: List[Dict],
        app_info: Dict = None,
        traffic_data: Dict = None
    ) -> List[LLMAnalysisResult]:
        """
        Analyze security findings using LLM
        
        Args:
            findings: List of security findings to analyze
            app_info: App metadata (name, platform, permissions, etc.)
            traffic_data: Captured network traffic for context
            
        Returns:
            List of LLMAnalysisResult with enhanced analysis
        """
        results = []
        
        for finding in findings:
            try:
                result = await self._analyze_single_finding(finding, app_info, traffic_data)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to analyze finding {finding.get('id', 'unknown')}: {e}")
                # Return basic result without LLM enhancement
                results.append(LLMAnalysisResult(
                    finding_id=finding.get('id', 'unknown'),
                    original_severity=finding.get('severity', 'medium'),
                    adjusted_severity=finding.get('severity', 'medium'),
                    exploitability_score=0.5,
                    impact_score=0.5,
                    confidence=0.3
                ))
        
        return results
    
    async def _analyze_single_finding(
        self,
        finding: Dict,
        app_info: Dict = None,
        traffic_data: Dict = None
    ) -> LLMAnalysisResult:
        """Analyze a single finding with LLM"""
        
        prompt = f"""Analyze this mobile security finding and provide detailed assessment:

## Finding
- Title: {finding.get('title', 'Unknown')}
- Category: {finding.get('category', 'Unknown')}
- Severity: {finding.get('severity', 'medium')}
- Description: {finding.get('description', '')}
- Affected Component: {finding.get('affected_component', 'Unknown')}
- Attack Vector: {finding.get('attack_vector', '')}
- POC: {finding.get('poc', '')}

## App Context
- Platform: {app_info.get('platform', 'unknown') if app_info else 'unknown'}
- Permissions: {', '.join(app_info.get('permissions', [])[:10]) if app_info else 'unknown'}
- Has SSL Pinning: {app_info.get('has_ssl_pinning', 'unknown') if app_info else 'unknown'}

Respond with JSON in this exact format:
{{
    "adjusted_severity": "critical|high|medium|low",
    "exploitability_score": 0.0-1.0,
    "impact_score": 0.0-1.0,
    "attack_scenario": "Real-world scenario description",
    "step_by_step_exploit": ["Step 1", "Step 2", "Step 3"],
    "business_impact": "Impact on business/users",
    "remediation_steps": ["Fix 1", "Fix 2"],
    "code_fix_example": "Code snippet if applicable",
    "related_owasp": "M1-M10 category"
}}"""

        try:
            response = await self._call_llm(prompt)
            
            # Parse JSON response
            result_data = json.loads(response)
            
            return LLMAnalysisResult(
                finding_id=finding.get('id', 'unknown'),
                original_severity=finding.get('severity', 'medium'),
                adjusted_severity=result_data.get('adjusted_severity', finding.get('severity', 'medium')),
                exploitability_score=float(result_data.get('exploitability_score', 0.5)),
                impact_score=float(result_data.get('impact_score', 0.5)),
                confidence=0.8,
                attack_scenario=result_data.get('attack_scenario', ''),
                step_by_step_exploit=result_data.get('step_by_step_exploit', []),
                business_impact=result_data.get('business_impact', ''),
                remediation_steps=result_data.get('remediation_steps', []),
                code_fix_example=result_data.get('code_fix_example', '')
            )
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            # Return basic result
            return LLMAnalysisResult(
                finding_id=finding.get('id', 'unknown'),
                original_severity=finding.get('severity', 'medium'),
                adjusted_severity=finding.get('severity', 'medium'),
                exploitability_score=0.5,
                impact_score=0.5,
                confidence=0.3
            )
    
    async def generate_attack_recommendations(
        self,
        app_info: Dict,
        discovered_endpoints: Dict,
        static_findings: List[Dict]
    ) -> List[Dict]:
        """
        Generate intelligent attack recommendations based on app analysis
        Uses same approach as web app AI planner
        """
        
        prompt = f"""As a mobile security expert, recommend attack vectors for this app:

## App Information
- Platform: {app_info.get('platform', 'unknown')}
- Package: {app_info.get('package_name', 'unknown')}
- Debuggable: {app_info.get('debuggable', False)}
- SSL Pinning: {app_info.get('has_ssl_pinning', 'unknown')}
- Permissions: {', '.join(app_info.get('permissions', [])[:15])}

## Discovered API Endpoints
{json.dumps(list(discovered_endpoints.keys())[:20], indent=2)}

## Static Analysis Findings
{json.dumps([{{
    'title': f.get('title'),
    'category': f.get('category'),
    'severity': f.get('severity')
}} for f in static_findings[:10]], indent=2)}

Recommend the top 10 attack vectors to test. Respond with JSON:
{{
    "recommendations": [
        {{
            "priority": 1-10,
            "attack_type": "attack name",
            "target": "specific target",
            "technique": "how to perform",
            "tools": ["tool1", "tool2"],
            "expected_impact": "what could be achieved",
            "owasp_category": "M1-M10"
        }}
    ]
}}"""

        try:
            response = await self._call_llm(prompt)
            result = json.loads(response)
            return result.get('recommendations', [])
        except Exception as e:
            logger.error(f"Failed to generate attack recommendations: {e}")
            return self._get_default_recommendations(app_info)
    
    def _get_default_recommendations(self, app_info: Dict) -> List[Dict]:
        """Get default attack recommendations when LLM fails"""
        platform = app_info.get('platform', 'android')
        
        if platform == 'android':
            return [
                {
                    'priority': 1,
                    'attack_type': 'Content Provider Injection',
                    'target': 'Exported content providers',
                    'technique': 'Query content:// URIs with SQL injection payloads',
                    'tools': ['adb', 'drozer'],
                    'expected_impact': 'Data extraction, SQL injection',
                    'owasp_category': 'M1'
                },
                {
                    'priority': 2,
                    'attack_type': 'Intent Injection',
                    'target': 'Exported activities',
                    'technique': 'Send crafted intents with malicious extras',
                    'tools': ['adb', 'drozer'],
                    'expected_impact': 'Bypass authentication, access restricted features',
                    'owasp_category': 'M1'
                },
                {
                    'priority': 3,
                    'attack_type': 'SSL Pinning Bypass',
                    'target': 'HTTPS traffic',
                    'technique': 'Use Frida to bypass certificate pinning',
                    'tools': ['frida', 'objection', 'mitmproxy'],
                    'expected_impact': 'Intercept encrypted traffic, find API vulnerabilities',
                    'owasp_category': 'M3'
                },
            ]
        else:
            return [
                {
                    'priority': 1,
                    'attack_type': 'Keychain Extraction',
                    'target': 'iOS Keychain',
                    'technique': 'Dump keychain items on jailbroken device',
                    'tools': ['keychain-dumper', 'frida'],
                    'expected_impact': 'Extract stored credentials and tokens',
                    'owasp_category': 'M2'
                },
                {
                    'priority': 2,
                    'attack_type': 'URL Scheme Hijacking',
                    'target': 'Custom URL schemes',
                    'technique': 'Register same URL scheme in test app',
                    'tools': ['Xcode'],
                    'expected_impact': 'Intercept deep links, steal OAuth tokens',
                    'owasp_category': 'M1'
                },
                {
                    'priority': 3,
                    'attack_type': 'SSL Pinning Bypass',
                    'target': 'HTTPS traffic',
                    'technique': 'Use Frida/objection to bypass pinning',
                    'tools': ['frida', 'objection', 'mitmproxy'],
                    'expected_impact': 'Intercept encrypted traffic',
                    'owasp_category': 'M3'
                },
            ]
    
    async def generate_executive_summary(
        self,
        app_info: Dict,
        findings: List[Dict],
        traffic_analysis: Dict = None
    ) -> MobileSecurityReport:
        """
        Generate executive summary report using LLM
        """
        
        # Count by severity
        critical = len([f for f in findings if f.get('severity') == 'critical'])
        high = len([f for f in findings if f.get('severity') == 'high'])
        medium = len([f for f in findings if f.get('severity') == 'medium'])
        low = len([f for f in findings if f.get('severity') == 'low'])
        
        prompt = f"""Generate an executive summary for this mobile security assessment:

## Application
- Name: {app_info.get('app_name', 'Unknown')}
- Platform: {app_info.get('platform', 'unknown')}
- Package: {app_info.get('package_name', 'unknown')}

## Findings Summary
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Low: {low}
- Total: {len(findings)}

## Top Findings
{json.dumps([{{
    'title': f.get('title'),
    'severity': f.get('severity'),
    'category': f.get('category')
}} for f in findings[:10]], indent=2)}

Generate a concise executive summary. Respond with JSON:
{{
    "executive_summary": "2-3 paragraph summary for executives",
    "top_risks": ["Risk 1", "Risk 2", "Risk 3"],
    "recommended_actions": ["Action 1", "Action 2", "Action 3"],
    "risk_rating": "Critical|High|Medium|Low",
    "key_stats": {{
        "data_exposure_risk": true/false,
        "authentication_issues": true/false,
        "encryption_problems": true/false
    }}
}}"""

        try:
            response = await self._call_llm(prompt)
            result = json.loads(response)
            
            return MobileSecurityReport(
                app_name=app_info.get('app_name', 'Unknown'),
                platform=app_info.get('platform', 'unknown'),
                scan_id=app_info.get('scan_id', ''),
                generated_at=datetime.now().isoformat(),
                total_findings=len(findings),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
                executive_summary=result.get('executive_summary', ''),
                top_risks=result.get('top_risks', []),
                recommended_actions=result.get('recommended_actions', []),
                findings=findings
            )
            
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            # Return basic report
            return MobileSecurityReport(
                app_name=app_info.get('app_name', 'Unknown'),
                platform=app_info.get('platform', 'unknown'),
                scan_id=app_info.get('scan_id', ''),
                generated_at=datetime.now().isoformat(),
                total_findings=len(findings),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
                executive_summary=f"Security assessment completed with {len(findings)} findings.",
                top_risks=[f.get('title', 'Unknown') for f in findings[:3]],
                recommended_actions=["Address critical findings immediately", "Review authentication mechanisms", "Implement SSL pinning"],
                findings=findings
            )
    
    async def _call_llm(self, prompt: str) -> str:
        """Call LLM API (Ollama or OpenAI)"""
        
        if self.provider == 'ollama':
            return await self._call_ollama(prompt)
        elif self.provider == 'openai':
            return await self._call_openai(prompt)
        else:
            raise ValueError(f"Unknown AI provider: {self.provider}")
    
    async def _call_ollama(self, prompt: str) -> str:
        """Call Ollama API"""
        session = await self._get_session()
        
        payload = {
            'model': self.model,
            'prompt': prompt,
            'system': self.SYSTEM_PROMPT,
            'stream': False,
            'format': 'json'
        }
        
        try:
            async with session.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result.get('response', '{}')
                else:
                    error = await response.text()
                    logger.error(f"Ollama error: {error}")
                    return '{}'
                    
        except asyncio.TimeoutError:
            logger.warning("Ollama request timed out")
            return '{}'
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            return '{}'
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        if not self.openai_key:
            logger.error("OpenAI API key not configured")
            return '{}'
        
        session = await self._get_session()
        
        payload = {
            'model': 'gpt-4o',
            'messages': [
                {'role': 'system', 'content': self.SYSTEM_PROMPT},
                {'role': 'user', 'content': prompt}
            ],
            'response_format': {'type': 'json_object'}
        }
        
        headers = {
            'Authorization': f'Bearer {self.openai_key}',
            'Content-Type': 'application/json'
        }
        
        try:
            async with session.post(
                'https://api.openai.com/v1/chat/completions',
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return result['choices'][0]['message']['content']
                else:
                    error = await response.text()
                    logger.error(f"OpenAI error: {error}")
                    return '{}'
                    
        except Exception as e:
            logger.error(f"OpenAI call failed: {e}")
            return '{}'
    
    async def analyze_otp_bypass(self, auth_flow: Dict) -> Dict:
        """
        Analyze authentication flow and suggest OTP bypass techniques
        """
        prompt = f"""Analyze this mobile app authentication flow for OTP bypass vulnerabilities:

## Auth Flow
- Login Endpoint: {auth_flow.get('login_endpoint', 'unknown')}
- OTP Endpoint: {auth_flow.get('otp_endpoint', 'unknown')}
- OTP Length: {auth_flow.get('otp_length', 'unknown')}
- OTP Type: {auth_flow.get('otp_type', 'SMS')}
- Rate Limiting: {auth_flow.get('rate_limiting', 'unknown')}

## Request/Response Samples
{json.dumps(auth_flow.get('samples', [])[:3], indent=2)}

Suggest OTP bypass techniques. Respond with JSON:
{{
    "bypass_techniques": [
        {{
            "technique": "name",
            "description": "how it works",
            "steps": ["step1", "step2"],
            "success_probability": "high|medium|low"
        }}
    ],
    "recommended_test": "best technique to try first"
}}"""

        try:
            response = await self._call_llm(prompt)
            return json.loads(response)
        except Exception as e:
            logger.error(f"Failed to analyze OTP bypass: {e}")
            return {
                'bypass_techniques': [
                    {
                        'technique': 'OTP Brute Force',
                        'description': 'Try all possible OTP combinations if no rate limiting',
                        'steps': ['Capture OTP request', 'Enumerate all OTPs', 'Check for lockout'],
                        'success_probability': 'medium'
                    },
                    {
                        'technique': 'Response Manipulation',
                        'description': 'Modify server response to indicate valid OTP',
                        'steps': ['Intercept response', 'Change status to success', 'Forward to app'],
                        'success_probability': 'medium'
                    }
                ],
                'recommended_test': 'Start with response manipulation'
            }


# Factory function
def create_llm_analyzer(config: dict = None) -> MobileLLMAnalyzer:
    """Create and configure LLM analyzer"""
    return MobileLLMAnalyzer(config)
