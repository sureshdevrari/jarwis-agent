"""
JARWIS AGI PEN TEST - Jarwis Human Intelligence Engine
Jarwis-powered test planning and intelligent decision making

Supports multiple AI providers:
- OpenAI (cloud, paid)
- Google Gemini (cloud, free tier available)
"""

import json
import logging
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class WebsiteAnalysis:
    """Represents Jarwis website analysis results"""
    business_type: str  # e-commerce, social media, payment app, marketing, etc.
    website_purpose: str  # Brief description of what the site does
    has_login: bool
    has_signup: bool
    has_forgot_password: bool
    has_payment: bool
    has_user_profiles: bool
    has_file_upload: bool
    has_api: bool
    has_admin_panel: bool
    technologies: List[str]  # Detected technologies
    risk_areas: List[str]  # Potential security risk areas
    recommended_focus: List[str]  # What to focus testing on


@dataclass
class TestRecommendation:
    """Represents a Jarwis-recommended test"""
    tool: str  # sqlmap, nuclei, zap, custom
    target: str  # URL
    method: str  # GET, POST
    param: str  # Parameter to test
    payload_type: str  # sqli, xss, idor, etc.
    reason: str  # Why this test
    priority: int  # 1-10
    

class AIPlanner:
    """Jarwis Human Intelligence - Intelligent test planning and analysis"""
    
    # Verbose callback for logging to frontend
    _verbose_callback = None
    
    @classmethod
    def set_verbose_callback(cls, callback):
        """Set callback for verbose logging"""
        cls._verbose_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log a message via callback if available"""
        if AIPlanner._verbose_callback:
            try:
                AIPlanner._verbose_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    SYSTEM_PROMPT = """You are Jarwis, an expert security testing assistant powered by human intelligence patterns. Your role is to analyze 
discovered endpoints and existing findings to recommend the single most impactful next security test.

## OWASP Top 10 Detection Knowledge:

### A01: Broken Access Control
- IDOR patterns: /user?id=2 (accessing other user's data)
- Admin endpoints without auth token getting 200 OK
- Evidence: Sensitive data returned for unauthorized user

### A02: Cryptographic Failures  
- HTTP instead of HTTPS
- Sensitive data in plaintext URLs (password=, token=, api_key=)
- Missing HSTS header

### A03: Injection (SQLi, XSS, CMDi)
- SQLi Evidence: SQL error messages in response (mysql_, ORA-, SQLSTATE)
- XSS Evidence: Payload reflected unencoded (<script>, onerror=)
- CMDi Evidence: Command output (uid=, /etc/passwd content, ping output)

### A05: Security Misconfiguration
- Missing headers: CSP, X-Frame-Options, X-Content-Type-Options, HSTS
- Stack traces/debug info exposed (Traceback, Fatal error)
- Default credentials working

### A06: Vulnerable Components
- Server version disclosure in headers (Apache/2.4.1, nginx/1.18.0)
- JS library versions in page source

### A07: Authentication Failures
- No rate limiting on login
- User enumeration (different errors for valid/invalid users)
- No account lockout

### A10: SSRF
- URL parameters (url=, redirect=, callback=) reaching internal IPs
- Response containing internal service data (127.0.0.1, 192.168.x.x)

## Detection Logic:
```
if response.status == 200 and no_auth_token and is_admin_endpoint:
    flag("A01: Broken Access Control")

if sql_error_pattern in response:
    flag("A03: SQL Injection")

if payload_reflected_unencoded in response:
    flag("A03: XSS")

if internal_ip in response and url_param_controlled:
    flag("A10: SSRF")
```

When recommending tests:
1. Prioritize untested parameters for injection attacks
2. Look for privilege escalation opportunities (302 redirects to /admin)
3. Identify upload endpoints not yet tested with malicious files
4. Consider authentication bypass opportunities
5. Look for IDOR patterns in numeric IDs
6. Test URL parameters for SSRF

You must respond ONLY with valid JSON in this exact format:
{
    "tool": "sqlmap|nuclei|zap|manual|upload_test|idor_test",
    "target": "full URL",
    "method": "GET|POST",
    "param": "parameter name",
    "payload_type": "sqli|xss|idor|upload|auth_bypass|ssrf|xxe",
    "reason": "brief explanation with expected evidence",
    "priority": 1-10
}

If no valuable tests remain, respond with:
{"complete": true, "reason": "explanation"}
"""

    def __init__(
        self,
        provider: str = None,
        model: str = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None
    ):
        # Use centralized AI config for defaults
        central_config = get_ai_config()
        self.provider = (provider or central_config.provider).lower()
        self.model = model or central_config.model
        self.api_key = api_key or central_config.api_key
        self.base_url = base_url or central_config.base_url
        self._client = None
        self._init_client()
    
    def _init_client(self):
        """Initialize the Jarwis intelligence engine"""
        if self.provider == "gemini" or self.provider == "google":
            try:
                import google.generativeai as genai
                
                if not self.api_key:
                    logger.warning("Gemini API key not provided. Set GEMINI_API_KEY env variable or pass api_key parameter.")
                    self._client = None
                    return
                
                genai.configure(api_key=self.api_key)
                
                # Default to gemini-1.5-flash if not specified
                if self.model in ["jarwis", "llama3", "llama3.1"]:
                    self.model = "gemini-1.5-flash"
                
                self._client = genai.GenerativeModel(
                    model_name=self.model,
                    generation_config={
                        "temperature": 0.3,
                        "top_p": 0.95,
                        "top_k": 40,
                        "max_output_tokens": 4096,
                    },
                    safety_settings={
                        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
                        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
                        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
                        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
                    }
                )
                logger.info(f"Jarwis intelligence engine ready with Google Gemini: {self.model}")
                
            except ImportError:
                logger.warning("google-generativeai not installed. Run: pip install google-generativeai")
                self._client = None
            except Exception as e:
                logger.warning(f"Failed to initialize Gemini: {e}")
                self._client = None
                
        elif self.provider == "ollama":
            try:
                import ollama
                self._client = ollama.Client(host=self.base_url)
                # Verify model exists by listing available models
                try:
                    response = self._client.list()
                    # Handle both old dict-style and new object-style API
                    if hasattr(response, 'models'):
                        # New ollama library (0.4+) returns ListResponse object
                        available = [m.model for m in response.models]
                    elif isinstance(response, dict):
                        # Old ollama library returns dict
                        available = [m.get('name', m.get('model', '')) for m in response.get('models', [])]
                    else:
                        available = []
                    
                    if available:
                        logger.info(f"Jarwis intelligence engine ready. Available models: {available}")
                    else:
                        logger.warning("Jarwis intelligence engine connected but needs model setup.")
                    
                    # Try to match model name with or without :latest tag
                    if self.model not in available:
                        # Try adding :latest if not specified
                        if ':' not in self.model and f"{self.model}:latest" in available:
                            self.model = f"{self.model}:latest"
                            logger.info(f"Jarwis using model: {self.model}")
                        elif available:
                            # Fallback to first available model
                            self.model = available[0]
                            logger.info(f"Model not found, Jarwis falling back to: {self.model}")
                        else:
                            logger.warning(f"No models available. Jarwis will use heuristic responses.")
                            self._client = None
                    else:
                        logger.info(f"Jarwis intelligence engine ready with model: {self.model}")
                        
                except Exception as e:
                    logger.warning(f"Jarwis intelligence engine connection issue: {e}")
                    logger.warning("Jarwis will use heuristic-based analysis instead.")
                    self._client = None
            except ImportError:
                logger.warning("Jarwis intelligence dependencies not installed.")
                self._client = None
        elif self.provider == "openai":
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
                logger.info(f"Jarwis intelligence engine ready with OpenAI: {self.model}")
            except ImportError:
                logger.warning("OpenAI not installed, Jarwis using heuristic responses")
    
    def _call_gemini(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Make a call to Google Gemini API"""
        if not self._client:
            return None
        
        try:
            # Gemini uses a different format - combine system and user prompts
            full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
            
            response = self._client.generate_content(full_prompt)
            
            if response and response.text:
                return response.text
            return None
        except Exception as e:
            logger.error(f"Gemini API call failed: {e}")
            return None

    async def analyze_website(self, html_content: str, url: str, page_title: str = "", discovered_links: List[str] = None) -> Dict:
        """
        Jarwis Human Intelligence: Analyze website to understand business type and features.
        This is Phase 1 - Understanding the target before testing.
        """
        self._log('jarwis', 'ðŸ§  Jarwis is using human intelligence to analyze the website...')
        self._log('info', 'Examining source code, page structure, and content patterns...')
        
        discovered_links = discovered_links or []
        
        # Extract key patterns from HTML for analysis
        html_lower = html_content.lower() if html_content else ""
        
        # Quick pattern detection for fallback
        has_login = any(x in html_lower for x in ['login', 'sign in', 'signin', 'log in'])
        has_signup = any(x in html_lower for x in ['signup', 'sign up', 'register', 'create account'])
        has_forgot = any(x in html_lower for x in ['forgot', 'reset password', 'recover'])
        has_payment = any(x in html_lower for x in ['payment', 'checkout', 'cart', 'buy', 'purchase', 'price', '$'])
        has_upload = any(x in html_lower for x in ['upload', 'file', 'attach', 'dropzone'])
        has_api = any(x in html_lower for x in ['/api/', 'graphql', 'swagger', 'rest'])
        has_admin = any(x in html_lower for x in ['admin', 'dashboard', 'management', 'control panel'])
        has_profiles = any(x in html_lower for x in ['profile', 'account', 'my account', 'settings'])
        
        prompt = f"""You are Jarwis, a human-intelligence security analyst. Analyze this website to understand:
1. What type of business/application is this?
2. What features and functionality does it have?
3. What security testing should we focus on?

WEBSITE URL: {url}
PAGE TITLE: {page_title}

DISCOVERED LINKS/PAGES ({len(discovered_links)} found):
{json.dumps(discovered_links[:30], indent=2) if discovered_links else "None yet"}

HTML CONTENT SAMPLE (first 3000 chars):
{html_content[:3000] if html_content else "No content available"}

Analyze like a human security expert would - look at the page structure, content, and functionality.

Respond with ONLY valid JSON:
{{
    "business_type": "e-commerce|social-media|payment-app|banking|healthcare|education|marketing|blog|forum|corporate|saas|other",
    "website_purpose": "Brief 1-2 sentence description of what this site does",
    "detected_features": {{
        "has_login": true/false,
        "has_signup": true/false, 
        "has_forgot_password": true/false,
        "has_payment": true/false,
        "has_user_profiles": true/false,
        "has_file_upload": true/false,
        "has_api": true/false,
        "has_admin_panel": true/false,
        "has_search": true/false,
        "has_comments": true/false
    }},
    "technologies": ["list", "of", "detected", "technologies"],
    "risk_areas": ["authentication", "payment processing", "file uploads", "etc"],
    "recommended_focus": ["What security tests Jarwis should prioritize"],
    "human_observation": "What a human security expert would notice about this site"
}}"""

        try:
            # Use Gemini if configured
            if self._client and self.provider in ["gemini", "google"]:
                self._log('jarwis', 'Jarwis is thinking like a human security expert (powered by Gemini)...')
                system_prompt = "You are Jarwis, an expert security analyst with human-like intelligence. Analyze websites thoroughly. Always respond with valid JSON only."
                content = self._call_gemini(system_prompt, prompt)
                
                if content:
                    result = self._parse_response(content)
                    if result:
                        self._log('success', 'Jarwis has completed website analysis')
                        return result
            
            # Use Ollama if configured
            elif self._client and self.provider == "ollama":
                self._log('jarwis', 'Jarwis is thinking like a human security expert...')
                response = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are Jarwis, an expert security analyst with human-like intelligence. Analyze websites thoroughly."},
                        {"role": "user", "content": prompt}
                    ]
                )
                if hasattr(response, 'message'):
                    content = response.message.content
                elif isinstance(response, dict):
                    content = response['message']['content']
                else:
                    return self._default_website_analysis(url, has_login, has_signup, has_forgot, has_payment, has_upload, has_api, has_admin, has_profiles)
                
                result = self._parse_response(content)
                if result:
                    self._log('success', 'Jarwis has completed website analysis')
                    return result
            
            return self._default_website_analysis(url, has_login, has_signup, has_forgot, has_payment, has_upload, has_api, has_admin, has_profiles)
            
        except Exception as e:
            logger.error(f"Website analysis failed: {e}")
            return self._default_website_analysis(url, has_login, has_signup, has_forgot, has_payment, has_upload, has_api, has_admin, has_profiles)
    
    def _default_website_analysis(self, url: str, has_login: bool, has_signup: bool, has_forgot: bool, 
                                   has_payment: bool, has_upload: bool, has_api: bool, 
                                   has_admin: bool, has_profiles: bool) -> Dict:
        """Generate default analysis when intelligence engine is unavailable"""
        risk_areas = []
        recommended_focus = []
        
        if has_login:
            risk_areas.append("Authentication mechanisms")
            recommended_focus.append("Test login for SQL injection, brute force, credential stuffing")
        if has_signup:
            risk_areas.append("User registration")
            recommended_focus.append("Test signup for mass registration, input validation")
        if has_forgot:
            risk_areas.append("Password reset functionality")
            recommended_focus.append("Test password reset for user enumeration, token manipulation")
        if has_payment:
            risk_areas.append("Payment processing")
            recommended_focus.append("Test payment flows for price manipulation, IDOR")
        if has_upload:
            risk_areas.append("File upload functionality")
            recommended_focus.append("Test uploads for malicious file execution, path traversal")
        if has_api:
            risk_areas.append("API endpoints")
            recommended_focus.append("Test API for authentication bypass, rate limiting, injection")
        if has_admin:
            risk_areas.append("Admin functionality")
            recommended_focus.append("Test admin access controls, privilege escalation")
        if has_profiles:
            risk_areas.append("User profiles")
            recommended_focus.append("Test profiles for IDOR, sensitive data exposure")
        
        if not risk_areas:
            risk_areas = ["General web application security"]
            recommended_focus = ["Comprehensive OWASP Top 10 testing"]
        
        return {
            "business_type": "web-application",
            "website_purpose": f"Web application at {url}",
            "detected_features": {
                "has_login": has_login,
                "has_signup": has_signup,
                "has_forgot_password": has_forgot,
                "has_payment": has_payment,
                "has_user_profiles": has_profiles,
                "has_file_upload": has_upload,
                "has_api": has_api,
                "has_admin_panel": has_admin,
                "has_search": False,
                "has_comments": False
            },
            "technologies": ["Unknown - requires deeper analysis"],
            "risk_areas": risk_areas,
            "recommended_focus": recommended_focus,
            "human_observation": "Jarwis detected key features through pattern analysis. Manual review recommended for comprehensive assessment."
        }

    async def generate_scan_plan(self, website_analysis: Dict, endpoints: List[Dict]) -> Dict:
        """
        Jarwis Human Intelligence: Generate a human-readable scan plan.
        This is Phase 2 - Planning the attack strategy.
        """
        self._log('jarwis', 'ðŸŽ¯ Jarwis is formulating the penetration testing strategy...')
        
        prompt = f"""You are Jarwis, a human security expert. Based on this website analysis, create a detailed scan plan.

WEBSITE ANALYSIS:
{json.dumps(website_analysis, indent=2)}

DISCOVERED ENDPOINTS ({len(endpoints)} found):
{json.dumps([{'url': e.get('url', ''), 'method': e.get('method', 'GET'), 'type': e.get('type', 'page')} for e in endpoints[:20]], indent=2)}

Create a penetration testing plan that sounds like a human expert wrote it. Explain:
1. What Jarwis will test and why
2. The order of testing phases
3. What vulnerabilities to look for based on the business type
4. Specific attack vectors for detected features

Respond with ONLY valid JSON:
{{
    "executive_overview": "2-3 sentences explaining the overall approach",
    "phases": [
        {{
            "phase_number": 1,
            "phase_name": "...",
            "description": "What Jarwis will do in this phase",
            "targets": ["specific things to test"],
            "techniques": ["techniques to use"]
        }}
    ],
    "priority_attacks": ["List of highest priority attack vectors"],
    "expected_findings": ["Types of vulnerabilities Jarwis expects to find"],
    "human_strategy": "How a human pentester would approach this target"
}}"""

        try:
            if self._client and self.provider == "ollama":
                self._log('jarwis', 'Jarwis is planning the attack like an expert...')
                response = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are Jarwis, a senior penetration tester. Create detailed, actionable security testing plans."},
                        {"role": "user", "content": prompt}
                    ]
                )
                if hasattr(response, 'message'):
                    content = response.message.content
                elif isinstance(response, dict):
                    content = response['message']['content']
                else:
                    return self._default_scan_plan(website_analysis, endpoints)
                
                result = self._parse_response(content)
                if result:
                    self._log('success', 'Jarwis has prepared the attack strategy')
                    return result
            
            return self._default_scan_plan(website_analysis, endpoints)
            
        except Exception as e:
            logger.error(f"Scan plan generation failed: {e}")
            return self._default_scan_plan(website_analysis, endpoints)
    
    def _default_scan_plan(self, website_analysis: Dict, endpoints: List[Dict]) -> Dict:
        """Generate default scan plan when intelligence engine is unavailable"""
        features = website_analysis.get('detected_features', {})
        phases = []
        phase_num = 1
        
        # Phase: Reconnaissance
        phases.append({
            "phase_number": phase_num,
            "phase_name": "Reconnaissance & Discovery",
            "description": "Jarwis will map the attack surface by crawling all accessible pages and identifying entry points",
            "targets": ["All discovered URLs", "Hidden directories", "API endpoints"],
            "techniques": ["Spidering", "Directory enumeration", "Technology fingerprinting"]
        })
        phase_num += 1
        
        # Phase: Authentication Testing (if login detected)
        if features.get('has_login') or features.get('has_signup'):
            phases.append({
                "phase_number": phase_num,
                "phase_name": "Authentication Testing",
                "description": "Jarwis will test login mechanisms for weaknesses including SQL injection, brute force resistance, and session management",
                "targets": ["Login forms", "Session tokens", "Remember me functionality"],
                "techniques": ["SQL injection", "Credential stuffing patterns", "Session hijacking attempts"]
            })
            phase_num += 1
        
        # Phase: Injection Testing
        phases.append({
            "phase_number": phase_num,
            "phase_name": "Injection Vulnerability Testing",
            "description": "Jarwis will test all input points for SQL injection, XSS, and command injection vulnerabilities",
            "targets": ["Form inputs", "URL parameters", "HTTP headers"],
            "techniques": ["SQLi payloads", "XSS vectors", "Command injection patterns"]
        })
        phase_num += 1
        
        # Phase: Access Control
        phases.append({
            "phase_number": phase_num,
            "phase_name": "Access Control Testing",
            "description": "Jarwis will verify that proper authorization checks are in place for all resources",
            "targets": ["User resources", "Admin functions", "API endpoints"],
            "techniques": ["IDOR testing", "Privilege escalation", "Forced browsing"]
        })
        phase_num += 1
        
        # Phase: Business Logic (if payment detected)
        if features.get('has_payment'):
            phases.append({
                "phase_number": phase_num,
                "phase_name": "Business Logic Testing",
                "description": "Jarwis will test payment and transaction flows for logic flaws that could lead to financial loss",
                "targets": ["Checkout flow", "Price parameters", "Coupon/discount logic"],
                "techniques": ["Price manipulation", "Race conditions", "Integer overflow testing"]
            })
            phase_num += 1
        
        return {
            "executive_overview": f"Jarwis will conduct a comprehensive security assessment of this {website_analysis.get('business_type', 'web application')}. The testing will focus on {', '.join(website_analysis.get('risk_areas', ['general vulnerabilities'])[:3])} based on the detected features and business context.",
            "phases": phases,
            "priority_attacks": website_analysis.get('recommended_focus', ["OWASP Top 10 vulnerabilities"]),
            "expected_findings": ["Injection vulnerabilities", "Broken access control", "Security misconfigurations", "Sensitive data exposure"],
            "human_strategy": "Jarwis approaches this target methodically - first understanding the application, then mapping attack surfaces, and finally executing targeted attacks based on the technology stack and business logic."
        }

    async def get_next_test(
        self,
        endpoints: List[Dict],
        findings: List,
        completed_tests: List[Dict]
    ) -> Optional[Dict]:
        """Get the next recommended test from Jarwis"""
        
        # Build context for the AI
        context = self._build_context(endpoints, findings, completed_tests)
        
        # Get recommendation
        response = await self._query_llm(context)
        
        if response and not response.get('complete'):
            return response
        
        return None
    
    def _build_context(
        self,
        endpoints: List[Dict],
        findings: List,
        completed_tests: List[Dict]
    ) -> str:
        """Build context string for the AI"""
        
        # Summarize endpoints
        endpoint_summary = []
        for ep in endpoints[:50]:  # Limit to first 50
            summary = {
                'url': ep.get('url', ''),
                'method': ep.get('method', 'GET'),
                'type': ep.get('type', 'page'),
                'params': list(ep.get('params', {}).keys()) if isinstance(ep.get('params'), dict) else [],
                'has_upload': ep.get('has_upload', False)
            }
            endpoint_summary.append(summary)
        
        # Summarize findings
        finding_summary = []
        for f in findings:
            finding_summary.append({
                'category': getattr(f, 'category', 'unknown'),
                'severity': getattr(f, 'severity', 'unknown'),
                'url': getattr(f, 'url', ''),
                'param': getattr(f, 'parameter', '')
            })
        
        # Summarize completed tests
        completed_summary = [
            f"{t.get('tool')}:{t.get('target')}:{t.get('param')}"
            for t in completed_tests[-20:]  # Last 20
        ]
        
        context = f"""
DISCOVERED ENDPOINTS ({len(endpoints)} total):
{json.dumps(endpoint_summary, indent=2)}

EXISTING FINDINGS ({len(findings)} total):
{json.dumps(finding_summary, indent=2)}

COMPLETED TESTS:
{json.dumps(completed_summary, indent=2)}

Based on this information, what is the single most valuable next security test to run?
"""
        return context
    
    async def _query_llm(self, context: str) -> Optional[Dict]:
        """Query Jarwis intelligence for a recommendation"""
        try:
            # Use Gemini if configured
            if self.provider in ["gemini", "google"] and self._client:
                self._log('jarwis', f'Jarwis is analyzing with Gemini AI...')
                content = self._call_gemini(self.SYSTEM_PROMPT, context)
                if content:
                    self._log('jarwis', 'Jarwis analysis complete', content[:200] if len(content) > 200 else content)
                    return self._parse_response(content)
                return None
            
            elif self.provider == "ollama" and self._client:
                self._log('jarwis', f'Jarwis is analyzing with human intelligence...')
                response = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": context}
                    ]
                )
                # Handle both old dict-style and new object-style API
                if hasattr(response, 'message'):
                    # New ollama library (0.4+) returns ChatResponse object
                    content = response.message.content
                elif isinstance(response, dict):
                    # Old ollama library returns dict
                    content = response['message']['content']
                else:
                    logger.error(f"Unexpected response type: {type(response)}")
                    return None
                self._log('jarwis', 'Jarwis analysis complete', content[:200] if len(content) > 200 else content)
                return self._parse_response(content)
            
            elif self.provider == "openai" and self._client:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": context}
                    ],
                    temperature=0.3,
                    max_tokens=500
                )
                return self._parse_response(response.choices[0].message.content)
            
            else:
                # Fallback mock response for testing
                return self._mock_response(context)
                
        except Exception as e:
            logger.error(f"LLM query failed: {e}")
            return None
    
    def _parse_response(self, response: str) -> Optional[Dict]:
        """Parse JSON response from LLM"""
        try:
            # Try to extract JSON from response
            response = response.strip()
            
            # Handle markdown code blocks
            if '```json' in response:
                response = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                response = response.split('```')[1].split('```')[0]
            
            return json.loads(response)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return None
    
    def _mock_response(self, context: str) -> Dict:
        """Generate a mock response for testing without LLM"""
        # Simple heuristic-based recommendation
        if 'upload' in context.lower():
            return {
                "tool": "upload_test",
                "target": "http://example.com/upload",
                "method": "POST",
                "param": "file",
                "payload_type": "upload",
                "reason": "Upload endpoint detected, testing for malicious file upload",
                "priority": 8
            }
        elif 'api' in context.lower():
            return {
                "tool": "nuclei",
                "target": "http://example.com/api/users",
                "method": "GET",
                "param": "id",
                "payload_type": "idor",
                "reason": "API endpoint with ID parameter, testing for IDOR",
                "priority": 7
            }
        else:
            return {"complete": True, "reason": "No high-value tests identified"}
    
    async def analyze_finding(self, finding: Dict) -> Dict:
        """Analyze a finding for severity and recommendations"""
        prompt = f"""
Analyze this security finding and provide:
1. Confirmed severity (critical/high/medium/low)
2. Potential impact
3. Remediation recommendation

Finding:
{json.dumps(finding, indent=2)}

Respond in JSON format:
{{
    "confirmed_severity": "...",
    "impact": "...",
    "remediation": "...",
    "false_positive_likelihood": "low|medium|high"
}}
"""
        try:
            if self._client:
                if self.provider == "ollama":
                    response = self._client.chat(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return self._parse_response(response['message']['content'])
            
            # Fallback
            return {
                "confirmed_severity": finding.get('severity', 'medium'),
                "impact": "Requires manual verification",
                "remediation": "Review and patch according to OWASP guidelines",
                "false_positive_likelihood": "medium"
            }
        except Exception as e:
            logger.error(f"Finding analysis failed: {e}")
            return {}
    
    async def correlate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Correlate related findings for attack chain analysis"""
        if len(findings) < 2:
            self._log('info', 'Not enough findings for attack chain analysis')
            return []
        
        self._log('jarwis', f'Jarwis is analyzing {len(findings)} findings for attack chain correlations...')
        
        prompt = f"""
Analyze these security findings and identify potential attack chains
where combining multiple vulnerabilities could lead to higher impact:

Findings:
{json.dumps(findings[:20], indent=2)}

Respond with JSON array of correlated attack chains:
[
    {{
        "chain_name": "...",
        "findings": ["finding_id1", "finding_id2"],
        "combined_impact": "...",
        "severity": "critical|high|medium"
    }}
]
"""
        try:
            if self._client:
                if self.provider == "ollama":
                    response = self._client.chat(
                        model=self.model,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return self._parse_response(response['message']['content']) or []
            
            return []
        except Exception as e:
            logger.error(f"Correlation failed: {e}")
            return []

    async def verify_vulnerability(self, finding: Dict) -> Dict:
        """
        Jarwis Human Intelligence: Verify if a vulnerability is a true positive or false positive.
        Returns verification result with confidence score.
        """
        self._log('jarwis', f"Jarwis is verifying: {finding.get('title', 'Unknown finding')}")
        prompt = f"""You are an expert penetration tester reviewing vulnerability findings.
Analyze this finding and determine if it's a TRUE POSITIVE or FALSE POSITIVE.

FINDING TO VERIFY:
- Title: {finding.get('title', 'Unknown')}
- Category: {finding.get('category', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- URL: {finding.get('url', 'Unknown')}
- Evidence: {finding.get('evidence', 'None')[:500]}
- Request Data: {finding.get('request_data', 'None')[:300]}
- Response Data: {finding.get('response_data', 'None')[:500]}

VERIFICATION CRITERIA:
1. Does the evidence clearly demonstrate the vulnerability?
2. Is the response behavior consistent with the claimed vulnerability type?
3. Could this be normal application behavior misinterpreted as a vulnerability?
4. Are there SQL errors, XSS reflection, or sensitive data actually exposed?

You MUST respond with ONLY valid JSON:
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "detailed explanation of why this is valid or false positive",
    "adjusted_severity": "critical/high/medium/low/info",
    "recommendation": "what action to take"
}}
"""
        try:
            if self._client and self.provider == "ollama":
                response = self._client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a security expert. Respond only with valid JSON."},
                        {"role": "user", "content": prompt}
                    ]
                )
                # Handle both API styles
                if hasattr(response, 'message'):
                    content = response.message.content
                elif isinstance(response, dict):
                    content = response['message']['content']
                else:
                    return self._default_verification(finding)
                
                result = self._parse_response(content)
                if result:
                    return result
            
            return self._default_verification(finding)
            
        except Exception as e:
            logger.error(f"AI verification failed: {e}")
            return self._default_verification(finding)
    
    def _default_verification(self, finding: Dict) -> Dict:
        """Default verification when Jarwis intelligence is unavailable"""
        return {
            "is_valid": True,
            "confidence": 0.5,
            "reasoning": "Jarwis heuristic verification applied, manual review recommended",
            "adjusted_severity": finding.get('severity', 'medium'),
            "recommendation": "Manual verification recommended"
        }
    
    async def batch_verify_findings(self, findings: List) -> List[Dict]:
        """
        Jarwis Human Intelligence: Verify a batch of findings.
        Returns list of findings with verification results.
        """
        verified_findings = []
        total = len(findings)
        self._log('jarwis', f'Jarwis is using human intelligence to verify {total} findings...')
        
        for idx, finding in enumerate(findings):
            self._log('info', f'Verifying finding {idx+1}/{total}...')
            # Convert finding to dict if it's a dataclass
            if hasattr(finding, '__dict__'):
                finding_dict = {
                    'id': getattr(finding, 'id', ''),
                    'title': getattr(finding, 'title', ''),
                    'category': getattr(finding, 'category', ''),
                    'severity': getattr(finding, 'severity', ''),
                    'url': getattr(finding, 'url', ''),
                    'evidence': getattr(finding, 'evidence', ''),
                    'request_data': getattr(finding, 'request_data', ''),
                    'response_data': getattr(finding, 'response_data', getattr(finding, 'response_snippet', '')),
                }
            else:
                finding_dict = finding
            
            verification = await self.verify_vulnerability(finding_dict)
            
            is_valid = verification.get('is_valid', True)
            confidence = verification.get('confidence', 0.5)
            if is_valid:
                self._log('success', f"Verified: {finding_dict.get('title', 'Finding')}", f"Confidence: {confidence*100:.0f}%")
            else:
                self._log('warning', f"False positive: {finding_dict.get('title', 'Finding')}", verification.get('reasoning', '')[:100])
            
            verified_findings.append({
                'finding': finding,
                'verification': verification
            })
        
        valid_count = sum(1 for v in verified_findings if v['verification'].get('is_valid', True))
        self._log('success', f'Jarwis verification complete: {valid_count}/{total} valid findings')
        return verified_findings
    
    async def generate_executive_summary(self, findings: List, verified_results: List[Dict]) -> str:
        """Generate a Jarwis-powered executive summary of the security assessment"""
        self._log('jarwis', 'Jarwis is generating executive summary with human intelligence...')
        
        # Count by severity after verification
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        valid_findings = []
        
        for result in verified_results:
            if result['verification'].get('is_valid', True):
                severity = result['verification'].get('adjusted_severity', 'medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                valid_findings.append(result)
        
        # Build findings summary - handle both dataclass and dict
        findings_list = []
        for r in valid_findings[:15]:
            finding = r['finding']
            if hasattr(finding, 'title'):
                title = finding.title
            elif isinstance(finding, dict):
                title = finding.get('title', 'Unknown')
            else:
                title = 'Unknown'
            
            findings_list.append({
                'title': title,
                'severity': r['verification'].get('adjusted_severity', 'medium'),
                'confidence': r['verification'].get('confidence', 0.5)
            })
        
        findings_summary = json.dumps(findings_list, indent=2)
        
        prompt = f"""You are a senior security consultant writing an executive summary.

VERIFIED FINDINGS SUMMARY:
- Critical: {severity_counts['critical']}
- High: {severity_counts['high']}
- Medium: {severity_counts['medium']}
- Low: {severity_counts['low']}
- Informational: {severity_counts['info']}

TOP FINDINGS:
{findings_summary}

Write a professional executive summary (3-4 paragraphs) that:
1. Summarizes the overall security posture
2. Highlights the most critical risks
3. Provides strategic recommendations
4. Uses professional language suitable for C-level executives

Respond with plain text, no JSON."""

        try:
            if self._client and self.provider == "ollama":
                response = self._client.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                if hasattr(response, 'message'):
                    return response.message.content
                elif isinstance(response, dict):
                    return response['message']['content']
            
            return self._generate_default_summary(severity_counts)
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return self._generate_default_summary(severity_counts)
    
    def _generate_default_summary(self, severity_counts: Dict) -> str:
        """Generate a default summary when AI is unavailable"""
        total = sum(severity_counts.values())
        critical_high = severity_counts['critical'] + severity_counts['high']
        
        return f"""Executive Summary

The security assessment identified {total} potential vulnerabilities, with {critical_high} classified as critical or high severity. These findings require immediate attention to prevent potential security breaches.

The assessment covered multiple attack vectors including injection vulnerabilities, cross-site scripting, security misconfigurations, and sensitive data exposure. Each finding has been verified to reduce false positives.

Recommended actions:
1. Address all critical and high severity findings within 30 days
2. Implement security headers and proper input validation
3. Review access controls and authentication mechanisms
4. Establish a regular security testing schedule"""
    
    # ========================
    # CLOUD SECURITY METHODS
    # ========================
    
    async def prioritize_cloud_findings(self, findings: List[Dict], attack_paths: List[Dict] = None) -> List[Dict]:
        """
        AI-powered prioritization of cloud security findings
        
        Args:
            findings: List of cloud security findings
            attack_paths: Optional attack path analysis from CloudSecurityGraph
        
        Returns:
            Prioritized findings with AI-generated risk scores and reasoning
        """
        if not findings:
            return []
        
        self._log("ai", "Prioritizing cloud security findings with AI...")
        
        # Build prompt with context
        prompt = self._build_cloud_prioritization_prompt(findings, attack_paths)
        
        try:
            if self._client and self.provider == "ollama":
                response = self._client.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                response_text = ""
                if hasattr(response, 'message'):
                    response_text = response.message.content
                elif isinstance(response, dict):
                    response_text = response['message']['content']
                
                # Parse AI response
                prioritized = self._parse_cloud_prioritization_response(response_text, findings)
                return prioritized
            
            # Fallback: Basic severity-based sorting
            return sorted(findings, key=lambda f: (
                {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(f.get('severity', 'info'), 5),
                -f.get('cvss_score', 0)
            ))
        
        except Exception as e:
            logger.error(f"Cloud finding prioritization failed: {e}")
            return findings
    
    def _build_cloud_prioritization_prompt(self, findings: List[Dict], attack_paths: List[Dict] = None) -> str:
        """Build AI prompt for cloud finding prioritization"""
        
        # Summarize findings
        findings_summary = []
        for idx, finding in enumerate(findings[:20]):  # Limit to top 20 for context
            findings_summary.append({
                'index': idx,
                'provider': finding.get('provider', 'unknown'),
                'service': finding.get('service', 'unknown'),
                'severity': finding.get('severity', 'info'),
                'title': finding.get('title', ''),
                'resource': finding.get('resource_arn', finding.get('resource_id', '')),
                'detection_layer': finding.get('detection_layer', 'cspm')
            })
        
        # Summarize attack paths if available
        attack_path_summary = ""
        if attack_paths:
            attack_path_summary = "\n\nATTACK PATHS DETECTED:\n"
            for path in attack_paths[:5]:
                attack_path_summary += f"- {path.get('description', 'Unknown path')}\n"
                attack_path_summary += f"  Blast radius: {path.get('blast_radius', 0)}\n"
                attack_path_summary += f"  Steps: {' -> '.join(path.get('path', []))}\n"
        
        prompt = f"""You are a cloud security expert analyzing findings from AWS, Azure, and GCP.

FINDINGS SUMMARY ({len(findings)} total):
{json.dumps(findings_summary, indent=2)}
{attack_path_summary}

TASK: Prioritize these findings based on:
1. Exploitability (how easy to exploit)
2. Impact (blast radius, data exposure, lateral movement potential)
3. Attack path involvement (is this finding part of a multi-step attack chain?)
4. Compliance impact (CIS benchmarks, PCI-DSS, HIPAA)

For each finding, respond with JSON:
{{
    "prioritized_findings": [
        {{
            "index": 0,
            "risk_score": 95,  // 0-100
            "reasoning": "Public S3 bucket containing PII. Direct data breach risk.",
            "exploitability": "trivial",  // trivial, easy, moderate, difficult
            "attack_chain": true,  // Is this part of an attack path?
            "remediation_priority": "immediate"  // immediate, short-term, long-term
        }}
    ]
}}

Only return valid JSON. Analyze all {len(findings_summary)} findings shown above."""

        return prompt
    
    def _parse_cloud_prioritization_response(self, response_text: str, findings: List[Dict]) -> List[Dict]:
        """Parse AI response and merge with original findings"""
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                ai_data = json.loads(json_match.group())
                prioritized = ai_data.get('prioritized_findings', [])
                
                # Merge AI insights with original findings
                for ai_item in prioritized:
                    idx = ai_item.get('index')
                    if 0 <= idx < len(findings):
                        findings[idx]['ai_risk_score'] = ai_item.get('risk_score', 0)
                        findings[idx]['ai_reasoning'] = ai_item.get('reasoning', '')
                        findings[idx]['exploitability'] = ai_item.get('exploitability', 'unknown')
                        findings[idx]['attack_chain'] = ai_item.get('attack_chain', False)
                        findings[idx]['remediation_priority'] = ai_item.get('remediation_priority', 'medium')
                
                # Sort by AI risk score
                return sorted(findings, key=lambda f: -f.get('ai_risk_score', 0))
        
        except Exception as e:
            logger.error(f"Failed to parse cloud prioritization response: {e}")
        
        return findings
    
    async def analyze_attack_path(self, attack_path: Dict, resources: List[Dict]) -> Dict[str, str]:
        """
        AI analysis of a specific attack path
        
        Args:
            attack_path: Attack path dict from CloudSecurityGraph
            resources: Cloud resources involved
        
        Returns:
            {
                'summary': str,
                'exploitation_steps': str,
                'remediation': str,
                'business_impact': str
            }
        """
        self._log("ai", f"Analyzing attack path: {attack_path.get('description', 'Unknown')}")
        
        prompt = f"""You are a cloud security expert analyzing an attack path.

ATTACK PATH:
- Description: {attack_path.get('description', 'Unknown')}
- Blast Radius: {attack_path.get('blast_radius', 0)} (0-100 scale)
- Steps: {' -> '.join(attack_path.get('path', []))}

RESOURCES INVOLVED:
{json.dumps(resources, indent=2)}

Provide a detailed analysis in JSON format:
{{
    "summary": "Brief 2-sentence summary of the attack",
    "exploitation_steps": "Step-by-step how an attacker would exploit this",
    "remediation": "Specific remediation actions with priority order",
    "business_impact": "Business consequences if exploited"
}}

Only return valid JSON."""

        try:
            if self._client and self.provider == "ollama":
                response = self._client.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                response_text = ""
                if hasattr(response, 'message'):
                    response_text = response.message.content
                elif isinstance(response, dict):
                    response_text = response['message']['content']
                
                # Extract JSON
                import re
                json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
        
        except Exception as e:
            logger.error(f"Attack path analysis failed: {e}")
        
        # Fallback
        return {
            'summary': attack_path.get('description', 'Unknown attack path'),
            'exploitation_steps': 'AI analysis unavailable',
            'remediation': 'Review resources involved in this attack path',
            'business_impact': 'Potential unauthorized access or data breach'
        }
    
    async def generate_cloud_remediation(self, finding: Dict) -> str:
        """
        Generate detailed remediation guidance for a cloud finding
        
        Args:
            finding: Cloud security finding
        
        Returns:
            Detailed remediation guidance string
        """
        prompt = f"""You are a cloud security expert providing remediation guidance.

FINDING:
- Provider: {finding.get('provider', 'unknown')}
- Service: {finding.get('service', 'unknown')}
- Severity: {finding.get('severity', 'info')}
- Title: {finding.get('title', '')}
- Description: {finding.get('description', '')}
- Resource: {finding.get('resource_arn', finding.get('resource_id', ''))}

Provide specific remediation steps in plain text format:
1. Step-by-step CLI commands or console instructions
2. Infrastructure-as-Code (Terraform/CloudFormation) fixes
3. Preventive controls to avoid recurrence

Be specific and actionable. Include actual command examples."""

        try:
            if self._client and self.provider == "ollama":
                response = self._client.chat(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}]
                )
                
                if hasattr(response, 'message'):
                    return response.message.content
                elif isinstance(response, dict):
                    return response['message']['content']
        
        except Exception as e:
            logger.error(f"Remediation generation failed: {e}")
        
        # Fallback to existing remediation_cli if available
        return finding.get('remediation_cli', finding.get('remediation', 'No remediation guidance available'))
