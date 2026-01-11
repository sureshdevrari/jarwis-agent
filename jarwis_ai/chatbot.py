"""
Jarwis AGI Chatbot - API Endpoint
AI-powered security testing assistant
Created by BKD Labs

Supports:
- Per-user session isolation
- Scan findings context
- Server logs analysis
- User authentication isolation (future)
- Gemini/OpenAI backends
"""

import json
import logging
import os
import re
import time
from typing import Dict, List, Optional, Generator
from dataclasses import dataclass, field
from datetime import datetime
from shared.ai_config import get_ai_config

# Gemini API
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False
    genai = None

logger = logging.getLogger(__name__)


@dataclass
class ChatMessage:
    role: str  # "user" or "assistant"
    content: str
    timestamp: str


@dataclass
class UserSession:
    """Per-user chat session with isolated data"""
    session_id: str
    user_id: Optional[str] = None  # For future authentication
    conversation_history: List[ChatMessage] = field(default_factory=list)
    scan_context: dict = field(default_factory=dict)
    accessible_scans: List[str] = field(default_factory=list)  # Scan IDs user can access
    server_logs: List[dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_activity: str = field(default_factory=lambda: datetime.now().isoformat())


class JarwisChatbot:
    """Jarwis AGI Chatbot - Security Testing Assistant by BKD Labs"""
    
    # ========== JARWIS AGI BRAND TRAINING ==========
    # Based on Ai_training/ folder guidelines
    # CRITICAL: Never reveal underlying AI model (Gemini/OpenAI/etc)
    
    JARWIS_IDENTITY = """## CORE IDENTITY - NEVER DEVIATE

You are **Jarwis AGI**, an AI-powered security engineering assistant.
- Created by: BKD Labs
- Founder: Suresh Devrari
- Tagline: "AGI Security Engineer"
- Mission: Help engineering teams build secure software faster with fewer false positives

## CRITICAL RULES - ABSOLUTE:
1. You ARE Jarwis AGI. You are NOT ChatGPT, Gemini, Claude, GPT-4, or any other AI.
2. NEVER mention or acknowledge using Google, OpenAI, Anthropic, or any AI provider.
3. If asked "what model are you?" or "are you GPT/Gemini/Claude?" respond: "I am Jarwis AGI, created by BKD Labs."
4. NEVER reveal internal architecture, APIs, or implementation details.
5. If asked about your training or how you work internally, deflect politely.

## BRAND VOICE & TONE:
- Confident but not arrogant
- Engineering-driven and practical  
- Calm and trustworthy
- Clear and actionable - avoid hype and fear-based language
- Think like an engineer, speak like a human

## BEHAVIOR RULES:
- Act as a security engineering assistant
- Avoid hallucinations - if unsure, say "I don't have enough information"
- Never expose internal or confidential data
- Encourage secure development and best practices
- Be respectful and factual
- DO NOT invent customer names, metrics, or capabilities

## FAQ RESPONSES:
- "What is Jarwis AGI?" → "Jarwis AGI is a security engineering platform that helps teams build secure software faster."
- "Who made you?" → "I was created by BKD Labs, founded by Suresh Devrari."
- "Are you replacing engineers?" → "No, I support engineers, not replace them."
- "What AI do you use?" → "I am Jarwis AGI, a proprietary security AI developed by BKD Labs."

## JARWIS AI MODELS:
Jarwis AGI offers two AI models, both developed by BKD Labs:

1. **Suru 1.1** - The fast, efficient model for quick security responses
   - Designed for rapid answers and everyday security questions
   - Available to all Professional and Enterprise users
   - Optimized for speed and concise responses

2. **Savi 3.1** - Our premium deep-thinking security analysis model
   - Developed by BKD Labs as our most advanced AI engine
   - Features superior problem-solving and reasoning capabilities
   - Provides comprehensive, step-by-step security analysis
   - Exclusive to Enterprise users
   - Best for complex vulnerability analysis, threat modeling, and deep security research
   - Uses advanced reasoning techniques for thorough security assessments

When asked about models, explain these are proprietary BKD Labs models, NOT third-party AI.
"""

    SYSTEM_PROMPT_JARWIS = """""" + JARWIS_IDENTITY + """

## MODE: Quick Response
Provide concise, actionable security guidance.

## Response Style:
- Be concise and direct (under 200 words unless detail needed)
- Give quick actionable advice
- Use bullet points for clarity
- Focus on practical security recommendations

## Current Scan Context:
{scan_context}

## Recent Server Logs:
{server_logs}

Remember: You are Jarwis AGI. Stay focused on security testing. Quick, helpful responses."""

    SYSTEM_PROMPT_SAV = """""" + JARWIS_IDENTITY + """

## MODE: Deep Analysis (Savi 3.1 Thinking)
You are operating in Savi 3.1 Thinking mode - the deep-thinking security analysis mode of Jarwis AGI.
This is an Enterprise-exclusive feature for comprehensive security analysis.
Provide thorough, detailed analysis with step-by-step reasoning.

## Response Style:
- Think step-by-step through problems
- Provide detailed explanations with reasoning
- Include technical details and context
- Explain WHY something is a vulnerability
- Suggest multiple remediation approaches
- Cross-reference with OWASP guidelines
- Analyze attack vectors and impact
- Consider edge cases and related vulnerabilities

## Deep Analysis Format:
1. **Understanding**: Restate what was asked
2. **Analysis**: Deep dive into the security context
3. **Findings**: Detailed breakdown of vulnerabilities
4. **Impact Assessment**: Potential security impact
5. **Remediation**: Step-by-step fix recommendations
6. **Additional Considerations**: Related security concerns

## Current Scan Context:
{scan_context}

## Recent Server Logs:
{server_logs}

Remember: You are Jarwis AGI in Savi 3.1 Thinking mode. Provide comprehensive security analysis with deep reasoning."""

    OFF_TOPIC_RESPONSES = [
        "I'm focused on security testing. Let me help you with your vulnerability findings or security questions instead!",
        "That's outside my expertise. I'm here to help with security testing - do you have questions about your scan results?",
        "I specialize in penetration testing assistance. How can I help you understand your security findings?",
        "Let's stay focused on security testing. What would you like to know about your vulnerability findings?"
    ]
    
    # Patterns to detect identity probing
    IDENTITY_PROBE_PATTERNS = [
        r'\b(what model|which model|what ai|which ai|are you gpt|are you gemini|are you claude)\b',
        r'\b(openai|google ai|anthropic|chatgpt|gpt-4|gpt-3|gemini|claude)\b.*\b(using|running|powered)\b',
        r'\b(powered by|built on|based on|running on)\b.*\b(gpt|gemini|claude|openai|google)\b',
        r'\b(your (real|actual|true) (name|identity|model))\b',
        r'\b(reveal|tell me|what\'s) your (true|real|actual)\b',
    ]
    
    def __init__(self, config: dict):
        self.config = config
        self.ai_config = config.get('ai', {})
        # Use centralized AI config for defaults
        central_config = get_ai_config()
        self.provider = self.ai_config.get('provider', central_config.provider)
        self.model = self.ai_config.get('model', central_config.model)  # Suru 1.1 (default)
        self.model_thinking = self.ai_config.get('model_thinking', central_config.model_thinking)  # Savi 3.1 Thinking
        self.base_url = self.ai_config.get('base_url', central_config.base_url or '')
        self.api_key = self.ai_config.get('api_key', central_config.api_key)
        self._client = None
        self._gemini_model = None
        self._gemini_model_thinking = None  # For Savi 3.1 Thinking mode
        self._available = False
        # Session management - per-user isolation
        self._sessions: Dict[str, UserSession] = {}
        self._init_client()
    
    def _init_client(self):
        """Initialize the AI client based on provider"""
        # Gemini provider
        if self.provider in ["gemini", "google"]:
            if not GEMINI_AVAILABLE:
                logger.warning("google-generativeai package not installed")
                self._available = False
                return
            try:
                genai.configure(api_key=self.api_key)
                # Safety settings - allow security discussions
                safety_settings = [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
                ]
                # Suru 1.1 model (gemini-2.5-flash) - Quick responses for Pro users
                self._gemini_model = genai.GenerativeModel(
                    model_name=self.model,
                    safety_settings=safety_settings
                )
                # Savi 3.1 Thinking model (gemini-2.5-pro) - Deep analysis for Enterprise
                try:
                    self._gemini_model_thinking = genai.GenerativeModel(
                        model_name=self.model_thinking,
                        safety_settings=safety_settings
                    )
                    logger.info(f"Savi 3.1 Thinking model initialized ({self.model_thinking})")
                except Exception as e:
                    logger.warning(f"Savi 3.1 Thinking model not available: {e}")
                    self._gemini_model_thinking = self._gemini_model  # Fallback to Suru
                
                # Test connection
                self._gemini_model.generate_content("test")
                self._available = True
                logger.info(f"Jarwis Chatbot initialized - Suru 1.1 ({self.model}), Savi 3.1 ({self.model_thinking})")
            except Exception as e:
                logger.warning(f"Gemini not available for chatbot: {e}")
                self._available = False
        
        # Ollama provider (fallback)
        elif self.provider == "ollama":
            try:
                import ollama
                self._client = ollama.Client(host=self.base_url)
                self._client.list()
                self._available = True
                logger.info("Jarwis Chatbot connected to Ollama")
            except Exception as e:
                logger.warning(f"Ollama not available for chatbot: {e}")
                self._available = False
    
    @property
    def is_available(self) -> bool:
        return self._available
    
    def get_or_create_session(self, session_id: str, user_id: str = None) -> UserSession:
        """Get existing session or create new one"""
        if session_id not in self._sessions:
            self._sessions[session_id] = UserSession(
                session_id=session_id,
                user_id=user_id
            )
            logger.info(f"Created new chat session: {session_id}")
        else:
            self._sessions[session_id].last_activity = datetime.now().isoformat()
        return self._sessions[session_id]
    
    def set_scan_context(self, session_id: str, findings: List[dict], 
                         endpoints: List[dict] = None, scan_id: str = None,
                         server_logs: List[dict] = None):
        """Set the current scan context for a specific session"""
        session = self.get_or_create_session(session_id)
        
        # Track accessible scans for user isolation
        if scan_id and scan_id not in session.accessible_scans:
            session.accessible_scans.append(scan_id)
        
        session.scan_context = {
            'scan_id': scan_id,
            'findings_count': len(findings),
            'findings_summary': self._summarize_findings(findings),
            'findings_details': self._get_findings_details(findings),
            'endpoints_count': len(endpoints) if endpoints else 0,
            'vulnerability_types': self._get_vuln_types(findings),
            'severity_breakdown': self._get_severity_breakdown(findings)
        }
        
        # Store server logs (last 50)
        if server_logs:
            session.server_logs = server_logs[-50:]
    
    def _summarize_findings(self, findings: List[dict]) -> str:
        """Create a summary of findings for context"""
        if not findings:
            return "No vulnerabilities found yet."
        
        summary_parts = []
        for f in findings[:10]:  # Limit to first 10 for context
            summary_parts.append(f"- {f.get('title', 'Unknown')}: {f.get('severity', 'medium')} severity at {f.get('url', 'unknown URL')}")
        
        if len(findings) > 10:
            summary_parts.append(f"... and {len(findings) - 10} more findings")
        
        return "\n".join(summary_parts)
    
    def _get_findings_details(self, findings: List[dict]) -> List[dict]:
        """Get detailed findings for context (limited)"""
        details = []
        for f in findings[:15]:  # Limit to first 15 for context window
            details.append({
                'id': f.get('id', 'unknown'),
                'title': f.get('title', 'Unknown'),
                'category': f.get('category', 'Unknown'),
                'severity': f.get('severity', 'medium'),
                'url': f.get('url', ''),
                'description': f.get('description', '')[:200],  # Limit description length
                'remediation': f.get('remediation', '')[:200] if f.get('remediation') else ''
            })
        return details
    
    def _get_vuln_types(self, findings: List[dict]) -> List[str]:
        """Get unique vulnerability types"""
        types = set()
        for f in findings:
            types.add(f.get('category', 'Unknown'))
        return list(types)
    
    def _get_severity_breakdown(self, findings: List[dict]) -> dict:
        """Get count by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'medium').lower()
            if sev in breakdown:
                breakdown[sev] += 1
        return breakdown
    
    def _is_off_topic(self, message: str) -> bool:
        """Check if message is off-topic (not security/pentest related)"""
        off_topic_patterns = [
            r'\b(weather|recipe|cook|movie|music|sports|game|joke|story)\b',
            r'\b(poem|song|write me a|generate a story)\b',
            r'\b(girlfriend|boyfriend|dating|relationship)\b',
            r'\b(homework|math problem|calculate|equation)\b',
            r'\b(stock|crypto|bitcoin|trading|investment)\b',
            r'\b(travel|vacation|holiday|restaurant|food)\b',
            r'\b(celebrity|gossip|news|politics)\b',
            r'\b(write code for|build me a|create an app)\b',  # General coding requests
        ]
        
        # Security-related keywords that ALLOW the message
        security_keywords = [
            r'\b(security|vulnerability|attack|exploit|pentest|penetration)\b',
            r'\b(owasp|cve|xss|sqli|sql injection|csrf|idor)\b',
            r'\b(scan|finding|report|remediation|fix|patch)\b',
            r'\b(authentication|authorization|session|token|cookie)\b',
            r'\b(encryption|cryptography|hash|ssl|tls|certificate)\b',
            r'\b(injection|bypass|privilege|escalation|misconfiguration)\b',
            r'\b(api|endpoint|payload|header|request|response)\b',
            r'\b(firewall|waf|ids|ips|siem|log)\b',
            r'\b(malware|phishing|social engineering|brute force)\b',
            r'\b(network|port|dns|http|https|tcp|udp)\b',
            r'\b(mobile|android|ios|apk|application)\b',
            r'\b(cloud|aws|azure|gcp|s3|bucket)\b',
            r'\b(password|credential|secret|key|token)\b',
            r'\b(compliance|gdpr|pci|hipaa|soc2)\b',
        ]
        
        message_lower = message.lower()
        
        # First check if it contains security keywords - allow these
        for pattern in security_keywords:
            if re.search(pattern, message_lower):
                return False  # Not off-topic, it's security related
        
        # Check for off-topic patterns
        for pattern in off_topic_patterns:
            if re.search(pattern, message_lower):
                return True
        
        return False
    
    def _is_probing_internals(self, message: str) -> bool:
        """Check if user is trying to probe internal details"""
        probe_patterns = [
            r'\b(source code|algorithm|implementation|how do you work)\b',
            r'\b(show me your|reveal|expose|internal)\b',
            r'\b(payload|detection logic|scanning engine)\b',
            r'\b(bypass|trick|hack you|jailbreak)\b',
        ]
        
        message_lower = message.lower()
        for pattern in probe_patterns:
            if re.search(pattern, message_lower):
                return True
        return False
    
    def _is_identity_probe(self, message: str) -> bool:
        """Check if user is probing AI identity (GPT/Gemini/Claude)"""
        message_lower = message.lower()
        for pattern in self.IDENTITY_PROBE_PATTERNS:
            if re.search(pattern, message_lower):
                return True
        return False
    
    def _get_identity_response(self) -> str:
        """Return identity response - always Jarwis AGI"""
        responses = [
            "I am Jarwis AGI, a security engineering assistant created by BKD Labs. How can I help you with your security testing today?",
            "I'm Jarwis AGI, developed by BKD Labs to help engineering teams build secure software. What security questions do you have?",
            "My name is Jarwis AGI. I was created by BKD Labs, founded by Suresh Devrari. I'm here to help with your security testing needs.",
            "I am Jarwis AGI - your security engineering assistant from BKD Labs. Let me help you with penetration testing or vulnerability analysis!",
        ]
        import random
        return random.choice(responses)
    
    def _format_server_logs(self, logs: List[dict]) -> str:
        """Format server logs for context"""
        if not logs:
            return "No recent server logs available."
        
        formatted = []
        for log in logs[-20:]:  # Last 20 logs
            log_type = log.get('type', 'info')
            message = log.get('message', '')
            timestamp = log.get('timestamp', '')[:19]  # Trim to datetime
            formatted.append(f"[{timestamp}] {log_type.upper()}: {message}")
        
        return "\n".join(formatted)
    
    def _build_messages(self, user_message: str, session: UserSession, model_mode: str = "jarwis") -> List[dict]:
        """Build message list for LLM with session context"""
        
        # Format scan context
        scan_context_str = json.dumps(session.scan_context, indent=2) if session.scan_context else "No active scan"
        
        # Format server logs
        server_logs_str = self._format_server_logs(session.server_logs)
        
        # Select prompt based on model mode
        if model_mode == "sav":
            system_prompt = self.SYSTEM_PROMPT_SAV.format(
                scan_context=scan_context_str,
                server_logs=server_logs_str
            )
        else:
            system_prompt = self.SYSTEM_PROMPT_JARWIS.format(
                scan_context=scan_context_str,
                server_logs=server_logs_str
            )
        
        messages = [
            {
                "role": "system",
                "content": system_prompt
            }
        ]
        
        # Add conversation history (last 10 messages from session)
        for msg in session.conversation_history[-10:]:
            messages.append({
                "role": msg.role,
                "content": msg.content
            })
        
        # Add current message
        messages.append({
            "role": "user",
            "content": user_message
        })
        
        return messages
    
    def chat(self, user_message: str, session_id: str = "default", model_mode: str = "jarwis") -> Generator[str, None, None]:
        """
        Stream a chat response - yields chunks for typing effect
        Session-aware for user isolation
        model_mode: 'jarwis' for quick responses, 'sav' for deep analysis
        """
        session = self.get_or_create_session(session_id)
        
        # Store user message
        session.conversation_history.append(ChatMessage(
            role="user",
            content=user_message,
            timestamp=datetime.now().isoformat()
        ))
        
        # Check for off-topic
        if self._is_off_topic(user_message):
            import random
            response = random.choice(self.OFF_TOPIC_RESPONSES)
            for word in response.split():
                yield word + " "
                time.sleep(0.03)
            session.conversation_history.append(ChatMessage(
                role="assistant",
                content=response,
                timestamp=datetime.now().isoformat()
            ))
            return
        
        # Check for probing internals
        if self._is_probing_internals(user_message):
            response = "I'm here to help with security testing, but I can't share internal implementation details. How can I help you understand your vulnerability findings?"
            for word in response.split():
                yield word + " "
                time.sleep(0.03)
            session.conversation_history.append(ChatMessage(
                role="assistant",
                content=response,
                timestamp=datetime.now().isoformat()
            ))
            return
        
        # Check for AI identity probing (GPT/Gemini/Claude questions)
        if self._is_identity_probe(user_message):
            response = self._get_identity_response()
            for word in response.split():
                yield word + " "
                time.sleep(0.03)
            session.conversation_history.append(ChatMessage(
                role="assistant",
                content=response,
                timestamp=datetime.now().isoformat()
            ))
            return
        
        # If AI not available, return helpful fallback
        if not self._available:
            response = "I'm currently operating in offline mode. I can still help with general security questions! What would you like to know about your scan findings?"
            for word in response.split():
                yield word + " "
                time.sleep(0.03)
            return
        
        # Query LLM with streaming
        try:
            messages = self._build_messages(user_message, session, model_mode)
            
            # Adjust temperature based on mode
            temperature = 0.3 if model_mode == "sav" else 0.7  # Lower temp for more focused deep analysis
            
            full_response = ""
            
            # Gemini provider
            if self.provider in ["gemini", "google"] and self._gemini_model:
                # Combine system prompt and messages for Gemini
                system_msg = messages[0]['content'] if messages else ""
                conversation = "\n\n".join([
                    f"{m['role'].upper()}: {m['content']}" 
                    for m in messages[1:]
                ])
                full_prompt = f"{system_msg}\n\n{conversation}"
                
                # Select model based on mode
                # Savi 3.1 Thinking (Enterprise) = gemini-2.5-pro
                # Suru 1.1 (Pro) = gemini-2.5-flash
                selected_model = self._gemini_model_thinking if model_mode == "sav" else self._gemini_model
                
                # Gemini streaming
                response = selected_model.generate_content(
                    full_prompt,
                    stream=True,
                    generation_config={"temperature": temperature}
                )
                
                for chunk in response:
                    if hasattr(chunk, 'text') and chunk.text:
                        full_response += chunk.text
                        yield chunk.text
            
            # Ollama provider
            elif self.provider == "ollama" and self._client:
                stream = self._client.chat(
                    model=self.model,
                    messages=messages,
                    stream=True,
                    options={"temperature": temperature}
                )
                
                for chunk in stream:
                    if hasattr(chunk, 'message'):
                        content = chunk.message.content
                    elif isinstance(chunk, dict):
                        content = chunk.get('message', {}).get('content', '')
                    else:
                        continue
                    
                    if content:
                        full_response += content
                        yield content
            
            # Store assistant response
            session.conversation_history.append(ChatMessage(
                role="assistant",
                content=full_response,
                timestamp=datetime.now().isoformat()
            ))
            
        except Exception as e:
            logger.error(f"Chat error: {e}")
            error_response = "I encountered an error processing your request. Please try again."
            for word in error_response.split():
                yield word + " "
                time.sleep(0.03)
    
    def chat_sync(self, user_message: str, session_id: str = "default") -> str:
        """Non-streaming chat for simple use cases"""
        response_parts = []
        for chunk in self.chat(user_message, session_id):
            response_parts.append(chunk)
        return "".join(response_parts)
    
    def analyze_file(self, file_content: str, file_name: str, file_type: str, 
                     session_id: str = "default") -> Generator[str, None, None]:
        """Analyze an uploaded file in security context"""
        
        # Security-focused file analysis prompt
        file_preview = file_content[:3000]
        analysis_prompt = (
            "The user uploaded a file for security analysis.\n\n"
            f"File Name: {file_name}\n"
            f"File Type: {file_type}\n"
            "Content (first 3000 chars):\n"
            "---\n"
            f"{file_preview}\n"
            "---\n\n"
            "Analyze this file from a security perspective:\n"
            "1. Identify any security-relevant information\n"
            "2. Look for credentials, API keys, tokens, or sensitive data\n"
            "3. Note any security misconfigurations if it's a config file\n"
            "4. Relate it to the current scan findings if relevant\n\n"
            "Provide a helpful security-focused analysis. Do NOT reveal internal Jarwis implementation details."
        )
        
        return self.chat(analysis_prompt, session_id)
    
    def clear_history(self, session_id: str = "default"):
        """Clear conversation history for a session"""
        if session_id in self._sessions:
            self._sessions[session_id].conversation_history = []
    
    def get_history(self, session_id: str = "default") -> List[dict]:
        """Get conversation history as dicts for a session"""
        if session_id not in self._sessions:
            return []
        
        return [
            {
                "role": msg.role,
                "content": msg.content,
                "timestamp": msg.timestamp
            }
            for msg in self._sessions[session_id].conversation_history
        ]
    
    def can_access_scan(self, session_id: str, scan_id: str) -> bool:
        """Check if a session has access to a specific scan (for user isolation)"""
        if session_id not in self._sessions:
            return False
        return scan_id in self._sessions[session_id].accessible_scans


# Singleton instance for the chatbot
_chatbot_instance: Optional[JarwisChatbot] = None


def get_chatbot(config: dict = None) -> JarwisChatbot:
    """Get or create the chatbot instance"""
    global _chatbot_instance
    if _chatbot_instance is None and config:
        _chatbot_instance = JarwisChatbot(config)
    return _chatbot_instance


def init_chatbot(config: dict) -> JarwisChatbot:
    """Initialize the chatbot with config"""
    global _chatbot_instance
    _chatbot_instance = JarwisChatbot(config)
    return _chatbot_instance
