"""
Jarwis AI Planner - Amazon Bedrock Integration
Add this code to core/ai_planner.py to enable Bedrock support

This file contains the code changes needed to replace Ollama with Amazon Bedrock.
"""

# ============================================================================
# STEP 1: Add these imports at the top of core/ai_planner.py
# ============================================================================

# Add to existing imports:
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError


# ============================================================================
# STEP 2: Update the AIPlanner.__init__ method
# ============================================================================

def __init__(
    self,
    provider: str = "bedrock",  # Changed default from "ollama" to "bedrock"
    model: str = "anthropic.claude-3-5-sonnet-20241022-v2:0",  # Bedrock model ID
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    aws_region: str = "us-east-1"
):
    """
    Initialize the Jarwis AI Planner.
    
    Args:
        provider: AI provider - "bedrock", "ollama", or "openai"
        model: Model identifier
            - For Bedrock: "anthropic.claude-3-5-sonnet-20241022-v2:0"
            - For Ollama: "jarwis" or "llama3.1"
            - For OpenAI: "gpt-4" or "gpt-3.5-turbo"
        api_key: API key (for OpenAI only)
        base_url: Base URL (for Ollama - default http://localhost:11434)
        aws_region: AWS region for Bedrock (default us-east-1)
    """
    self.provider = provider
    self.model = model
    self.api_key = api_key
    self.base_url = base_url or "http://localhost:11434"
    self.aws_region = aws_region
    self._client = None
    self._init_client()


# ============================================================================
# STEP 3: Update the _init_client method to support Bedrock
# ============================================================================

def _init_client(self):
    """Initialize the Jarwis intelligence engine"""
    
    if self.provider == "bedrock":
        try:
            # Configure boto3 for Bedrock with retry logic
            config = Config(
                region_name=self.aws_region,
                retries={
                    'max_attempts': 3,
                    'mode': 'adaptive'
                },
                connect_timeout=10,
                read_timeout=60
            )
            
            self._client = boto3.client(
                'bedrock-runtime',
                config=config
            )
            
            # Test connection by checking if we can access Bedrock
            logger.info(f"Jarwis Bedrock client initialized with model: {self.model}")
            logger.info(f"AWS Region: {self.aws_region}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}")
            logger.warning("Jarwis will use heuristic-based analysis instead.")
            self._client = None
            
    elif self.provider == "ollama":
        # ... existing Ollama code stays the same ...
        try:
            import ollama
            self._client = ollama.Client(host=self.base_url)
            # ... rest of existing Ollama initialization ...
        except ImportError:
            logger.warning("Ollama not installed, Jarwis using heuristic responses")
            self._client = None
            
    elif self.provider == "openai":
        try:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)
        except ImportError:
            logger.warning("OpenAI not installed, Jarwis using heuristic responses")


# ============================================================================
# STEP 4: Add the Bedrock chat method
# ============================================================================

async def _bedrock_chat(self, messages: List[Dict], max_tokens: int = 4096) -> str:
    """
    Send chat request to Amazon Bedrock.
    
    Args:
        messages: List of message dicts with 'role' and 'content'
        max_tokens: Maximum tokens in response
        
    Returns:
        Response text from the model
    """
    import json
    
    # Separate system message from conversation
    system_message = ""
    formatted_messages = []
    
    for msg in messages:
        if msg["role"] == "system":
            system_message = msg["content"]
        else:
            formatted_messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })
    
    # Build request body for Claude on Bedrock
    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": formatted_messages
    }
    
    # Add system message if present
    if system_message:
        request_body["system"] = system_message
    
    try:
        self._log('jarwis', 'Sending request to Amazon Bedrock...')
        
        response = self._client.invoke_model(
            modelId=self.model,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(request_body)
        )
        
        # Parse response
        response_body = json.loads(response['body'].read())
        
        # Extract text from Claude response format
        if 'content' in response_body and len(response_body['content']) > 0:
            text = response_body['content'][0]['text']
            self._log('success', 'Received response from Bedrock')
            return text
        else:
            logger.error(f"Unexpected Bedrock response format: {response_body}")
            return ""
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'AccessDeniedException':
            logger.error(f"Bedrock access denied. Ensure model access is enabled: {error_message}")
        elif error_code == 'ThrottlingException':
            logger.warning(f"Bedrock rate limited, retrying...")
        elif error_code == 'ModelNotReadyException':
            logger.error(f"Model not ready: {error_message}")
        else:
            logger.error(f"Bedrock API error ({error_code}): {error_message}")
        
        raise
        
    except Exception as e:
        logger.error(f"Bedrock request failed: {e}")
        raise


# ============================================================================
# STEP 5: Update the get_next_test method to use Bedrock
# ============================================================================

async def get_next_test(self, context: Dict) -> Optional[TestRecommendation]:
    """Get the next recommended security test from Jarwis"""
    
    prompt = self._build_prompt(context)
    
    messages = [
        {"role": "system", "content": self.SYSTEM_PROMPT},
        {"role": "user", "content": prompt}
    ]
    
    try:
        if self._client is None:
            return self._heuristic_next_test(context)
        
        if self.provider == "bedrock":
            response_text = await self._bedrock_chat(messages)
            
        elif self.provider == "ollama":
            response = self._client.chat(
                model=self.model,
                messages=messages
            )
            if hasattr(response, 'message'):
                response_text = response.message.content
            elif isinstance(response, dict):
                response_text = response['message']['content']
            else:
                return self._heuristic_next_test(context)
                
        elif self.provider == "openai":
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            response_text = response.choices[0].message.content
        
        # Parse the JSON response
        result = self._parse_response(response_text)
        
        if result and 'complete' not in result:
            return TestRecommendation(
                tool=result.get('tool', 'manual'),
                target=result.get('target', ''),
                method=result.get('method', 'GET'),
                param=result.get('param', ''),
                payload_type=result.get('payload_type', ''),
                reason=result.get('reason', ''),
                priority=result.get('priority', 5)
            )
        
        return None
        
    except Exception as e:
        logger.error(f"AI planning failed: {e}")
        return self._heuristic_next_test(context)


# ============================================================================
# STEP 6: Environment Variables Configuration
# ============================================================================
"""
Set these environment variables for Bedrock:

# Required - tells ai_planner to use Bedrock
AI_PROVIDER=bedrock

# Optional - defaults to Claude 3.5 Sonnet
AI_MODEL=anthropic.claude-3-5-sonnet-20241022-v2:0

# Optional - defaults to us-east-1
AWS_REGION=us-east-1

# AWS credentials (handled automatically by IAM roles in ECS)
# Only needed for local development:
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
"""


# ============================================================================
# STEP 7: Update config loading to read from environment
# ============================================================================

import os

def get_ai_config() -> dict:
    """Get AI configuration from environment variables"""
    return {
        'provider': os.getenv('AI_PROVIDER', 'bedrock'),
        'model': os.getenv('AI_MODEL', 'anthropic.claude-3-5-sonnet-20241022-v2:0'),
        'aws_region': os.getenv('AWS_REGION', 'us-east-1'),
        'api_key': os.getenv('OPENAI_API_KEY'),  # For OpenAI fallback
        'base_url': os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
    }


# ============================================================================
# USAGE EXAMPLE
# ============================================================================
"""
# Create AIPlanner with Bedrock
from core.ai_planner import AIPlanner

# Using Bedrock (recommended for AWS deployment)
planner = AIPlanner(
    provider="bedrock",
    model="anthropic.claude-3-5-sonnet-20241022-v2:0",
    aws_region="us-east-1"
)

# Analyze a website
analysis = await planner.analyze_website(
    html_content="<html>...</html>",
    url="https://example.com",
    page_title="Example Site"
)

# Get next test recommendation
context = {
    "endpoints": [...],
    "findings": [...],
    "tested_params": [...]
}
recommendation = await planner.get_next_test(context)
"""
