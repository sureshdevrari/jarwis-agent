"""
JARWIS AI Configuration - SINGLE SOURCE OF TRUTH

This file centralizes all AI/LLM configuration.
To change AI providers, ONLY edit this file.

Supported Providers:
- gemini (Google Gemini) - Default
- openai (OpenAI GPT)
- custom (Your own model - see add_custom_provider())

Usage:
    from shared.ai_config import get_ai_config, AIProvider
    
    config = get_ai_config()
    print(config.provider)  # "gemini"
    print(config.model)     # "gemini-1.5-flash"
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class AIProvider(Enum):
    """Supported AI Providers"""
    GEMINI = "gemini"
    OPENAI = "openai"
    CUSTOM = "custom"


@dataclass
class AIConfig:
    """
    Centralized AI Configuration
    
    To switch providers, change DEFAULT_PROVIDER below.
    To add a custom provider, use register_custom_provider().
    """
    
    # ========================================
    # CHANGE THESE TO SWITCH AI PROVIDERS
    # ========================================
    DEFAULT_PROVIDER: str = "gemini"
    DEFAULT_MODEL: str = "gemini-1.5-flash"
    
    # Provider-specific model mappings
    PROVIDER_MODELS: Dict[str, str] = field(default_factory=lambda: {
        "gemini": "gemini-1.5-flash",
        "openai": "gpt-4o-mini",
        "custom": "your-model-name",
    })
    
    # ========================================
    # Configuration (loaded from env/.env)
    # ========================================
    provider: str = ""
    model: str = ""
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.3
    
    # Feature flags
    request_analysis: bool = True
    verify_findings: bool = True
    chatbot_enabled: bool = True
    
    def __post_init__(self):
        """Load configuration from environment variables"""
        # Provider (from env or default)
        self.provider = os.getenv("AI_PROVIDER", self.DEFAULT_PROVIDER).lower()
        
        # Model (from env or provider-specific default)
        self.model = os.getenv("AI_MODEL", self.PROVIDER_MODELS.get(self.provider, self.DEFAULT_MODEL))
        
        # API Keys (check provider-specific first, then generic)
        if self.provider == "gemini":
            self.api_key = os.getenv("GEMINI_API_KEY")
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY")
        else:
            self.api_key = os.getenv("AI_API_KEY") or os.getenv("CUSTOM_API_KEY")
        
        # Fallback to generic key
        if not self.api_key:
            self.api_key = os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
        
        # Base URL (for custom/self-hosted models)
        self.base_url = os.getenv("AI_BASE_URL")
        
        # Optional settings from env
        self.max_tokens = int(os.getenv("AI_MAX_TOKENS", "4096"))
        self.temperature = float(os.getenv("AI_TEMPERATURE", "0.3"))
        
        logger.info(f"AI Config loaded: provider={self.provider}, model={self.model}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for passing to other modules"""
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }
    
    def get_client_config(self) -> Dict[str, Any]:
        """Get config formatted for AI client initialization"""
        return {
            "provider": self.provider,
            "model": self.model,
            "api_key": self.api_key,
            "base_url": self.base_url,
        }


# ========================================
# CUSTOM PROVIDER REGISTRY
# ========================================

_custom_providers: Dict[str, Callable] = {}


def register_custom_provider(name: str, client_factory: Callable):
    """
    Register a custom AI provider.
    
    Example:
        def my_custom_client(config: AIConfig):
            return MyCustomAIClient(api_key=config.api_key)
        
        register_custom_provider("my_model", my_custom_client)
    
    Then set AI_PROVIDER=my_model in .env
    """
    _custom_providers[name.lower()] = client_factory
    logger.info(f"Registered custom AI provider: {name}")


def get_custom_provider(name: str) -> Optional[Callable]:
    """Get a registered custom provider factory"""
    return _custom_providers.get(name.lower())


def list_custom_providers() -> list:
    """List all registered custom providers"""
    return list(_custom_providers.keys())


# ========================================
# GLOBAL CONFIG INSTANCE
# ========================================

_ai_config: Optional[AIConfig] = None


def get_ai_config() -> AIConfig:
    """
    Get the global AI configuration instance.
    
    Usage:
        from shared.ai_config import get_ai_config
        
        config = get_ai_config()
        print(config.provider)  # "gemini"
    """
    global _ai_config
    if _ai_config is None:
        _ai_config = AIConfig()
    return _ai_config


def reload_ai_config() -> AIConfig:
    """Reload AI configuration (useful after changing env vars)"""
    global _ai_config
    _ai_config = AIConfig()
    return _ai_config


# ========================================
# CONVENIENCE FUNCTIONS
# ========================================

def get_provider() -> str:
    """Get current AI provider name"""
    return get_ai_config().provider


def get_model() -> str:
    """Get current AI model name"""
    return get_ai_config().model


def get_api_key() -> Optional[str]:
    """Get current AI API key"""
    return get_ai_config().api_key


def is_ai_available() -> bool:
    """Check if AI is properly configured"""
    config = get_ai_config()
    return bool(config.api_key and config.provider)


# ========================================
# HOW TO ADD YOUR OWN AI MODEL
# ========================================
"""
To add your own custom AI model:

1. Set environment variables in .env:
   AI_PROVIDER=custom
   AI_MODEL=your-model-name
   AI_API_KEY=your-api-key
   AI_BASE_URL=http://your-model-server:8080

2. (Optional) Register a custom client factory:
   
   from shared.ai_config import register_custom_provider
   
   def my_model_client(config):
       import requests
       class MyClient:
           def chat(self, messages):
               response = requests.post(
                   f"{config.base_url}/chat",
                   json={"messages": messages},
                   headers={"Authorization": f"Bearer {config.api_key}"}
               )
               return response.json()
       return MyClient()
   
   register_custom_provider("my_model", my_model_client)

3. Restart the server - your model will be used!
"""
