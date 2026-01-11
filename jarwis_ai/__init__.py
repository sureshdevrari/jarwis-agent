"""
Jarwis AI - Intelligent Security Analysis Engine

This is the core AI module for Jarwis penetration testing tool.
All AI components are contained in this single folder for easy management.

NO EXTERNAL LLM OR API REQUIRED - Pure algorithmic intelligence.

Components:
-----------
- JarwisAIEngine: Main AI engine with Bayesian scoring
- PatternMatcher: 49+ vulnerability detection patterns
- IntentClassifier: Chatbot intent routing
- CorrelationEngine: Attack chain detection
- FeedbackLearner: Self-learning from user feedback
- AdaptiveController: Scan optimization
- KnowledgeService: Vulnerability knowledge base
- AILearningService: Continuous learning service
- AIChatbot: Interactive security assistant

Usage:
------
    from jarwis_ai import JarwisAIEngine, PatternMatcher, KnowledgeService
    
    engine = JarwisAIEngine()
    result = engine.analyze(scan_data)
"""

# Lazy imports to avoid circular dependencies
def __getattr__(name):
    """Lazy loading of AI components"""
    if name == "JarwisAIEngine":
        from .engine import JarwisAIEngine
        return JarwisAIEngine
    elif name == "PatternMatcher":
        from .pattern_matcher import PatternMatcher
        return PatternMatcher
    elif name == "IntentClassifier":
        from .intent_classifier import IntentClassifier
        return IntentClassifier
    elif name == "CorrelationEngine":
        from .correlation_engine import CorrelationEngine
        return CorrelationEngine
    elif name == "FeedbackLearner":
        from .feedback_learner import FeedbackLearner
        return FeedbackLearner
    elif name == "AdaptiveController":
        from .adaptive_controller import AdaptiveController
        return AdaptiveController
    elif name == "AILearningService":
        from .learning_service import AILearningService
        return AILearningService
    elif name == "KnowledgeService":
        from .knowledge_service import KnowledgeService
        return KnowledgeService
    elif name == "AIChatbot":
        from .chatbot import AIChatbot
        return AIChatbot
    elif name == "AIPlanner":
        from .planner import AIPlanner
        return AIPlanner
    elif name == "AIVerifier":
        from .verifier import AIVerifier
        return AIVerifier
    elif name == "training":
        from . import training
        return training
    raise AttributeError(f"module 'jarwis_ai' has no attribute '{name}'")

__all__ = [
    # Core
    "JarwisAIEngine",
    
    # Analysis
    "PatternMatcher",
    "IntentClassifier",
    "CorrelationEngine",
    
    # Learning
    "FeedbackLearner",
    "AdaptiveController",
    "AILearningService",
    
    # Knowledge
    "KnowledgeService",
    
    # Chatbot
    "AIChatbot",
    
    # Planning
    "AIPlanner",
    "AIVerifier",
]

__version__ = "1.0.0"
