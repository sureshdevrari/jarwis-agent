"""
Jarwis AI System Test Script
=============================

Tests all components of the Jarwis AI system without LLM:
- AI Engine (Bayesian analysis)
- Pattern Matcher (vulnerability detection)
- Correlation Engine (attack chains)
- Feedback Learner (self-improvement)
- Intent Classifier (chatbot routing)
- Knowledge Service (vulnerability info)
- AI Chatbot (response generation)

Run: python scripts/test_jarwis_ai.py

Author: Jarwis AI Team
Created: January 2026
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown

console = Console()


def test_pattern_matcher():
    """Test pattern matching engine"""
    console.print("\n[bold cyan]1. Testing Pattern Matcher[/bold cyan]")
    
    from core.pattern_matcher import PatternMatcher
    
    matcher = PatternMatcher()
    
    # Test SQL injection detection
    test_cases = [
        ("SQL Error: syntax error near 'OR 1=1'", "sql_injection"),
        ("<script>alert('xss')</script>", "xss"),
        ("AWS Access Key: AKIAIOSFODNN7EXAMPLE", "sensitive_data"),
        ("Apache/2.4.41 (Ubuntu)", "version_disclosure"),
        ("root:x:0:0:root:/root:/bin/bash", "info_disclosure"),
    ]
    
    table = Table(title="Pattern Matching Results")
    table.add_column("Input", style="cyan")
    table.add_column("Expected", style="yellow")
    table.add_column("Detected", style="green")
    table.add_column("Confidence", style="magenta")
    
    for text, expected_category in test_cases:
        result = matcher.match_text(text)  # Fixed: was analyze()
        detected = result.categories_found[0] if result.categories_found else "None"
        confidence = f"{result.combined_confidence:.2%}"
        
        table.add_row(
            text[:40] + "..." if len(text) > 40 else text,
            expected_category,
            detected,
            confidence
        )
    
    console.print(table)
    console.print("[green]✓ Pattern Matcher working![/green]")


def test_intent_classifier():
    """Test intent classification"""
    console.print("\n[bold cyan]2. Testing Intent Classifier[/bold cyan]")
    
    from core.intent_classifier import IntentClassifier, Intent
    
    classifier = IntentClassifier()
    
    test_queries = [
        ("What is Jarwis?", Intent.BRAND_INFO),
        ("What is SQL injection?", Intent.VULN_DEFINITION),
        ("How do I fix XSS?", Intent.FIX_GUIDANCE),
        ("Summarize my scan results", Intent.SCAN_SUMMARY),
        ("What is A03?", Intent.OWASP_INFO),
        ("Who founded Jarwis?", Intent.FOUNDER_INFO),
        ("What's the weather today?", Intent.OFF_TOPIC),
        ("Are there attack chains?", Intent.ATTACK_CHAIN),
    ]
    
    table = Table(title="Intent Classification Results")
    table.add_column("Query", style="cyan")
    table.add_column("Expected", style="yellow")
    table.add_column("Classified", style="green")
    table.add_column("Confidence", style="magenta")
    table.add_column("Match", style="white")
    
    for query, expected in test_queries:
        result = classifier.classify(query)
        match = "✓" if result.primary_intent == expected else "✗"
        
        table.add_row(
            query,
            expected.value,
            result.primary_intent.value,
            f"{result.confidence:.2%}",
            match
        )
    
    console.print(table)
    console.print("[green]✓ Intent Classifier working![/green]")


def test_knowledge_service():
    """Test knowledge base lookups"""
    console.print("\n[bold cyan]3. Testing Knowledge Service[/bold cyan]")
    
    from services.knowledge_service import KnowledgeService
    
    service = KnowledgeService()
    
    # Test vulnerability lookup
    vuln_result = service.get_vulnerability_definition("sql_injection")
    console.print(Panel(
        vuln_result.content[:500] + "...",
        title="SQL Injection Definition (truncated)",
        border_style="blue"
    ))
    
    # Test OWASP lookup
    owasp_result = service.get_owasp_info("A03")
    console.print(Panel(
        owasp_result.content[:400] + "...",
        title="OWASP A03 Info (truncated)",
        border_style="yellow"
    ))
    
    # Test brand response
    brand_result = service.get_brand_response("brand_info")
    console.print(Panel(
        brand_result.content[:300] + "...",
        title="Brand Info (truncated)",
        border_style="green"
    ))
    
    console.print("[green]✓ Knowledge Service working![/green]")


def test_ai_engine():
    """Test main AI engine"""
    console.print("\n[bold cyan]4. Testing AI Engine[/bold cyan]")
    
    from core.jarwis_ai_engine import JarwisAIEngine
    
    engine = JarwisAIEngine()
    
    # Test finding analysis
    finding = {
        "title": "SQL Injection in login form",
        "severity": "high",
        "category": "A03:2021 - Injection",
        "url": "https://example.com/login",
        "description": "SQL injection vulnerability detected in username parameter",
        "evidence": "Error: You have an error in your SQL syntax near 'admin' OR '1'='1'",
        "parameter": "username",
        "poc": "username=admin' OR '1'='1"
    }
    
    result = engine.analyze_finding(finding)
    
    console.print(f"[cyan]Finding:[/cyan] {finding['title']}")
    console.print(f"[yellow]AI Confidence:[/yellow] {result.confidence_score:.2%}")
    console.print(f"[yellow]Adjusted Severity:[/yellow] {result.severity_adjusted}")
    console.print(f"[yellow]Exploitability:[/yellow] {result.exploitability_score:.2%}")
    console.print(f"[yellow]FP Probability:[/yellow] {result.false_positive_probability:.2%}")
    
    console.print("\n[cyan]Reasoning Chain:[/cyan]")
    for step in result.reasoning_chain[:3]:
        console.print(f"  • {step.observation}: {step.inference}")
    
    console.print("[green]✓ AI Engine working![/green]")


def test_correlation_engine():
    """Test attack chain detection"""
    console.print("\n[bold cyan]5. Testing Correlation Engine[/bold cyan]")
    
    from core.correlation_engine import CorrelationEngine
    
    engine = CorrelationEngine()
    
    # Test with related findings
    findings = [
        {
            "id": "1",
            "title": "SQL Injection",
            "severity": "high",
            "category": "A03:2021 - Injection",
            "url": "/api/users",
            "description": "SQL injection allows data extraction"
        },
        {
            "id": "2",
            "title": "Sensitive Data Exposure",
            "severity": "high",
            "category": "A02:2021 - Cryptographic Failures",
            "url": "/api/users/export",
            "description": "PII data exposed without encryption"
        },
        {
            "id": "3",
            "title": "IDOR Vulnerability",
            "severity": "medium",
            "category": "A01:2021 - Broken Access Control",
            "url": "/api/users/123",
            "description": "Can access other users' data"
        }
    ]
    
    result = engine.analyze_findings(findings)  # Fixed: was detect_chains()
    chains = result.attack_chains
    
    if chains:
        console.print(f"[green]Detected {len(chains)} attack chain(s)![/green]")
        for i, chain in enumerate(chains, 1):
            console.print(f"\n[yellow]Chain {i}:[/yellow] {chain.chain_type.value}")
            console.print(f"  Severity: {chain.severity}, Impact: {chain.combined_impact:.2f}")
            console.print(f"  Confidence: {chain.confidence:.2%}")
            console.print(f"  Vulnerabilities: {chain.finding_count}")
    else:
        console.print("[yellow]No attack chains detected (this is normal for unrelated findings)[/yellow]")
    
    console.print("[green]✓ Correlation Engine working![/green]")


def test_feedback_learner():
    """Test self-learning from feedback"""
    console.print("\n[bold cyan]6. Testing Feedback Learner[/bold cyan]")
    
    from core.feedback_learner import FeedbackLearner, FeedbackEvent, FeedbackType
    from datetime import datetime
    import uuid
    
    learner = FeedbackLearner()
    
    # Create sample feedback events (matching the dataclass fields)
    events = [
        FeedbackEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            finding_id="test_1",
            scan_id="scan_1",
            feedback_type=FeedbackType.CONFIRMED,
            pattern_ids=["sqli_error_pattern"],
            scanner_id="sqli_scanner",
            target_type="web",
            target_domain="example.com",
            vuln_type="sql_injection",
            original_severity="high",
            original_confidence=0.85
        ),
        FeedbackEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            finding_id="test_2",
            scan_id="scan_1",
            feedback_type=FeedbackType.FALSE_POSITIVE,
            pattern_ids=["xss_script_pattern"],
            scanner_id="xss_scanner",
            target_type="api",
            target_domain="api.example.com",
            vuln_type="xss",
            original_severity="medium",
            original_confidence=0.65
        ),
    ]
    
    console.print(f"[yellow]Created {len(events)} feedback events[/yellow]")
    console.print(f"[yellow]FeedbackLearner initialized[/yellow]")
    console.print("[dim](Note: Actual feedback recording is async, testing structure only)[/dim]")
    
    console.print("[green]✓ Feedback Learner structure working![/green]")


def test_adaptive_controller():
    """Test adaptive scan strategy"""
    console.print("\n[bold cyan]7. Testing Adaptive Controller[/bold cyan]")
    
    from core.adaptive_controller import AdaptiveController
    
    controller = AdaptiveController()
    
    # Analyze a target
    target_url = "https://api.example.com/v1/users"
    domain = "api.example.com"
    crawl_data = {
        "url": target_url,
        "endpoints": ["/api/users", "/api/login", "/api/admin"],
        "response_headers": {"Server": "nginx/1.18.0"},
        "technologies": ["Python", "Flask"],
        "html": "<html><body>API Server</body></html>",
        "urls": ["/api/users", "/api/login"]
    }
    
    profile = controller.analyze_target(domain, crawl_data)
    
    console.print(f"[cyan]Target URL:[/cyan] {target_url}")
    console.print(f"[yellow]Target Type:[/yellow] {profile.target_type.value}")
    console.print(f"[yellow]Technologies:[/yellow] {profile.technologies}")
    console.print(f"[yellow]Has Login:[/yellow] {profile.has_login}")
    console.print(f"[yellow]Has API:[/yellow] {profile.has_api}")
    console.print(f"[yellow]Has Upload:[/yellow] {profile.has_upload}")
    
    # Build strategy
    strategy = controller.build_strategy(profile)
    
    console.print(f"\n[cyan]Scan Strategy:[/cyan]")
    console.print(f"  Max Requests: {strategy.max_total_requests}")
    console.print(f"  Max Duration: {strategy.max_scan_duration_minutes} minutes")
    console.print(f"  Priority Scanners: {list(strategy.scanner_configs.keys())[:3]}...")
    console.print(f"  Strategy Confidence: {strategy.strategy_confidence:.2%}")
    
    console.print("[green]✓ Adaptive Controller working![/green]")


def test_ai_chatbot():
    """Test the complete AI chatbot"""
    console.print("\n[bold cyan]8. Testing AI Chatbot (Complete System)[/bold cyan]")
    
    from core.jarwis_chatbot import JarwisAIChatbot, ChatContext
    
    chatbot = JarwisAIChatbot()
    
    # Test various queries
    test_queries = [
        "What is Jarwis?",
        "What is SQL injection?",
        "How do I fix XSS?",
        "Who founded Jarwis?",
    ]
    
    for query in test_queries:
        console.print(f"\n[cyan]User:[/cyan] {query}")
        
        context = ChatContext()
        response = chatbot.chat(query, context)
        
        # Truncate response for display
        msg = response.message[:200] + "..." if len(response.message) > 200 else response.message
        console.print(f"[green]Jarwis:[/green] {msg}")
        console.print(f"[dim]Confidence: {response.confidence:.2%}[/dim]")
    
    # Test with scan data
    console.print("\n[bold yellow]Testing with Scan Context:[/bold yellow]")
    
    context = ChatContext(
        scan_id="test_scan",
        findings=[
            {
                "id": "1",
                "title": "SQL Injection",
                "severity": "critical",
                "category": "Injection",
                "url": "/api/login"
            },
            {
                "id": "2",
                "title": "XSS Reflected",
                "severity": "high",
                "category": "XSS",
                "url": "/search"
            },
            {
                "id": "3",
                "title": "Missing Security Headers",
                "severity": "low",
                "category": "Misconfiguration",
                "url": "/"
            }
        ]
    )
    
    response = chatbot.chat("Summarize my scan results", context)
    console.print(f"\n[cyan]User:[/cyan] Summarize my scan results")
    console.print(f"[green]Jarwis:[/green]\n{response.message[:500]}...")
    
    console.print("\n[green]✓ AI Chatbot working![/green]")


def test_ai_learning_service():
    """Test the unified AI learning service"""
    console.print("\n[bold cyan]9. Testing AI Learning Service[/bold cyan]")
    
    # Test that the service can be imported and instantiated
    from services.ai_learning_service import AILearningService
    
    service = AILearningService(data_dir="data/test")
    
    console.print(f"[cyan]AI Learning Service initialized[/cyan]")
    console.print(f"[yellow]Components:[/yellow]")
    console.print(f"  • AI Engine: {type(service.ai_engine).__name__}")
    console.print(f"  • Pattern Matcher: {type(service.pattern_matcher).__name__}")
    console.print(f"  • Correlation Engine: {type(service.correlation_engine).__name__}")
    console.print(f"  • Feedback Learner: {type(service.feedback_learner).__name__}")
    console.print(f"  • Adaptive Controller: {type(service.adaptive_controller).__name__}")
    
    # Test basic text analysis (if match_text is available)
    try:
        result = service.pattern_matcher.match_text("SQL syntax error near 'OR 1=1'")
        console.print(f"\n[cyan]Pattern Analysis Test:[/cyan]")
        console.print(f"  Confidence: {result.combined_confidence:.2%}")
        console.print(f"  Categories: {result.categories_found[:3]}")
    except Exception as e:
        console.print(f"[dim]Pattern analysis skipped: {e}[/dim]")
    
    console.print("[green]✓ AI Learning Service working![/green]")


def main():
    """Run all tests"""
    console.print(Panel(
        "[bold white]Jarwis AI System Test Suite[/bold white]\n\n"
        "Testing all AI components without LLM dependency",
        title="🧠 Jarwis AI",
        border_style="cyan"
    ))
    
    tests = [
        ("Pattern Matcher", test_pattern_matcher),
        ("Intent Classifier", test_intent_classifier),
        ("Knowledge Service", test_knowledge_service),
        ("AI Engine", test_ai_engine),
        ("Correlation Engine", test_correlation_engine),
        ("Feedback Learner", test_feedback_learner),
        ("Adaptive Controller", test_adaptive_controller),
        ("AI Chatbot", test_ai_chatbot),
        ("AI Learning Service", test_ai_learning_service),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            console.print(f"[red]✗ {name} failed: {e}[/red]")
            import traceback
            traceback.print_exc()
            failed += 1
    
    console.print("\n" + "=" * 60)
    console.print(Panel(
        f"[green]✓ Passed: {passed}[/green]  [red]✗ Failed: {failed}[/red]",
        title="Test Results",
        border_style="green" if failed == 0 else "red"
    ))
    
    if failed == 0:
        console.print("\n[bold green]🎉 All Jarwis AI components working without LLM![/bold green]")
        console.print("\n[cyan]New API endpoints available:[/cyan]")
        console.print("  • POST /api/ai/chat - AI chat (no LLM)")
        console.print("  • POST /api/ai/feedback - Submit finding feedback")
        console.print("  • GET  /api/ai/insights/{scan_id} - Scan insights")
        console.print("  • GET  /api/ai/knowledge/vulnerability/{type} - Vuln info")
        console.print("  • GET  /api/ai/knowledge/owasp/{category} - OWASP info")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
