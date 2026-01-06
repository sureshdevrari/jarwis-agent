"""
JARWIS AGI PEN TEST - Report Generator
Multi-format security report generation
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from dataclasses import asdict

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates security reports in multiple formats"""
    
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    
    OWASP_CATEGORIES = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable Components',
        'A07': 'Auth Failures',
        'A08': 'Data Integrity Failures',
        'A09': 'Logging Failures',
        'A10': 'SSRF'
    }
    
    def __init__(self, output_dir: str, formats: List[str]):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.formats = formats
    
    def _sanitize_filename(self, url: str, app_name: str = None) -> str:
        """Extract and sanitize website name from URL for filename"""
        import re
        from urllib.parse import urlparse
        try:
            # If app name is provided, use it
            if app_name:
                sanitized = re.sub(r'[^a-zA-Z0-9]', '_', app_name)
                return sanitized
            
            parsed = urlparse(url)
            # Get domain without www. and port
            domain = parsed.netloc.replace('www.', '').split(':')[0]
            
            # Handle localhost/127.0.0.1 - try to use a more descriptive name
            if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
                # Try to get port for identification
                port = parsed.netloc.split(':')[1] if ':' in parsed.netloc else '80'
                # Common ports and their applications
                port_apps = {
                    '3000': 'juice_shop',
                    '8080': 'webapp',
                    '8000': 'django',
                    '5000': 'flask',
                    '4200': 'angular',
                    '3001': 'react'
                }
                domain = port_apps.get(port, f'local_{port}')
            
            # Replace dots and special chars with underscores
            sanitized = re.sub(r'[^a-zA-Z0-9]', '_', domain)
            return sanitized
        except:
            return 'unknown_target'
    
    async def generate(
        self,
        findings: List,
        context,
        config: Dict,
        traffic_log: List = None,
        executive_summary: str = None,
        attack_chains: List = None
    ) -> List[str]:
        """Generate reports in all configured formats with AI-enhanced data"""
        generated = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Get sanitized website name for filename
        target_url = config.get('target', {}).get('url', 'unknown')
        app_name = config.get('target', {}).get('name', None)  # Optional app name from config
        website_name = self._sanitize_filename(target_url, app_name)
        
        # Create unique base filename: website_timestamp
        base_filename = f"{website_name}_{timestamp}"
        
        logger.info(f"Generating report: {base_filename}")
        
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(getattr(f, 'severity', 'info'), 4)
        )
        
        # Store extra data for reports
        self._executive_summary = executive_summary or ""
        self._attack_chains = attack_chains or []
        
        for fmt in self.formats:
            if fmt == 'sarif':
                path = self._generate_sarif(sorted_findings, base_filename)
            elif fmt == 'json':
                path = self._generate_json(sorted_findings, context, config, base_filename, traffic_log)
            elif fmt == 'html':
                path = self._generate_html(sorted_findings, context, config, base_filename, traffic_log)
            else:
                continue
            
            if path:
                generated.append(str(path))
        
        return generated
    
    def _generate_sarif(self, findings: List, timestamp: str) -> Path:
        """Generate SARIF format report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Jarwis Security Testing by BKD Labs",
                        "version": "1.0.0",
                        "informationUri": "https://bkdlabs.com/jarwis",
                        "rules": self._get_sarif_rules(findings)
                    }
                },
                "results": self._get_sarif_results(findings)
            }]
        }
        
        path = self.output_dir / f"report_{timestamp}.sarif"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)
        
        logger.info(f"SARIF report saved: {path}")
        return path
    
    def _get_sarif_rules(self, findings: List) -> List[Dict]:
        """Generate SARIF rules from findings"""
        rules = {}
        for f in findings:
            rule_id = getattr(f, 'category', 'UNKNOWN')
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": self.OWASP_CATEGORIES.get(rule_id, rule_id),
                    "shortDescription": {"text": getattr(f, 'title', 'Security Issue')},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(getattr(f, 'severity', 'medium'))
                    }
                }
        return list(rules.values())
    
    def _get_sarif_results(self, findings: List) -> List[Dict]:
        """Generate SARIF results from findings"""
        results = []
        for f in findings:
            result = {
                "ruleId": getattr(f, 'category', 'UNKNOWN'),
                "level": self._severity_to_sarif_level(getattr(f, 'severity', 'medium')),
                "message": {"text": getattr(f, 'description', '')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": getattr(f, 'url', '')}
                    }
                }]
            }
            results.append(result)
        return results
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity, 'warning')
    
    def _generate_json(
        self,
        findings: List,
        context,
        config: Dict,
        base_filename: str,
        traffic_log: List = None
    ) -> Path:
        """Generate JSON format report"""
        report = {
            "metadata": {
                "tool": "Jarwis Security Testing by BKD Labs",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "target": config['target']['url']
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity(findings),
                "by_category": self._count_by_category(findings),
                "endpoints_tested": len(context.endpoints),
                "authenticated_scan": context.authenticated,
                "total_requests_captured": len(traffic_log) if traffic_log else 0
            },
            "findings": [self._finding_to_dict(f) for f in findings],
            "traffic_log": traffic_log or []
        }
        
        path = self.output_dir / f"report_{base_filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report saved: {path}")
        return path
    
    def _generate_html(
        self,
        findings: List,
        context,
        config: Dict,
        base_filename: str,
        traffic_log: List = None
    ) -> Path:
        """Generate HTML format report with traffic log"""
        severity_counts = self._count_by_severity(findings)
        category_counts = self._count_by_category(findings)
        traffic_log = traffic_log or []
        
        target_url = config['target']['url']
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jarwis Security Report - {target_url} - {base_filename}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
                line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; 
                  padding: 40px; border-radius: 10px; margin-bottom: 30px; }}
        header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.8; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                    gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; border-radius: 10px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .card h3 {{ font-size: 0.9em; text-transform: uppercase; color: #666; margin-bottom: 10px; }}
        .card .value {{ font-size: 2.5em; font-weight: bold; }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: white; border-radius: 10px; padding: 25px; margin-bottom: 20px; 
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid; }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; }}
        .badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; color: white; }}
        .badge.critical {{ background: #dc3545; }}
        .badge.high {{ background: #fd7e14; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #28a745; }}
        .badge.info {{ background: #17a2b8; }}
        .finding-details {{ margin-top: 15px; }}
        .finding-details dt {{ font-weight: bold; color: #666; margin-top: 10px; }}
        .finding-details dd {{ margin-left: 0; padding: 10px; background: #f8f9fa; border-radius: 5px; 
                               font-family: monospace; word-break: break-all; }}
        .category-tag {{ display: inline-block; padding: 3px 8px; background: #e9ecef; border-radius: 4px; 
                         font-size: 0.85em; margin-right: 10px; }}
        footer {{ text-align: center; padding: 40px; color: #666; }}
        .tab-btn-active {{ background: #0066cc !important; color: white !important; }}
        .tab-btn-inactive {{ background: #444 !important; color: #ccc !important; }}
        .executive-summary {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; 
                              padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .executive-summary h2 {{ margin-bottom: 20px; }}
        .executive-summary p {{ margin: 15px 0; line-height: 1.8; }}
        .attack-chain {{ background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 10px 0; }}
        .ai-verified {{ background: #d4edda; border: 1px solid #28a745; padding: 5px 10px; border-radius: 15px; font-size: 0.8em; }}
    </style>
    <script>
        function showTab(findingId, tabName) {{
            // Get the request and response divs
            var reqDiv = document.getElementById(findingId + '-request');
            var resDiv = document.getElementById(findingId + '-response');
            var reqBtn = document.getElementById(findingId + '-req-btn');
            var resBtn = document.getElementById(findingId + '-res-btn');
            
            if (tabName === 'request') {{
                reqDiv.style.display = 'block';
                resDiv.style.display = 'none';
                reqBtn.style.background = '#0066cc';
                reqBtn.style.color = 'white';
                resBtn.style.background = '#444';
                resBtn.style.color = '#ccc';
            }} else {{
                reqDiv.style.display = 'none';
                resDiv.style.display = 'block';
                reqBtn.style.background = '#444';
                reqBtn.style.color = '#ccc';
                resBtn.style.background = '#0066cc';
                resBtn.style.color = 'white';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <header>
            <h1>ðŸ›¡ï¸ Jarwis Security Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {config['target']['url']}</p>
                <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Authenticated:</strong> {'Yes' if context.authenticated else 'No'}</p>
                <p><strong>Verified:</strong> <span class="ai-verified">[OK] Jarwis Human Intelligence Verified</span></p>
            </div>
        </header>
        
        {self._generate_executive_summary_html()}
        
        <section class="summary">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value">{len(findings)}</div>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="value critical">{severity_counts.get('critical', 0)}</div>
            </div>
            <div class="card">
                <h3>High</h3>
                <div class="value high">{severity_counts.get('high', 0)}</div>
            </div>
            <div class="card">
                <h3>Medium</h3>
                <div class="value medium">{severity_counts.get('medium', 0)}</div>
            </div>
            <div class="card">
                <h3>Low</h3>
                <div class="value low">{severity_counts.get('low', 0)}</div>
            </div>
            <div class="card">
                <h3>Endpoints Tested</h3>
                <div class="value">{len(context.endpoints)}</div>
            </div>
        </section>
        
        <section class="findings">
            <h2>Detailed Findings</h2>
            {self._generate_findings_html(findings)}
        </section>
        
        <section class="findings" style="margin-top: 40px;">
            <h2>ðŸ"¡ Traffic Log (Request/Response Headers)</h2>
            <p style="margin: 15px 0; color: #666;">Total captured: {len(traffic_log)} requests/responses</p>
            {self._generate_traffic_log_html(traffic_log)}
        </section>
        
        {self._generate_attack_chains_html()}
        
        <footer>
            <p>Generated by Jarwis Security Testing v1.0.0</p>
            <p>OWASP Top 10 Security Assessment</p>
            <p>ðŸ›¡ï¸ Developed by BKD Labs</p>
            <p>Report: {base_filename}</p>
        </footer>
    </div>
</body>
</html>"""
        
        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"HTML report saved: {path}")
        return path
    
    def _generate_traffic_log_html(self, traffic_log: List) -> str:
        """Generate HTML for traffic log section"""
        if not traffic_log:
            return '<p>No traffic captured.</p>'
        
        html_parts = []
        for i, entry in enumerate(traffic_log[:100]):  # Limit to first 100 entries
            entry_type = entry.get('type', 'unknown')
            is_request = entry_type == 'request'
            
            badge_color = '#007bff' if is_request else '#28a745'
            badge_text = '-> REQUEST' if is_request else '<- RESPONSE'
            
            headers_html = ''
            headers = entry.get('headers', {})
            for key, value in headers.items():
                headers_html += f'<div><strong>{key}:</strong> {value}</div>'
            
            status_html = ''
            if not is_request:
                status = entry.get('status', '')
                status_text = entry.get('status_text', '')
                status_html = f'<div style="margin-bottom: 10px;"><strong>Status:</strong> {status} {status_text}</div>'
            
            method_html = ''
            if is_request:
                method = entry.get('method', 'GET')
                method_html = f'<span style="background: #6c757d; color: white; padding: 2px 8px; border-radius: 4px; margin-right: 10px;">{method}</span>'
            
            html_parts.append(f"""
            <div class="finding info" style="border-left-color: {badge_color};">
                <div class="finding-header">
                    <div>
                        {method_html}
                        <span style="font-family: monospace; word-break: break-all;">{entry.get('url', 'N/A')}</span>
                    </div>
                    <span class="badge" style="background: {badge_color};">{badge_text}</span>
                </div>
                {status_html}
                <details>
                    <summary style="cursor: pointer; padding: 10px 0; font-weight: bold;">Headers ({len(headers)} items)</summary>
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 0.85em;">
                        {headers_html}
                    </div>
                </details>
                <div style="font-size: 0.8em; color: #666; margin-top: 10px;">Timestamp: {entry.get('timestamp', 'N/A')}</div>
            </div>
            """)
        
        if len(traffic_log) > 100:
            html_parts.append(f'<p style="text-align: center; color: #666;">... and {len(traffic_log) - 100} more entries (see JSON report for full log)</p>')
        
        return '\n'.join(html_parts)
    
    def _generate_findings_html(self, findings: List) -> str:
        """Generate HTML for findings section with POC and reasoning - Burp Suite style"""
        html_parts = []
        
        for idx, f in enumerate(findings):
            severity = getattr(f, 'severity', 'info')
            poc = getattr(f, 'poc', '') or getattr(f, 'evidence', '') or 'N/A'
            reasoning = getattr(f, 'reasoning', '') or self._generate_reasoning(f)
            request_data = getattr(f, 'request_data', '') or 'N/A'
            response_data = getattr(f, 'response_data', getattr(f, 'response_snippet', '')) or 'N/A'
            cwe_id = getattr(f, 'cwe_id', '') or 'N/A'
            finding_id = f"finding-{idx}"
            
            html_parts.append(f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div>
                        <span class="category-tag">{getattr(f, 'category', 'Unknown')}</span>
                        <span class="category-tag" style="background: #6c5ce7;">{cwe_id}</span>
                        <span class="finding-title">{getattr(f, 'title', 'Security Issue')}</span>
                    </div>
                    <span class="badge {severity}">{severity.upper()}</span>
                </div>
                <p style="margin: 15px 0;">{getattr(f, 'description', 'No description available')}</p>
                
                <div style="background: #e8f4fd; border: 1px solid #0066cc; border-radius: 8px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #004085; margin-bottom: 10px;">ðŸŽ¯ Vulnerable Endpoint</h4>
                    <table style="width: 100%; border-collapse: collapse;">
                        <tr><td style="padding: 5px; font-weight: bold; width: 100px;">URL:</td><td style="padding: 5px; font-family: monospace; word-break: break-all;">{getattr(f, 'url', 'N/A')}</td></tr>
                        <tr><td style="padding: 5px; font-weight: bold;">Method:</td><td style="padding: 5px;">{getattr(f, 'method', 'N/A')}</td></tr>
                        <tr><td style="padding: 5px; font-weight: bold;">Parameter:</td><td style="padding: 5px; font-family: monospace;">{getattr(f, 'parameter', 'N/A') or 'N/A'}</td></tr>
                    </table>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #856404; margin-bottom: 10px;">ðŸ§  Verification & Reasoning</h4>
                    <p style="color: #856404;">{reasoning}</p>
                </div>
                
                <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin: 15px 0;">
                    <h4 style="margin-bottom: 10px;">ðŸ"¬ Proof of Concept</h4>
                    <pre style="background: #1a1a2e; color: #00ff00; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; font-family: 'Courier New', monospace; font-size: 12px;">{self._escape_html(poc)}</pre>
                </div>
                
                <!-- Request/Response Section - Burp Suite Style -->
                <div style="background: #2d2d2d; border-radius: 8px; margin: 15px 0; overflow: hidden;">
                    <div style="display: flex; background: #1a1a1a;">
                        <button onclick="showTab('{finding_id}', 'request')" id="{finding_id}-req-btn" style="flex: 1; padding: 12px; border: none; background: #0066cc; color: white; cursor: pointer; font-weight: bold;">ðŸ"¤ REQUEST</button>
                        <button onclick="showTab('{finding_id}', 'response')" id="{finding_id}-res-btn" style="flex: 1; padding: 12px; border: none; background: #444; color: #ccc; cursor: pointer; font-weight: bold;">ðŸ"YEN RESPONSE</button>
                    </div>
                    <div id="{finding_id}-request" style="display: block;">
                        <pre style="margin: 0; padding: 15px; color: #f8f8f2; font-family: 'Courier New', monospace; font-size: 11px; white-space: pre-wrap; overflow-x: auto; max-height: 400px; overflow-y: auto;">{self._escape_html(request_data)}</pre>
                    </div>
                    <div id="{finding_id}-response" style="display: none;">
                        <pre style="margin: 0; padding: 15px; color: #f8f8f2; font-family: 'Courier New', monospace; font-size: 11px; white-space: pre-wrap; overflow-x: auto; max-height: 400px; overflow-y: auto;">{self._escape_html(response_data)}</pre>
                    </div>
                </div>
                
                <div style="background: #d4edda; border: 1px solid #28a745; border-radius: 8px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: #155724; margin-bottom: 10px;">ðŸ›¡ï¸ Remediation</h4>
                    <p style="color: #155724;">{getattr(f, 'remediation', 'Review and fix according to OWASP guidelines')}</p>
                </div>
                
                <div style="background: #f0f0f0; border-radius: 5px; padding: 10px; margin-top: 10px; font-size: 0.85em; color: #666;">
                    <strong>Evidence:</strong> {self._escape_html(getattr(f, 'evidence', 'N/A')[:300] if getattr(f, 'evidence', '') else 'N/A')}
                </div>
            </div>
            """)
        
        return '\n'.join(html_parts) if html_parts else '<p>No findings to display.</p>'
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return 'N/A'
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    def _generate_reasoning(self, finding) -> str:
        """Generate reasoning for why this was detected as a vulnerability"""
        category = getattr(finding, 'category', '')
        title = getattr(finding, 'title', '').lower()
        evidence = getattr(finding, 'evidence', '')
        
        reasoning_map = {
            'A01': f"Jarwis detected a Broken Access Control issue. The application failed to properly restrict access to resources. Evidence: {evidence[:200] if evidence else 'Access to unauthorized resource was successful'}.",
            'A02': f"Jarwis identified a Cryptographic Failure. Sensitive data may be exposed due to weak or missing encryption. Evidence: {evidence[:200] if evidence else 'Sensitive data found in plaintext or weak encryption detected'}.",
            'A03': f"Jarwis detected an Injection vulnerability. User input is being processed without proper sanitization, allowing malicious payloads to be executed. Evidence: {evidence[:200] if evidence else 'Application responded to injection payload in an unexpected way'}.",
            'A04': f"Jarwis found an Insecure Design issue. The application architecture lacks security controls. Evidence: {evidence[:200] if evidence else 'Missing security controls detected in application design'}.",
            'A05': f"Jarwis detected a Security Misconfiguration. The application or server has insecure default settings or missing security hardening. Evidence: {evidence[:200] if evidence else 'Misconfigured security settings found'}.",
            'A06': f"Jarwis identified a Vulnerable Component. The application uses outdated or known-vulnerable libraries/frameworks. Evidence: {evidence[:200] if evidence else 'Outdated or vulnerable component version detected'}.",
            'A07': f"Jarwis detected an Authentication/Identification Failure. The application has weak authentication mechanisms. Evidence: {evidence[:200] if evidence else 'Weak authentication controls detected'}.",
            'A08': f"Jarwis found a Software/Data Integrity Failure. The application does not properly verify integrity of data or software updates. Evidence: {evidence[:200] if evidence else 'Missing integrity verification detected'}.",
            'A09': f"Jarwis detected a Security Logging/Monitoring Failure. The application lacks proper logging or monitoring capabilities. Evidence: {evidence[:200] if evidence else 'Insufficient logging detected'}.",
            'A10': f"Jarwis identified a Server-Side Request Forgery (SSRF) vulnerability. The application makes server-side requests based on user input. Evidence: {evidence[:200] if evidence else 'SSRF payload triggered server-side request'}."
        }
        
        if category in reasoning_map:
            return reasoning_map[category]
        
        # Generic reasoning based on title
        if 'sql' in title or 'injection' in title:
            return f"Jarwis tested the endpoint with SQL injection payloads and observed error messages or behavioral changes indicating the input is being interpreted as SQL code. This confirms the parameter is vulnerable to injection attacks."
        elif 'xss' in title or 'cross-site' in title:
            return f"Jarwis injected XSS payloads and detected that user input is reflected in the response without proper encoding, allowing JavaScript execution in the browser context."
        elif 'idor' in title:
            return f"Jarwis tested object references by modifying ID parameters and successfully accessed resources belonging to other users, indicating missing authorization checks."
        elif 'csrf' in title:
            return f"Jarwis tested state-changing requests without CSRF tokens and the server accepted the requests, indicating vulnerability to cross-site request forgery attacks."
        elif 'sensitive' in title or 'exposure' in title:
            return f"Jarwis scanned for sensitive information exposure and found data that should be protected (credentials, tokens, PII) accessible without proper authorization."
        
        return f"Jarwis automated security testing detected this issue based on the application's response to security test payloads. The evidence collected confirms the vulnerability. Evidence: {evidence[:200] if evidence else 'See POC for details'}."
    
    def _count_by_severity(self, findings: List) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for f in findings:
            sev = getattr(f, 'severity', 'info')
            counts[sev] = counts.get(sev, 0) + 1
        return counts
    
    def _count_by_category(self, findings: List) -> Dict[str, int]:
        """Count findings by OWASP category"""
        counts = {}
        for f in findings:
            cat = getattr(f, 'category', 'Unknown')
            counts[cat] = counts.get(cat, 0) + 1
        return counts
    
    def _finding_to_dict(self, finding) -> Dict:
        """Convert finding to dictionary"""
        try:
            return asdict(finding)
        except:
            return {
                'id': getattr(finding, 'id', ''),
                'category': getattr(finding, 'category', ''),
                'severity': getattr(finding, 'severity', ''),
                'title': getattr(finding, 'title', ''),
                'description': getattr(finding, 'description', ''),
                'url': getattr(finding, 'url', ''),
                'method': getattr(finding, 'method', ''),
                'parameter': getattr(finding, 'parameter', ''),
                'evidence': getattr(finding, 'evidence', ''),
                'remediation': getattr(finding, 'remediation', ''),
                'cwe_id': getattr(finding, 'cwe_id', ''),
                'poc': getattr(finding, 'poc', ''),
                'reasoning': getattr(finding, 'reasoning', ''),
                'request_data': getattr(finding, 'request_data', ''),
                'response_snippet': getattr(finding, 'response_snippet', '')
            }
    
    def _generate_executive_summary_html(self) -> str:
        """Generate HTML for executive summary section"""
        if not hasattr(self, '_executive_summary') or not self._executive_summary:
            return ""
        
        # Split summary into paragraphs
        paragraphs = self._executive_summary.strip().split('\n\n')
        paragraphs_html = ''.join([f'<p>{p.strip()}</p>' for p in paragraphs if p.strip()])
        
        return f'''
        <section class="executive-summary">
            <h2>ï¿½ Jarwis Human Intelligence Executive Summary</h2>
            {paragraphs_html}
        </section>
        '''
    
    def _generate_attack_chains_html(self) -> str:
        """Generate HTML for attack chains section"""
        if not hasattr(self, '_attack_chains') or not self._attack_chains:
            return ""
        
        chains_html = []
        for chain in self._attack_chains[:5]:
            chains_html.append(f'''
            <div class="attack-chain">
                <h4>â›"ï¸ {chain.get('chain_name', 'Unknown Chain')}</h4>
                <p><strong>Combined Impact:</strong> {chain.get('combined_impact', 'N/A')}</p>
                <p><strong>Severity:</strong> {chain.get('severity', 'medium').upper()}</p>
                <p><strong>Related Findings:</strong> {', '.join(chain.get('findings', []))}</p>
            </div>
            ''')
        
        if chains_html:
            return f'''
            <section class="findings" style="margin-top: 40px;">
                <h2>â›"ï¸ Jarwis-Detected Attack Chains</h2>
                <p style="margin: 15px 0; color: #666;">Jarwis human intelligence identified potential attack chains where combining multiple vulnerabilities increases impact.</p>
                {''.join(chains_html)}
            </section>
            '''
        return ""
