"""
JARWIS AGI PEN TEST - Professional Report Generator V3
Multi-format security report generation with PDF support

Optimized for CISO and Senior Management reporting:
- Professional cover page with proper alignment
- XBOW-style Introduction and Executive Summary
- Purpose and Scope sections
- Findings summary table
- Detailed findings with technical evidence
- Methodology section
- Appendix with endpoints and disclaimer
"""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import asdict

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates professional security reports in multiple formats"""
    
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
    
    CWE_MAPPING = {
        'A01': 'CWE-284',
        'A02': 'CWE-327',
        'A03': 'CWE-79',
        'A04': 'CWE-73',
        'A05': 'CWE-16',
        'A06': 'CWE-1104',
        'A07': 'CWE-287',
        'A08': 'CWE-494',
        'A09': 'CWE-778',
        'A10': 'CWE-918'
    }
    
    # Jarwis Logo SVG (inline for PDF compatibility)
    JARWIS_LOGO_SVG = '''<svg viewBox="0 0 500 500" xmlns="http://www.w3.org/2000/svg" width="70" height="70">
        <defs>
            <linearGradient id="logoGrad" x1="250" y1="111.235" x2="250" y2="383.576" gradientUnits="userSpaceOnUse">
                <stop offset="0" style="stop-color:#00C19F"/>
                <stop offset="1" style="stop-color:#256AD1"/>
            </linearGradient>
        </defs>
        <path fill="url(#logoGrad)" d="M343.73,166.48l-12.75-7.4L250,112.35l-25.51,14.73l-12.75,7.33l-80.97,46.8V318.8l25.5,14.72l12.75,7.4l12.75,7.33l12.75,7.39L250,387.65l25.51-14.73l12.75-7.4l12.75-7.33l12.75-7.33l55.47-32.07V181.21L343.73,166.48z M250,127.08l80.97,46.73v14.73l0,0v14.73l0,0v65.29l-12.75,7.14v-94.49l-12.75-7.4l-55.47-32l-12.75-7.33L250,127.08z M250,314.01L194.53,282V218L250,185.99L305.47,218v64.84L250,314.01z M143.53,188.54l80.97-46.73l12.75,7.33h0.07l12.69,7.39l55.47,32.01v14.72l-55.47-32l-12.75-7.4l-12.75-7.33l-12.75,7.4h-0.07l-55.41,32l-12.75,7.4V188.54z M143.53,311.47V218l12.75-7.33l12.75-7.4l55.41-32l12.81,7.4l-55.47,32L169.03,218l-12.75,7.39v93.41L143.53,311.47z M250,372.92l-55.47-32l-12.75-7.4l-12.75-7.33v-93.47l12.75-7.39v93.47v0.06l12.75,7.33L250,358.2l12.75,7.33L250,372.92z M275.51,358.2l-12.75-7.4L250,343.47l-55.47-32v-14.73l55.47,32l12.75,7.4l12.75,7.33l12.75,7.4L275.51,358.2z M356.47,311.47l-55.47,32l-12.75-7.33l55.47-32v-0.07l12.75-7.33V311.47z M356.47,282l-12.75,7.33l-12.75,7.4l-55.47,32l-12.63-7.27l68.09-38.32l12.75-7.14l12.75-7.2V282z M356.47,254.21l-12.75,7.13v-65.41v-14.72l12.75,7.33V254.21z"/>
        <polygon fill="#00C598" points="250,229.09 220.91,245.88 220.91,279.44 250,296.23 279.09,279.88 279.09,245.88"/>
        <path fill="#256AD1" d="M250,208.65c-13.03,0-23.62,10.6-23.62,23.63v5.37l7-4.04v-1.33c0-9.17,7.46-16.63,16.63-16.63c9.16,0,16.63,7.46,16.63,16.63v1.33l7,4.04v-5.37C273.62,219.25,263.02,208.65,250,208.65z"/>
        <polygon fill="#040B28" points="257.37,273.56 242.63,273.56 248,255.24 252,255.24"/>
        <circle fill="#040B28" cx="250" cy="254.83" r="5.69"/>
    </svg>'''
    
    JARWIS_LOGO_SVG_SMALL = '''<svg viewBox="0 0 500 500" width="28" height="28" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="logoGradSmall" x1="250" y1="111.235" x2="250" y2="383.576" gradientUnits="userSpaceOnUse">
                <stop offset="0" style="stop-color:#00C19F"/>
                <stop offset="1" style="stop-color:#256AD1"/>
            </linearGradient>
        </defs>
        <path fill="url(#logoGradSmall)" d="M343.73,166.48l-12.75-7.4L250,112.35l-25.51,14.73l-12.75,7.33l-80.97,46.8V318.8l25.5,14.72l12.75,7.4l12.75,7.33l12.75,7.39L250,387.65l25.51-14.73l12.75-7.4l12.75-7.33l12.75-7.33l55.47-32.07V181.21L343.73,166.48z M250,127.08l80.97,46.73v14.73l0,0v14.73l0,0v65.29l-12.75,7.14v-94.49l-12.75-7.4l-55.47-32l-12.75-7.33L250,127.08z M250,314.01L194.53,282V218L250,185.99L305.47,218v64.84L250,314.01z M143.53,188.54l80.97-46.73l12.75,7.33h0.07l12.69,7.39l55.47,32.01v14.72l-55.47-32l-12.75-7.4l-12.75-7.33l-12.75,7.4h-0.07l-55.41,32l-12.75,7.4V188.54z M143.53,311.47V218l12.75-7.33l12.75-7.4l55.41-32l12.81,7.4l-55.47,32L169.03,218l-12.75,7.39v93.41L143.53,311.47z M250,372.92l-55.47-32l-12.75-7.4l-12.75-7.33v-93.47l12.75-7.39v93.47v0.06l12.75,7.33L250,358.2l12.75,7.33L250,372.92z M275.51,358.2l-12.75-7.4L250,343.47l-55.47-32v-14.73l55.47,32l12.75,7.4l12.75,7.33l12.75,7.4L275.51,358.2z M356.47,311.47l-55.47,32l-12.75-7.33l55.47-32v-0.07l12.75-7.33V311.47z M356.47,282l-12.75,7.33l-12.75,7.4l-55.47,32l-12.63-7.27l68.09-38.32l12.75-7.14l12.75-7.2V282z M356.47,254.21l-12.75,7.13v-65.41v-14.72l12.75,7.33V254.21z"/>
        <polygon fill="#00C598" points="250,229.09 220.91,245.88 220.91,279.44 250,296.23 279.09,279.88 279.09,245.88"/>
    </svg>'''
    
    def __init__(self, output_dir: str, formats: List[str]):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.formats = formats
        self.template_dir = Path(__file__).parent.parent / 'templates'
        
    def _sanitize_filename(self, url: str, app_name: str = None) -> str:
        """Extract and sanitize website name from URL for filename"""
        import re
        from urllib.parse import urlparse
        try:
            if app_name:
                sanitized = re.sub(r'[^a-zA-Z0-9]', '_', app_name)
                return sanitized
            
            parsed = urlparse(url)
            domain = parsed.netloc.replace('www.', '').split(':')[0]
            
            if domain in ['localhost', '127.0.0.1', '0.0.0.0']:
                port = parsed.netloc.split(':')[1] if ':' in parsed.netloc else '80'
                port_apps = {
                    '3000': 'juice_shop',
                    '8080': 'webapp',
                    '8000': 'django',
                    '5000': 'flask',
                    '4200': 'angular',
                    '3001': 'react'
                }
                domain = port_apps.get(port, f'local_{port}')
            
            sanitized = re.sub(r'[^a-zA-Z0-9]', '_', domain)
            return sanitized
        except:
            return 'unknown_target'
    
    def _get_finding_attr(self, finding, attr: str, default=''):
        """Get attribute from finding - works with both dict and object"""
        if isinstance(finding, dict):
            return finding.get(attr, default)
        return getattr(finding, attr, default)
    
    async def generate(
        self,
        findings: List,
        context,
        config: Dict,
        traffic_log: List = None,
        executive_summary: str = None,
        attack_chains: List = None
    ) -> List[str]:
        """Generate reports in all configured formats"""
        generated = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        target_url = config.get('target', {}).get('url', 'unknown')
        app_name = config.get('target', {}).get('name', None)
        website_name = self._sanitize_filename(target_url, app_name)
        
        base_filename = f"{website_name}_{timestamp}"
        report_id = f"JAR-{timestamp}-{str(uuid.uuid4())[:6].upper()}"
        
        logger.info(f"Generating report: {base_filename}")
        
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(self._get_finding_attr(f, 'severity', 'info'), 4)
        )
        
        # Store extra data
        self._attack_chains = attack_chains or []
        self._report_id = report_id
        
        for fmt in self.formats:
            if fmt == 'sarif':
                path = self._generate_sarif(sorted_findings, base_filename)
            elif fmt == 'json':
                path = self._generate_json(sorted_findings, context, config, base_filename, traffic_log)
            elif fmt == 'html':
                path = self._generate_professional_html(sorted_findings, context, config, base_filename, traffic_log)
            elif fmt == 'pdf':
                html_path = self._generate_professional_html(sorted_findings, context, config, base_filename, traffic_log)
                path = await self._generate_pdf(html_path, base_filename)
            else:
                continue
            
            if path:
                generated.append(str(path))
        
        return generated
    
    def _count_by_severity(self, findings: List) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = self._get_finding_attr(f, 'severity', 'info').lower()
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML characters"""
        if not text:
            return ''
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')
    
    def _format_http_for_pdf(self, http_data: str, is_request: bool = True) -> str:
        """
        Format HTTP request/response data line-by-line for PDF rendering.
        Parses headers and body separately with proper color coding.
        """
        if not http_data:
            return ''
        
        lines = str(http_data).strip().split('\n')
        formatted_lines = []
        in_body = False
        body_lines = []
        
        for i, line in enumerate(lines):
            line = line.rstrip('\r')
            
            # Check for empty line (separator between headers and body)
            if not line.strip() and not in_body:
                in_body = True
                continue
            
            if in_body:
                body_lines.append(self._escape_html(line))
            else:
                # First line is request/status line
                if i == 0:
                    css_class = "http-line-method" if is_request else "http-line-status"
                    formatted_lines.append(
                        f'<span class="http-line {css_class}">{self._escape_html(line)}</span>'
                    )
                else:
                    # Header line (Key: Value)
                    if ':' in line:
                        key, _, value = line.partition(':')
                        formatted_lines.append(
                            f'<span class="http-line">'
                            f'<span class="http-line-header">{self._escape_html(key)}:</span> '
                            f'<span class="http-line-value">{self._escape_html(value.strip())}</span>'
                            f'</span>'
                        )
                    else:
                        formatted_lines.append(
                            f'<span class="http-line">{self._escape_html(line)}</span>'
                        )
        
        # Join headers
        html = '\n'.join(formatted_lines)
        
        # Add body if present
        if body_lines:
            body_content = '\n'.join(body_lines)
            # Truncate body if too long (800 chars max for PDF readability)
            if len(body_content) > 800:
                body_content = body_content[:800] + '\n... (truncated for readability)'
            html += f'\n<div class="http-body-separator"></div>\n<span class="http-body">{body_content}</span>'
        
        return html

    
    def _calculate_risk_score(self, findings: List) -> Tuple[int, str, str, str]:
        """Calculate overall risk score (0-100), color, gradient, and level"""
        severity_counts = self._count_by_severity(findings)
        
        # Weighted scoring
        score = 0
        score += severity_counts.get('critical', 0) * 25
        score += severity_counts.get('high', 0) * 15
        score += severity_counts.get('medium', 0) * 8
        score += severity_counts.get('low', 0) * 3
        score += severity_counts.get('info', 0) * 1
        
        # Normalize to 0-100
        score = min(100, score)
        
        if severity_counts.get('critical', 0) > 0:
            return score, "#dc2626", "linear-gradient(90deg, #dc2626, #ea580c)", "CRITICAL"
        elif severity_counts.get('high', 0) > 0:
            return score, "#ea580c", "linear-gradient(90deg, #ea580c, #d97706)", "HIGH"
        elif severity_counts.get('medium', 0) > 0:
            return score, "#d97706", "linear-gradient(90deg, #d97706, #eab308)", "MEDIUM"
        else:
            return score, "#059669", "linear-gradient(90deg, #059669, #10b981)", "LOW"
    
    def _generate_findings_overview(self, findings: List) -> str:
        """Generate XBOW-style findings overview paragraph"""
        severity_counts = self._count_by_severity(findings)
        total = len(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)
        
        if total == 0:
            return "During the assessment, Jarwis did not identify any security vulnerabilities. The application demonstrates strong security practices and defensive controls."
        
        # Build natural language summary
        severity_parts = []
        if critical > 0:
            severity_parts.append(f"<strong>{critical} critical-severity</strong> vulnerabilit{'ies' if critical > 1 else 'y'}")
        if high > 0:
            severity_parts.append(f"<strong>{high} high-severity</strong> vulnerabilit{'ies' if high > 1 else 'y'}")
        if medium > 0:
            severity_parts.append(f"<strong>{medium} medium-severity</strong> vulnerabilit{'ies' if medium > 1 else 'y'}")
        if low > 0:
            severity_parts.append(f"<strong>{low} low-severity</strong> vulnerabilit{'ies' if low > 1 else 'y'}")
        
        # Join with proper grammar
        if len(severity_parts) == 1:
            severity_text = severity_parts[0]
        elif len(severity_parts) == 2:
            severity_text = f"{severity_parts[0]} and {severity_parts[1]}"
        else:
            severity_text = ", ".join(severity_parts[:-1]) + f", and {severity_parts[-1]}"
        
        overview = f"During the assessment, Jarwis identified <strong>{total} distinct security vulnerabilities</strong> across the target environment. The findings include {severity_text}."
        
        return overview
    
    def _generate_critical_findings_summary(self, findings: List) -> str:
        """Generate detailed summary of critical and high findings"""
        critical_high = [f for f in findings if self._get_finding_attr(f, 'severity', '') in ['critical', 'high']]
        
        if not critical_high:
            return ""
        
        summaries = []
        for f in critical_high[:4]:  # Top 4 critical/high
            severity = self._get_finding_attr(f, 'severity', 'high')
            title = self._get_finding_attr(f, 'title', 'Security Issue')
            desc = self._get_finding_attr(f, 'description', '')[:200]
            
            summaries.append(f'''
<p class="content-text" style="margin-bottom: 12px;">
The <strong>{severity}-severity finding</strong> involves {self._escape_html(title.lower())}. {self._escape_html(desc)}
</p>''')
        
        # Add risk statement
        risk_text = '''
<div class="warning-box" style="margin-top: 15px;">
<p>The critical and high-severity vulnerabilities pose immediate risks to the organization's security posture, as they provide pathways for unauthorized data access and system compromise. Immediate remediation is strongly recommended.</p>
</div>'''
        
        return "".join(summaries) + risk_text
    
    def _generate_conclusion(self, findings: List, context) -> str:
        """Generate XBOW-style conclusion"""
        severity_counts = self._count_by_severity(findings)
        total = len(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        
        if total == 0:
            return "The penetration test did not reveal any significant security vulnerabilities. The target application demonstrates robust security controls and defensive measures. However, security is an ongoing process, and regular assessments are recommended to maintain this security posture."
        
        if critical > 0 or high > 0:
            conclusion = f"The penetration test revealed several significant security vulnerabilities that require immediate attention. The presence of {critical + high} critical and high-severity vulnerabilities represents substantial risks that could lead to unauthorized system access and data compromise."
        else:
            conclusion = f"The penetration test identified {total} security issues of medium to low severity. While these do not pose immediate critical risk, they should be addressed to strengthen the overall security posture."
        
        conclusion += " By promptly addressing these identified vulnerabilities, the organization can significantly enhance their application security and reduce exposure to potential cyber threats."
        
        return conclusion
    
    def _generate_recommendations(self, findings: List) -> str:
        """Generate prioritized recommendations"""
        severity_counts = self._count_by_severity(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        
        recommendations = []
        
        if critical > 0:
            recommendations.append(f"Remediate {critical} critical vulnerabilities within 24-48 hours")
        if high > 0:
            recommendations.append(f"Address {high} high-severity findings within 7 days")
        if medium > 0:
            recommendations.append(f"Plan remediation of {medium} medium-severity issues within 30 days")
        
        recommendations.append("Implement security monitoring and logging for affected components")
        recommendations.append("Conduct follow-up assessment to verify remediation effectiveness")
        
        return " âEUR¢ ".join(recommendations)
    
    def _generate_findings_table_rows(self, findings: List) -> str:
        """Generate findings summary table rows"""
        if not findings:
            return '<tr><td colspan="4" style="text-align: center; padding: 20px; color: #6b7280;">No vulnerabilities found</td></tr>'
        
        rows = []
        for f in findings:
            severity = self._get_finding_attr(f, 'severity', 'info')
            title = self._get_finding_attr(f, 'title', 'Finding')[:50]
            category = self._get_finding_attr(f, 'category', 'A05')
            category_name = self.OWASP_CATEGORIES.get(category, 'Security Issue')
            cwe = self._get_finding_attr(f, 'cwe_id', '') or self.CWE_MAPPING.get(category, 'N/A')
            
            rows.append(f'''<tr>
                <td><span class="severity-pill {severity}">{severity.upper()}</span></td>
                <td>{self._escape_html(title)}</td>
                <td>{category_name}</td>
                <td>{cwe}</td>
            </tr>''')
        
        return '\n'.join(rows)
    
    def _generate_endpoints_list(self, endpoints: List) -> str:
        """Generate endpoints list for appendix"""
        if not endpoints:
            return '<div class="endpoint-item"><span class="endpoint-number">-</span>No endpoints discovered</div>'
        
        items = []
        for i, endpoint in enumerate(endpoints[:25], 1):
            items.append(f'<div class="endpoint-item"><span class="endpoint-number">{i}.</span>{self._escape_html(str(endpoint))}</div>')
        
        if len(endpoints) > 25:
            items.append(f'<div class="endpoint-item" style="color: #6b7280; font-style: italic;"><span class="endpoint-number">...</span>And {len(endpoints) - 25} more endpoints (see JSON report)</div>')
        
        return '\n'.join(items)
    
    def _generate_findings_html(self, findings: List) -> str:
        """Generate detailed findings HTML"""
        if not findings:
            return '''<div style="text-align: center; padding: 50px; background: #f0fdf4; border-radius: 10px; margin: 20px 0; border: 1px solid #a7f3d0;">
                <div style="font-size: 36px; margin-bottom: 12px;">âœ"</div>
                <div style="font-size: 14pt; font-weight: 700; color: #059669; margin-bottom: 8px;">No Vulnerabilities Found</div>
                <div style="color: #065f46; font-size: 10pt;">The target application passed all security tests.</div>
            </div>'''
        
        html_parts = []
        
        for idx, f in enumerate(findings, 1):
            severity = self._get_finding_attr(f, 'severity', 'info')
            finding_id = self._get_finding_attr(f, 'id', f'JAR-{idx:03d}')
            title = self._get_finding_attr(f, 'title', 'Security Issue')
            description = self._get_finding_attr(f, 'description', 'No description available')
            url = self._get_finding_attr(f, 'url', 'N/A')
            method = self._get_finding_attr(f, 'method', 'GET')
            parameter = self._get_finding_attr(f, 'parameter', '') or 'N/A'
            category = self._get_finding_attr(f, 'category', 'A05')
            category_name = self.OWASP_CATEGORIES.get(category, 'Security Issue')
            cwe = self._get_finding_attr(f, 'cwe_id', '') or self.CWE_MAPPING.get(category, 'N/A')
            
            evidence = self._get_finding_attr(f, 'evidence', '') or self._get_finding_attr(f, 'poc', '') or ''
            remediation = self._get_finding_attr(f, 'remediation', 'Review and fix according to OWASP guidelines.')
            reasoning = self._get_finding_attr(f, 'reasoning', '')
            
            # New vulnerability metadata fields
            impact = self._get_finding_attr(f, 'impact', '')
            disclosure_days = self._get_finding_attr(f, 'disclosure_days', None)
            compliance_refs = self._get_finding_attr(f, 'compliance_refs', []) or []
            attack_type = self._get_finding_attr(f, 'attack_type', '')
            cvss_score = self._get_finding_attr(f, 'cvss_score', None)
            
            request_data = self._get_finding_attr(f, 'request_data', '') or ''
            response_data = self._get_finding_attr(f, 'response_data', self._get_finding_attr(f, 'response_snippet', '')) or ''
            
            # Build finding card
            cvss_display = f'{cvss_score:.1f}' if cvss_score else 'N/A'
            disclosure_display = f'{disclosure_days} days' if disclosure_days else 'N/A'
            
            html = f'''
<div class="finding severity-{severity}">
    <div class="finding-header">
        <div class="finding-meta">
            <div class="finding-id">{finding_id}</div>
            <div class="finding-title">{self._escape_html(title)}</div>
            <div class="finding-tags">
                <span class="tag tag-category">{category}</span>
                <span class="tag tag-cwe">{cwe}</span>
                <span class="tag tag-cvss">CVSS: {cvss_display}</span>
            </div>
        </div>
        <span class="severity-pill {severity}">{severity.upper()}</span>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <div class="finding-section-title">Description</div>
            <div class="finding-description">{self._escape_html(description)}</div>
        </div>
        
        <div class="detail-grid">
            <div class="detail-item">
                <div class="detail-label">URL</div>
                <div class="detail-value">{self._escape_html(url)}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Method</div>
                <div class="detail-value">{method}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Parameter</div>
                <div class="detail-value">{self._escape_html(parameter)}</div>
            </div>
            <div class="detail-item">
                <div class="detail-label">Disclosure Timeline</div>
                <div class="detail-value">{disclosure_display}</div>
            </div>
        </div>'''
            
            # Add evidence if available
            if evidence:
                html += f'''
        <div class="finding-section">
            <div class="finding-section-title">Evidence / Proof of Concept</div>
            <div class="evidence-box">{self._escape_html(evidence)}</div>
        </div>'''
            
            # Add AI reasoning if available
            if reasoning:
                html += f'''
        <div class="ai-box">
            <div class="ai-box-header">ðŸ¤- AI Analysis</div>
            <div class="ai-box-content">{self._escape_html(reasoning)}</div>
        </div>'''
            
            # Add request/response if available - formatted line by line for PDF
            if request_data or response_data:
                html += '''
        <div class="finding-section avoid-break">
            <div class="finding-section-title">HTTP Details</div>'''
                
                if request_data:
                    formatted_request = self._format_http_for_pdf(str(request_data)[:2000], is_request=True)
                    html += f'''
            <div class="http-section">
                <div class="http-title">📤 Request</div>
                <div class="http-content">{formatted_request}</div>
            </div>'''
                
                if response_data:
                    formatted_response = self._format_http_for_pdf(str(response_data)[:2000], is_request=False)
                    html += f'''
            <div class="http-section">
                <div class="http-title">📥 Response</div>
                <div class="http-content">{formatted_response}</div>
            </div>'''
                
                html += '</div>'
            
            # Add impact section if available
            if impact:
                html += f'''
        <div class="finding-section">
            <div class="finding-section-title">⚠️ Impact</div>
            <div class="impact-box">{self._escape_html(impact)}</div>
        </div>'''
            
            # Add compliance section if available
            if compliance_refs and len(compliance_refs) > 0:
                compliance_tags = ' '.join([f'<span class="compliance-tag">{self._escape_html(ref)}</span>' for ref in compliance_refs[:8]])
                html += f'''
        <div class="finding-section">
            <div class="finding-section-title">📋 Compliance Impact</div>
            <div class="compliance-refs">{compliance_tags}</div>
        </div>'''
            
            # Add remediation
            html += f'''
        <div class="remediation-box">
            <div class="remediation-header">✔ Remediation</div>
            <div class="remediation-content">{self._escape_html(remediation)}</div>
        </div>
    </div>
</div>'''
            
            html_parts.append(html)
        
        return '\n'.join(html_parts)
    
    def _generate_professional_html(
        self,
        findings: List,
        context,
        config: Dict,
        base_filename: str,
        traffic_log: List = None
    ) -> Path:
        """Generate professional HTML report using v3 template"""
        severity_counts = self._count_by_severity(findings)
        risk_score, risk_color, risk_gradient, risk_level = self._calculate_risk_score(findings)
        
        target_url = config.get('target', {}).get('url', 'Unknown')
        target_name = config.get('target', {}).get('name', target_url)
        report_date = datetime.now().strftime('%B %d, %Y')
        scan_type = config.get('target', {}).get('type', 'Web Application Security Assessment')
        client_name = config.get('target', {}).get('client', 'The Client')
        
        # Determine auth status
        auth_status = "Authenticated & Unauthenticated" if getattr(context, 'authenticated', False) else "Unauthenticated"
        endpoints_count = len(getattr(context, 'endpoints', []))
        
        # Determine risk badge class
        risk_badge_class = f"risk-{risk_level.lower()}"
        risk_class = "low-risk" if risk_level in ['LOW', 'MEDIUM'] else ""
        
        # Load v3 template
        template_path = self.template_dir / 'report_template_v3.html'
        
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                html = f.read()
        else:
            logger.warning("Template v3 not found, using embedded fallback")
            html = self._get_embedded_template()
        
        # Generate all content
        findings_overview = self._generate_findings_overview(findings)
        critical_findings_summary = self._generate_critical_findings_summary(findings)
        conclusion_text = self._generate_conclusion(findings, context)
        recommended_actions = self._generate_recommendations(findings)
        findings_table_rows = self._generate_findings_table_rows(findings)
        endpoints_list = self._generate_endpoints_list(getattr(context, 'endpoints', []))
        findings_html = self._generate_findings_html(findings)
        
        # Replace all placeholders
        replacements = {
            '{{TARGET_NAME}}': self._escape_html(target_name),
            '{{TARGET_URL}}': self._escape_html(target_url),
            '{{CLIENT_NAME}}': self._escape_html(client_name),
            '{{REPORT_DATE}}': report_date,
            '{{REPORT_ID}}': self._report_id,
            '{{SCAN_TYPE}}': scan_type,
            '{{SCAN_TYPE_LOWER}}': scan_type.lower(),
            '{{AUTH_STATUS}}': auth_status,
            '{{ENDPOINTS_COUNT}}': str(endpoints_count),
            '{{RISK_LEVEL}}': risk_level,
            '{{RISK_BADGE_CLASS}}': risk_badge_class,
            '{{RISK_CLASS}}': risk_class,
            '{{CRITICAL_COUNT}}': str(severity_counts.get('critical', 0)),
            '{{HIGH_COUNT}}': str(severity_counts.get('high', 0)),
            '{{MEDIUM_COUNT}}': str(severity_counts.get('medium', 0)),
            '{{LOW_COUNT}}': str(severity_counts.get('low', 0)),
            '{{INFO_COUNT}}': str(severity_counts.get('info', 0)),
            '{{FINDINGS_OVERVIEW}}': findings_overview,
            '{{CRITICAL_FINDINGS_SUMMARY}}': critical_findings_summary,
            '{{CONCLUSION_TEXT}}': conclusion_text,
            '{{RECOMMENDED_ACTIONS}}': recommended_actions,
            '{{FINDINGS_TABLE_ROWS}}': findings_table_rows,
            '{{ENDPOINTS_LIST}}': endpoints_list,
            '{{FINDINGS_HTML}}': findings_html,
            '{{LOGO_SVG}}': self.JARWIS_LOGO_SVG,
            '{{LOGO_SVG_SMALL}}': self.JARWIS_LOGO_SVG_SMALL,
        }
        
        for placeholder, value in replacements.items():
            html = html.replace(placeholder, str(value))
        
        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Professional HTML report saved: {path}")
        return path
    
    def _get_embedded_template(self) -> str:
        """Embedded fallback template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Jarwis Security Report - {{TARGET_NAME}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 900px; margin: 0 auto; padding: 40px; }
        header { background: linear-gradient(135deg, #040B28, #1a2c55); color: white; padding: 60px 40px; text-align: center; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 30px 0; }
        .card { background: #f8fafc; border-radius: 10px; padding: 20px; text-align: center; }
        .card .value { font-size: 2em; font-weight: bold; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #d97706; }
        .low { color: #059669; }
    </style>
</head>
<body>
    <header>
        <h1>Jarwis Security Report</h1>
        <p>{{TARGET_URL}}</p>
        <p>{{REPORT_DATE}} | {{REPORT_ID}}</p>
    </header>
    <div class="container">
        <section class="summary">
            <div class="card"><div class="value critical">{{CRITICAL_COUNT}}</div><div>Critical</div></div>
            <div class="card"><div class="value high">{{HIGH_COUNT}}</div><div>High</div></div>
            <div class="card"><div class="value medium">{{MEDIUM_COUNT}}</div><div>Medium</div></div>
            <div class="card"><div class="value low">{{LOW_COUNT}}</div><div>Low</div></div>
            <div class="card"><div class="value">{{INFO_COUNT}}</div><div>Info</div></div>
        </section>
        <section>
            <h2>Findings</h2>
            {{FINDINGS_HTML}}
        </section>
    </div>
</body>
</html>'''
    
    async def _generate_pdf(self, html_path: Path, base_filename: str) -> Optional[Path]:
        """Generate PDF from HTML report"""
        pdf_path = self.output_dir / f"report_{base_filename}.pdf"
        
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"PDF report generated with WeasyPrint: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("WeasyPrint not installed, trying playwright...")
        except Exception as e:
            logger.warning(f"WeasyPrint failed: {e}, trying playwright...")
        
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                browser = await p.chromium.launch()
                page = await browser.new_page()
                await page.goto(f'file:///{html_path.absolute().as_posix()}')
                await page.pdf(
                    path=str(pdf_path), 
                    format='A4', 
                    print_background=True,
                    margin={'top': '0', 'bottom': '0', 'left': '0', 'right': '0'}
                )
                await browser.close()
            logger.info(f"PDF report generated with Playwright: {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"Playwright PDF failed: {e}")
        
        return None
    
    async def generate_pdf_async(self, html_path: Path, pdf_path: Path) -> bool:
        """Async PDF generation for API endpoints (works in asyncio context)"""
        import asyncio
        import logging
        pdf_logger = logging.getLogger(__name__)
        
        # Try WeasyPrint first (sync but quick)
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            pdf_logger.info(f"PDF generated with WeasyPrint: {pdf_path}")
            return True
        except ImportError:
            pdf_logger.warning("WeasyPrint not available, trying Playwright...")
        except Exception as e:
            pdf_logger.warning(f"WeasyPrint failed: {e}, trying Playwright...")
        
        # Run sync Playwright in thread pool to avoid asyncio subprocess issues on Windows
        try:
            result = await asyncio.to_thread(self._generate_pdf_with_playwright_sync, html_path, pdf_path)
            if result:
                pdf_logger.info(f"PDF generated with Playwright (threaded): {pdf_path}")
                return True
        except Exception as e:
            pdf_logger.error(f"Playwright PDF failed: {e}")
        
        return False
    
    def _generate_pdf_with_playwright_sync(self, html_path: Path, pdf_path: Path) -> bool:
        """Helper: Generate PDF with Playwright sync API (runs in thread)"""
        import logging
        pdf_logger = logging.getLogger(__name__)
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                file_url = f'file:///{html_path.absolute().as_posix()}'
                pdf_logger.info(f"Loading HTML for PDF: {file_url}")
                page.goto(file_url, wait_until='networkidle')
                
                # Generate professional PDF with proper settings
                page.pdf(
                    path=str(pdf_path), 
                    format='A4', 
                    print_background=True,
                    margin={
                        'top': '15mm', 
                        'bottom': '15mm', 
                        'left': '15mm', 
                        'right': '15mm'
                    },
                    # Enable page footers with page numbers
                    display_header_footer=True,
                    header_template='<div></div>',  # Empty header
                    footer_template='''
                        <div style="font-size: 9px; width: 100%; text-align: center; color: #6b7280; padding: 5px 20px;">
                            <span>Jarwis AI Penetration Test Report</span>
                            <span style="float: right;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span>
                        </div>
                    ''',
                    prefer_css_page_size=True,  # Respect @page CSS rules
                    scale=1.0,  # No scaling
                )
                browser.close()
            return True
        except Exception as e:
            pdf_logger.error(f"Playwright sync PDF error: {e}")
            return False
    
    def generate_pdf_sync(self, html_path: Path, pdf_path: Path) -> bool:
        """Synchronous PDF generation (use only in non-async contexts)"""
        import logging
        pdf_logger = logging.getLogger(__name__)
        
        # Try WeasyPrint first
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            pdf_logger.info(f"PDF generated with WeasyPrint: {pdf_path}")
            return True
        except ImportError:
            pdf_logger.warning("WeasyPrint not available, trying Playwright...")
        except Exception as e:
            pdf_logger.warning(f"WeasyPrint failed: {e}, trying Playwright...")
        
        # Try Playwright sync as fallback (only works outside asyncio loop)
        return self._generate_pdf_with_playwright_sync(html_path, pdf_path)
    
    def _generate_sarif(self, findings: List, base_filename: str) -> Path:
        """Generate SARIF report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Jarwis",
                        "informationUri": "https://jarwis.ai",
                        "version": "2.0.0",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        for f in findings:
            sarif["runs"][0]["results"].append({
                "ruleId": self._get_finding_attr(f, 'id', 'unknown'),
                "level": self._sarif_level(self._get_finding_attr(f, 'severity', 'info')),
                "message": {"text": self._get_finding_attr(f, 'description', '')},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": self._get_finding_attr(f, 'url', '')}
                    }
                }]
            })
        
        path = self.output_dir / f"report_{base_filename}.sarif"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)
        
        return path
    
    def _sarif_level(self, severity: str) -> str:
        """Map severity to SARIF level"""
        mapping = {'critical': 'error', 'high': 'error', 'medium': 'warning', 'low': 'note', 'info': 'note'}
        return mapping.get(severity.lower(), 'note')
    
    def _generate_json(self, findings: List, context, config: Dict, base_filename: str, traffic_log: List = None) -> Path:
        """Generate JSON report"""
        report = {
            "report_id": self._report_id,
            "generated_at": datetime.now().isoformat(),
            "target": config.get('target', {}),
            "summary": {
                "total_findings": len(findings),
                "by_severity": self._count_by_severity(findings)
            },
            "findings": [self._finding_to_dict(f) for f in findings],
            "endpoints_tested": len(getattr(context, 'endpoints', [])),
            "authenticated": getattr(context, 'authenticated', False)
        }
        
        path = self.output_dir / f"report_{base_filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return path
    
    def _finding_to_dict(self, finding) -> Dict:
        """Convert finding to dictionary"""
        try:
            return asdict(finding)
        except:
            return {
                'id': getattr(finding, 'id', 'unknown'),
                'title': getattr(finding, 'title', ''),
                'description': getattr(finding, 'description', ''),
                'severity': getattr(finding, 'severity', 'info'),
                'category': getattr(finding, 'category', ''),
                'url': getattr(finding, 'url', ''),
                'method': getattr(finding, 'method', ''),
                'parameter': getattr(finding, 'parameter', ''),
                'evidence': getattr(finding, 'evidence', ''),
                'remediation': getattr(finding, 'remediation', ''),
                # New vulnerability metadata fields
                'attack_type': getattr(finding, 'attack_type', ''),
                'impact': getattr(finding, 'impact', ''),
                'disclosure_days': getattr(finding, 'disclosure_days', None),
                'cwe_id': getattr(finding, 'cwe_id', ''),
                'cvss_score': getattr(finding, 'cvss_score', None),
                'compliance_refs': getattr(finding, 'compliance_refs', []),
                'request_data': getattr(finding, 'request_data', ''),
                'response_data': getattr(finding, 'response_data', ''),
            }

    # ========================
    # CLOUD SECURITY REPORTS
    # ========================

    def generate_cloud_report(
        self,
        findings: List,
        resources: List,
        attack_paths: List,
        compliance_scores: Dict,
        config: Dict,
        base_filename: str = None
    ) -> Dict[str, Path]:
        """Generate cloud security scan reports"""
        if not base_filename:
            base_filename = f"cloud_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        reports = {}
        if 'html' in self.formats:
            reports['html'] = self._generate_cloud_html(
                findings, resources, attack_paths, compliance_scores, config, base_filename
            )
        if 'json' in self.formats:
            reports['json'] = self._generate_cloud_json(
                findings, resources, attack_paths, compliance_scores, config, base_filename
            )
        if 'sarif' in self.formats:
            reports['sarif'] = self._generate_cloud_sarif(findings, base_filename)
        return reports

    def _generate_cloud_html(
        self,
        findings: List,
        resources: List,
        attack_paths: List,
        compliance_scores: Dict,
        config: Dict,
        base_filename: str
    ) -> Path:
        """Generate cloud-specific HTML report with attack path diagrams."""
        providers = config.get('providers', [])
        provider_str = ', '.join(p.upper() for p in providers) if providers else 'Cloud'

        # Severity counts
        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = self._get_finding_attr(f, 'severity', 'info')
            if hasattr(sev, 'value'):
                sev = sev.value
            sev_counts[str(sev).lower()] = sev_counts.get(str(sev).lower(), 0) + 1

        # Build compliance cards HTML
        compliance_html = ''
        for framework, score in compliance_scores.items():
            if isinstance(score, dict):
                pct = score.get('score', 0)
            else:
                pct = score
            compliance_html += f'''
            <div style="background:#1a1a2e;border-radius:8px;padding:16px;text-align:center;">
                <h4 style="margin:0;color:#888;">{framework}</h4>
                <div style="font-size:28px;font-weight:bold;color:{'#00c19f' if pct >= 70 else '#ff6b6b'};">{pct:.0f}%</div>
            </div>'''

        # Build attack path diagram HTML (Mermaid syntax wrapped in <pre>)
        attack_path_html = ''
        if attack_paths:
            mermaid_lines = ['graph LR']
            for idx, ap in enumerate(attack_paths[:5]):
                path = ap.get('path', [])
                if len(path) >= 2:
                    for i in range(len(path) - 1):
                        src = path[i].replace(' ', '_')
                        tgt = path[i + 1].replace(' ', '_')
                        mermaid_lines.append(f'    {src} --> {tgt}')
            mermaid_code = '\n'.join(mermaid_lines)
            attack_path_html = f'''
            <h2>Attack Paths</h2>
            <pre class="mermaid">{mermaid_code}</pre>
            <script type="module">
                import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
                mermaid.initialize({{startOnLoad:true, theme:'dark'}});
            </script>'''

        # Build findings table rows
        findings_rows = ''
        for f in findings[:100]:
            fid = self._get_finding_attr(f, 'id', '')
            title = self._get_finding_attr(f, 'title', '')
            sev = self._get_finding_attr(f, 'severity', 'info')
            if hasattr(sev, 'value'):
                sev = sev.value
            provider = self._get_finding_attr(f, 'provider', '')
            if hasattr(provider, 'value'):
                provider = provider.value
            service = self._get_finding_attr(f, 'service', '')
            resource_id = self._get_finding_attr(f, 'resource_id', '')
            findings_rows += f'''
            <tr>
                <td>{fid}</td>
                <td><span class="severity-{sev}">{sev}</span></td>
                <td>{title}</td>
                <td>{provider}</td>
                <td>{service}</td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">{resource_id}</td>
            </tr>'''

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cloud Security Report - {provider_str}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f0f1a; color: #e0e0e0; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #00c19f; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; margin: 20px 0; }}
        .summary-card {{ background: #1a1a2e; border-radius: 8px; padding: 16px; text-align: center; }}
        .summary-card h3 {{ margin: 0; font-size: 28px; }}
        .summary-card p {{ margin: 4px 0 0; color: #888; }}
        .severity-critical {{ background: #dc3545; padding: 2px 8px; border-radius: 4px; }}
        .severity-high {{ background: #fd7e14; padding: 2px 8px; border-radius: 4px; }}
        .severity-medium {{ background: #ffc107; color: #000; padding: 2px 8px; border-radius: 4px; }}
        .severity-low {{ background: #28a745; padding: 2px 8px; border-radius: 4px; }}
        .severity-info {{ background: #6c757d; padding: 2px 8px; border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #2a2a3e; }}
        th {{ background: #1a1a2e; }}
        .mermaid {{ background: #1a1a2e; padding: 20px; border-radius: 8px; }}
        .compliance-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }}
    </style>
</head>
<body>
<div class="container">
    <h1>☁️ Cloud Security Report</h1>
    <p>Providers: {provider_str} | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>

    <h2>Summary</h2>
    <div class="summary-grid">
        <div class="summary-card"><h3>{len(findings)}</h3><p>Total Findings</p></div>
        <div class="summary-card"><h3>{len(resources)}</h3><p>Resources</p></div>
        <div class="summary-card"><h3 style="color:#dc3545">{sev_counts['critical']}</h3><p>Critical</p></div>
        <div class="summary-card"><h3 style="color:#fd7e14">{sev_counts['high']}</h3><p>High</p></div>
        <div class="summary-card"><h3 style="color:#ffc107">{sev_counts['medium']}</h3><p>Medium</p></div>
        <div class="summary-card"><h3 style="color:#28a745">{sev_counts['low']}</h3><p>Low</p></div>
    </div>

    <h2>Compliance Scores</h2>
    <div class="compliance-grid">{compliance_html}</div>

    {attack_path_html}

    <h2>Findings</h2>
    <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Provider</th><th>Service</th><th>Resource</th></tr></thead>
        <tbody>{findings_rows}</tbody>
    </table>
</div>
</body>
</html>'''

        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        return path

    def _generate_cloud_json(
        self,
        findings: List,
        resources: List,
        attack_paths: List,
        compliance_scores: Dict,
        config: Dict,
        base_filename: str
    ) -> Path:
        """Generate cloud-specific JSON report."""
        report = {
            'report_id': str(uuid.uuid4())[:8],
            'generated_at': datetime.now().isoformat(),
            'providers': config.get('providers', []),
            'summary': {
                'total_findings': len(findings),
                'total_resources': len(resources),
                'attack_paths_count': len(attack_paths),
                'by_severity': {},
            },
            'compliance_scores': compliance_scores,
            'attack_paths': attack_paths[:20],
            'findings': [self._cloud_finding_to_dict(f) for f in findings],
            'resources': [self._cloud_resource_to_dict(r) for r in resources[:500]],
        }
        # Count by severity
        for f in findings:
            sev = self._get_finding_attr(f, 'severity', 'info')
            if hasattr(sev, 'value'):
                sev = sev.value
            sev = str(sev).lower()
            report['summary']['by_severity'][sev] = report['summary']['by_severity'].get(sev, 0) + 1

        path = self.output_dir / f"report_{base_filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        return path

    def _generate_cloud_sarif(self, findings: List, base_filename: str) -> Path:
        """Generate cloud findings in SARIF format."""
        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'Jarwis Cloud Scanner',
                        'informationUri': 'https://jarwis.ai',
                        'version': '2.0.0',
                        'rules': []
                    }
                },
                'results': []
            }]
        }
        for f in findings:
            fid = self._get_finding_attr(f, 'id', 'unknown')
            sev = self._get_finding_attr(f, 'severity', 'info')
            if hasattr(sev, 'value'):
                sev = sev.value
            desc = self._get_finding_attr(f, 'description', '')
            resource = self._get_finding_attr(f, 'resource_arn', '')
            sarif['runs'][0]['results'].append({
                'ruleId': fid,
                'level': self._sarif_level(str(sev)),
                'message': {'text': desc},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': resource}
                    }
                }]
            })
        path = self.output_dir / f"report_{base_filename}.sarif"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)
        return path

    def _cloud_finding_to_dict(self, finding) -> Dict:
        """Convert cloud finding to dict handling enums."""
        try:
            d = asdict(finding)
            # Convert enums to strings
            for k, v in d.items():
                if hasattr(v, 'value'):
                    d[k] = v.value
            return d
        except Exception:
            return {
                'id': getattr(finding, 'id', ''),
                'title': getattr(finding, 'title', ''),
                'severity': str(getattr(finding, 'severity', 'info')),
                'provider': str(getattr(finding, 'provider', '')),
                'service': getattr(finding, 'service', ''),
                'resource_id': getattr(finding, 'resource_id', ''),
                'description': getattr(finding, 'description', ''),
                'remediation': getattr(finding, 'remediation', ''),
            }

    def _cloud_resource_to_dict(self, resource) -> Dict:
        """Convert cloud resource to dict."""
        try:
            d = asdict(resource)
            for k, v in d.items():
                if hasattr(v, 'value'):
                    d[k] = v.value
            return d
        except Exception:
            return {
                'resource_id': getattr(resource, 'resource_id', ''),
                'resource_type': getattr(resource, 'resource_type', ''),
                'provider': str(getattr(resource, 'provider', '')),
                'name': getattr(resource, 'name', ''),
            }
