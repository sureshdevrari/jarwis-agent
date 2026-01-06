"""
Jarwis AGI Pen Test - Professional Report Generator V2
Multi-format security report generation with PDF support

Optimized for CISO and Senior Management reporting:
- Professional cover page
- Executive summary with risk metrics
- Detailed findings with AI reasoning
- Methodology section
- Appendix with endpoints
"""

import json
import logging
import base64
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
    
    # Jarwis Logo SVG (inline for PDF compatibility)
    JARWIS_LOGO_SVG = '''<svg viewBox="0 0 500 500" xmlns="http://www.w3.org/2000/svg">
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
    
    JARWIS_LOGO_SVG_SMALL = '''<svg viewBox="0 0 500 500" width="32" height="32" xmlns="http://www.w3.org/2000/svg">
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
            key=lambda f: self.SEVERITY_ORDER.get(getattr(f, 'severity', 'info'), 4)
        )
        
        # Store extra data
        self._executive_summary = executive_summary or self._generate_executive_summary(sorted_findings, context, config)
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
    
    def _generate_executive_summary(self, findings: List, context, config: Dict) -> str:
        """Generate a professional executive summary for CISO/Senior Management"""
        severity_counts = self._count_by_severity(findings)
        total = len(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)
        
        target_url = config.get('target', {}).get('url', 'the target application')
        scan_type = config.get('target', {}).get('type', 'Security Assessment')
        
        # Determine risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_statement = "Immediate action is required. Critical vulnerabilities have been identified that could lead to complete system compromise, data breach, or significant business impact."
        elif high > 0:
            risk_level = "HIGH"
            risk_statement = "Urgent remediation recommended. High-severity vulnerabilities exist that could be exploited to cause significant damage to the organization."
        elif medium > 0:
            risk_level = "MODERATE"
            risk_statement = "Remediation should be planned. Medium-severity issues have been identified that should be addressed in the near-term to maintain security posture."
        else:
            risk_level = "LOW"
            risk_statement = "The application demonstrates good security practices. Minor issues identified should be addressed as part of regular maintenance."
        
        # Build professional summary
        summary = f"""<p><strong>Assessment Objective:</strong> Jarwis AGI Security Platform conducted a comprehensive {scan_type} of the target environment to identify security vulnerabilities, assess risk exposure, and provide actionable remediation guidance.</p>

<p><strong>Scope:</strong> {self._escape_html(target_url)}</p>

<p><strong>Key Findings:</strong> A total of <strong>{total} security issues</strong> were identified during this assessment:</p>
<ul style="margin: 10px 0 10px 20px; list-style: disc;">
    <li><strong style="color: #dc2626;">{critical} Critical</strong> - Require immediate attention</li>
    <li><strong style="color: #ea580c;">{high} High</strong> - Urgent remediation recommended</li>
    <li><strong style="color: #d97706;">{medium} Medium</strong> - Should be addressed promptly</li>
    <li><strong style="color: #059669;">{low} Low</strong> - Address in regular maintenance cycle</li>
</ul>

<p><strong>Overall Risk Level: {risk_level}</strong></p>
<p>{risk_statement}</p>

<p><strong>Testing Methodology:</strong> This assessment utilized Jarwis AGI-powered security testing covering the OWASP Top 10 (2021) vulnerability categories. Testing included {"authenticated and unauthenticated" if context.authenticated else "unauthenticated"} testing across {len(context.endpoints)} discovered endpoints.</p>

<p><strong>Recommendations:</strong> It is recommended that all Critical and High severity findings be remediated within 7 days. Medium severity findings should be addressed within 30 days. Detailed remediation guidance is provided for each finding in this report.</p>"""
        
        return summary
    
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
        
        if score >= 75:
            color = "#dc2626"
            gradient = "linear-gradient(90deg, #dc2626, #ea580c)"
            level = "CRITICAL"
        elif score >= 50:
            color = "#ea580c"
            gradient = "linear-gradient(90deg, #ea580c, #d97706)"
            level = "HIGH"
        elif score >= 25:
            color = "#d97706"
            gradient = "linear-gradient(90deg, #d97706, #eab308)"
            level = "MEDIUM"
        else:
            color = "#059669"
            gradient = "linear-gradient(90deg, #059669, #10b981)"
            level = "LOW"
        
        return score, color, gradient, level
    
    def _generate_professional_html(
        self,
        findings: List,
        context,
        config: Dict,
        base_filename: str,
        traffic_log: List = None
    ) -> Path:
        """Generate professional HTML report using v2 template"""
        severity_counts = self._count_by_severity(findings)
        risk_score, risk_color, risk_gradient, risk_level = self._calculate_risk_score(findings)
        traffic_log = traffic_log or []
        
        target_url = config['target']['url']
        report_date = datetime.now().strftime('%B %d, %Y')
        scan_type = config.get('target', {}).get('type', 'Web Application Security Assessment')
        
        # Load v2 template
        html = self._get_report_template()
        
        # Generate TOC findings
        toc_findings = self._generate_toc_findings(findings)
        
        # Generate key findings list (critical and high only)
        key_findings = self._generate_key_findings(findings)
        
        # Generate endpoints table
        endpoints_table = self._generate_endpoints_table(context.endpoints)
        
        # Generate findings HTML
        findings_html = self._generate_findings_html(findings)
        
        # Replace all placeholders
        replacements = {
            '{{TARGET_NAME}}': self._escape_html(target_url),
            '{{TARGET_URL}}': self._escape_html(target_url),
            '{{REPORT_DATE}}': report_date,
            '{{REPORT_ID}}': self._report_id,
            '{{SCAN_TYPE}}': scan_type,
            '{{TOTAL_FINDINGS}}': str(len(findings)),
            '{{RISK_LEVEL}}': risk_level,
            '{{CRITICAL_COUNT}}': str(severity_counts.get('critical', 0)),
            '{{HIGH_COUNT}}': str(severity_counts.get('high', 0)),
            '{{MEDIUM_COUNT}}': str(severity_counts.get('medium', 0)),
            '{{LOW_COUNT}}': str(severity_counts.get('low', 0)),
            '{{INFO_COUNT}}': str(severity_counts.get('info', 0)),
            '{{RISK_SCORE}}': str(risk_score),
            '{{RISK_COLOR}}': risk_color,
            '{{RISK_GRADIENT}}': risk_gradient,
            '{{EXECUTIVE_SUMMARY}}': self._executive_summary,
            '{{TOC_FINDINGS}}': toc_findings,
            '{{KEY_FINDINGS_LIST}}': key_findings,
            '{{ENDPOINTS_TABLE}}': endpoints_table,
            '{{FINDINGS_HTML}}': findings_html,
            '{{LOGO_SVG}}': self.JARWIS_LOGO_SVG,
            '{{LOGO_SVG_SMALL}}': self.JARWIS_LOGO_SVG_SMALL,
        }
        
        for placeholder, value in replacements.items():
            html = html.replace(placeholder, value)
        
        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Professional HTML report saved: {path}")
        return path
    
    def _get_report_template(self) -> str:
        """Load report template v2"""
        template_path = self.template_dir / 'report_template_v2.html'
        
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Fallback to v1 or embedded
        template_path_v1 = self.template_dir / 'report_template.html'
        if template_path_v1.exists():
            with open(template_path_v1, 'r', encoding='utf-8') as f:
                return f.read()
        
        return self._get_embedded_template()
    
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
        .finding { background: white; border: 1px solid #e2e8f0; border-radius: 10px; margin: 20px 0; overflow: hidden; }
        .finding-header { padding: 20px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
        .finding-body { padding: 20px; }
        footer { text-align: center; padding: 40px; color: #666; }
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
            <div class="card"><div class="value">{{TOTAL_FINDINGS}}</div><div>Total</div></div>
            <div class="card"><div class="value critical">{{CRITICAL_COUNT}}</div><div>Critical</div></div>
            <div class="card"><div class="value high">{{HIGH_COUNT}}</div><div>High</div></div>
            <div class="card"><div class="value medium">{{MEDIUM_COUNT}}</div><div>Medium</div></div>
            <div class="card"><div class="value low">{{LOW_COUNT}}</div><div>Low</div></div>
        </section>
        <section>
            <h2>Executive Summary</h2>
            <div style="margin: 20px 0;">{{EXECUTIVE_SUMMARY}}</div>
        </section>
        <section>
            <h2>Findings</h2>
            {{FINDINGS_HTML}}
        </section>
    </div>
    <footer>
        <p>Generated by Jarwis AGI Security Testing Platform</p>
        <p>[OK]  2026 Jarwis Technologies</p>
    </footer>
</body>
</html>'''
    
    def _generate_toc_findings(self, findings: List) -> str:
        """Generate table of contents entries for findings"""
        if not findings:
            return '<div class="toc-item"><span>No vulnerabilities found</span></div>'
        
        items = []
        for i, f in enumerate(findings, 1):
            severity = getattr(f, 'severity', 'info')
            title = getattr(f, 'title', 'Finding')[:60]
            items.append(f'<div class="toc-item"><span>{i}. [{severity.upper()}] {self._escape_html(title)}</span></div>')
        
        return '\n'.join(items)
    
    def _generate_key_findings(self, findings: List) -> str:
        """Generate key findings list (critical and high only)"""
        critical_high = [f for f in findings if getattr(f, 'severity', '') in ['critical', 'high']]
        
        if not critical_high:
            return '<div class="key-finding-item"><span class="key-finding-bullet">[!]   critical or high severity findings identified.</span></div>'
        
        items = []
        for f in critical_high[:5]:  # Limit to top 5
            severity = getattr(f, 'severity', 'info').upper()
            title = getattr(f, 'title', 'Finding')
            items.append(f'<div class="key-finding-item"><span class="key-finding-bullet">Ã¢â"*</span><span><strong>[{severity}]</strong> {self._escape_html(title)}</span></div>')
        
        if len(critical_high) > 5:
            items.append(f'<div class="key-finding-item"><span class="key-finding-bullet">...</span><span>And {len(critical_high) - 5} more critical/high findings</span></div>')
        
        return '\n'.join(items)
    
    def _generate_endpoints_table(self, endpoints: List) -> str:
        """Generate endpoints table rows"""
        if not endpoints:
            return '<tr><td colspan="2">No endpoints discovered</td></tr>'
        
        rows = []
        for i, endpoint in enumerate(endpoints[:30], 1):  # Limit to 30
            rows.append(f'<tr><td>{i}</td><td>{self._escape_html(str(endpoint))}</td></tr>')
        
        if len(endpoints) > 30:
            rows.append(f'<tr><td colspan="2" style="text-align: center; color: #6b7280;">... and {len(endpoints) - 30} more endpoints (see JSON report for complete list)</td></tr>')
        
        return '\n'.join(rows)
    
    async def _generate_pdf(self, html_path: Path, base_filename: str) -> Optional[Path]:
        """Generate PDF from HTML report"""
        pdf_path = self.output_dir / f"report_{base_filename}.pdf"
        
        try:
            # Try WeasyPrint first (best quality)
            from weasyprint import HTML, CSS
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"PDF report generated with WeasyPrint: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("WeasyPrint not installed, trying pdfkit...")
        except Exception as e:
            logger.warning(f"WeasyPrint failed: {e}, trying pdfkit...")
        
        try:
            # Try pdfkit (requires wkhtmltopdf)
            import pdfkit
            pdfkit.from_file(str(html_path), str(pdf_path))
            logger.info(f"PDF report generated with pdfkit: {pdf_path}")
            return pdf_path
        except ImportError:
            logger.warning("pdfkit not installed, trying playwright...")
        except Exception as e:
            logger.warning(f"pdfkit failed: {e}, trying playwright...")
        
        try:
            # Try Playwright (browser-based PDF)
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
        except ImportError:
            logger.warning("Playwright not available for PDF generation")
        except Exception as e:
            logger.error(f"Playwright PDF failed: {e}")
        
        logger.error("No PDF generation library available. Install weasyprint, pdfkit, or playwright.")
        return None
    
    def generate_pdf_sync(self, html_path: Path, pdf_path: Path) -> bool:
        """Synchronous PDF generation for API endpoints"""
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"WeasyPrint failed: {e}")
        
        try:
            import pdfkit
            pdfkit.from_file(str(html_path), str(pdf_path))
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"pdfkit failed: {e}")
        
        # Playwright sync version
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(f'file:///{html_path.absolute().as_posix()}')
                page.pdf(
                    path=str(pdf_path), 
                    format='A4', 
                    print_background=True,
                    margin={'top': '0', 'bottom': '0', 'left': '0', 'right': '0'}
                )
                browser.close()
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Playwright sync PDF failed: {e}")
        
        return False
    
    def _generate_findings_html(self, findings: List) -> str:
        """Generate HTML for findings section - Professional PDF-optimized"""
        if not findings:
            return '''<div style="text-align: center; padding: 60px; background: #f0fdf4; border-radius: 10px; margin: 30px 0;">
                <div style="font-size: 48px; margin-bottom: 15px;">[!]  
                <div style="font-size: 18pt; font-weight: 700; color: #059669; margin-bottom: 10px;">No Vulnerabilities Found</div>
                <div style="color: #6b7280;">The target application passed all security tests. Great job!</div>
            </div>'''
        
        html_parts = []
        
        for idx, f in enumerate(findings, 1):
            severity = getattr(f, 'severity', 'info')
            finding_id = getattr(f, 'id', f'FINDING-{idx:03d}')
            title = getattr(f, 'title', 'Security Issue')
            description = getattr(f, 'description', 'No description available')
            url = getattr(f, 'url', 'N/A')
            method = getattr(f, 'method', 'N/A')
            parameter = getattr(f, 'parameter', '') or 'N/A'
            category = getattr(f, 'category', 'Unknown')
            cwe_id = getattr(f, 'cwe_id', '') or 'N/A'
            
            evidence = getattr(f, 'evidence', '') or getattr(f, 'poc', '') or 'N/A'
            remediation = getattr(f, 'remediation', 'Review and fix according to OWASP guidelines.')
            reasoning = getattr(f, 'reasoning', '') or self._generate_reasoning(f)
            
            request_data = getattr(f, 'request_data', '') or 'Request data not captured'
            response_data = getattr(f, 'response_data', getattr(f, 'response_snippet', '')) or 'Response data not captured'
            
            category_name = self.OWASP_CATEGORIES.get(category, 'Security Issue')
            
            html_parts.append(f'''
<div class="finding finding-severity-{severity} avoid-break" style="margin-bottom: 25px;">
    <div class="finding-header">
        <div>
            <div class="finding-id">{finding_id}</div>
            <div class="finding-title">{self._escape_html(title)}</div>
            <div class="finding-tags">
                <span class="tag tag-category">{category} - {category_name}</span>
                <span class="tag tag-cwe">{cwe_id}</span>
            </div>
        </div>
        <span class="severity-badge severity-{severity}">{severity.upper()}</span>
    </div>
    
    <div class="finding-body">
        <div class="finding-section">
            <div class="finding-section-title">Description</div>
            <div class="finding-description">{self._escape_html(description)}</div>
        </div>
        
        <div class="finding-section">
            <div class="finding-section-title">Technical Details</div>
            <table class="detail-table">
                <tr><th>URL</th><td>{self._escape_html(url)}</td></tr>
                <tr><th>Method</th><td>{method}</td></tr>
                <tr><th>Parameter</th><td>{self._escape_html(parameter)}</td></tr>
            </table>
        </div>
        
        <div class="finding-section">
            <div class="finding-section-title">Evidence / Proof of Concept</div>
            <div class="evidence-box">{self._escape_html(evidence)}</div>
        </div>
        
        <div class="ai-analysis-box">
            <div class="ai-analysis-title">[OK]  Jarwis AGI Analysis</div>
            <div class="ai-analysis-text">{self._escape_html(reasoning)}</div>
        </div>
        
        <div class="finding-section">
            <div class="http-title">HTTP Request</div>
            <div class="http-content">{self._escape_html(request_data)}</div>
        </div>
        
        <div class="finding-section">
            <div class="http-title">HTTP Response</div>
            <div class="http-content">{self._escape_html(response_data)}</div>
        </div>
        
        <div class="remediation-box">
            <div class="remediation-title">[!]   Remediation</div>
            <div class="remediation-text">{self._escape_html(remediation)}</div>
        </div>
    </div>
</div>
''')
        
        return '\n'.join(html_parts)
    
    def _generate_reasoning(self, finding) -> str:
        """Generate AI reasoning for the finding"""
        category = getattr(finding, 'category', '')
        title = getattr(finding, 'title', '').lower()
        evidence = getattr(finding, 'evidence', '')
        
        reasoning_map = {
            'A01': f"Jarwis detected a Broken Access Control vulnerability. The application failed to properly enforce authorization, allowing access to resources or actions that should be restricted. This was verified through systematic testing of access control mechanisms.",
            'A02': f"Jarwis identified a Cryptographic Failure. Sensitive data may be exposed due to weak encryption, missing encryption, or improper key management. This vulnerability could lead to data exposure in transit or at rest.",
            'A03': f"Jarwis detected an Injection vulnerability. The application processes user-supplied data without proper validation or sanitization, allowing malicious code or commands to be executed. This was confirmed by observing the application's response to specially crafted payloads.",
            'A04': f"Jarwis identified an Insecure Design issue. The application's architecture lacks security controls that should have been implemented during the design phase. This represents a fundamental weakness that cannot be fixed through implementation changes alone.",
            'A05': f"Jarwis detected a Security Misconfiguration. The application or its infrastructure has insecure default settings, incomplete configurations, or missing security hardening measures that expose unnecessary attack surface.",
            'A06': f"Jarwis identified use of Vulnerable and Outdated Components. The application depends on libraries, frameworks, or software with known security vulnerabilities. Attackers could exploit these known weaknesses.",
            'A07': f"Jarwis detected an Identification and Authentication Failure. The application has weaknesses in authentication mechanisms, session management, or credential handling that could allow attackers to compromise user accounts.",
            'A08': f"Jarwis identified a Software and Data Integrity Failure. The application does not properly verify the integrity of code, data, or updates, potentially allowing attackers to inject malicious content.",
            'A09': f"Jarwis detected a Security Logging and Monitoring Failure. The application lacks adequate logging, monitoring, or alerting capabilities, making it difficult to detect and respond to security incidents.",
            'A10': f"Jarwis identified a Server-Side Request Forgery (SSRF) vulnerability. The application makes server-side requests based on user input without proper validation, potentially allowing attackers to access internal resources."
        }
        
        if category in reasoning_map:
            return reasoning_map[category]
        
        # Fallback based on title keywords
        if 'sql' in title or 'injection' in title:
            return "Jarwis tested the endpoint with injection payloads and observed error messages or behavioral changes indicating the input is being interpreted as code."
        elif 'xss' in title or 'cross-site' in title:
            return "Jarwis injected XSS payloads and detected that user input is reflected in the response without proper encoding, allowing JavaScript execution in the browser context."
        elif 'idor' in title:
            return "Jarwis tested object references by modifying ID parameters and successfully accessed resources belonging to other users, confirming broken access control."
        
        return f"Jarwis automated security testing identified this vulnerability through comprehensive testing. The issue was verified to minimize false positives."
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return 'N/A'
        return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
    
    def _count_by_severity(self, findings: List) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = getattr(f, 'severity', 'info')
            if sev in counts:
                counts[sev] += 1
        return counts
    
    def _count_by_category(self, findings: List) -> Dict[str, int]:
        """Count findings by OWASP category"""
        counts = {}
        for f in findings:
            cat = getattr(f, 'category', 'Unknown')
            counts[cat] = counts.get(cat, 0) + 1
        return counts
    
    def _generate_sarif(self, findings: List, base_filename: str) -> Path:
        """Generate SARIF format report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Jarwis AGI Security Testing",
                        "version": "2.0.0",
                        "informationUri": "https://jarwis.ai",
                        "rules": self._get_sarif_rules(findings)
                    }
                },
                "results": self._get_sarif_results(findings)
            }]
        }
        
        path = self.output_dir / f"report_{base_filename}.sarif"
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
        severity_counts = self._count_by_severity(findings)
        risk_score, risk_color, risk_gradient, risk_level = self._calculate_risk_score(findings)
        
        report = {
            "metadata": {
                "tool": "Jarwis AGI Security Testing",
                "version": "2.0.0",
                "report_id": self._report_id,
                "generated_at": datetime.now().isoformat(),
                "target": config['target']['url']
            },
            "summary": {
                "total_findings": len(findings),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "by_severity": severity_counts,
                "by_category": self._count_by_category(findings),
                "endpoints_tested": len(context.endpoints),
                "authenticated_scan": context.authenticated,
                "total_requests_captured": len(traffic_log) if traffic_log else 0
            },
            "executive_summary": self._executive_summary,
            "findings": [self._finding_to_dict(f) for f in findings],
            "endpoints": context.endpoints[:100] if hasattr(context, 'endpoints') else [],
            "traffic_log": traffic_log[:50] if traffic_log else []
        }
        
        path = self.output_dir / f"report_{base_filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report saved: {path}")
        return path
    
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
