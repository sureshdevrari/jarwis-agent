"""
Jarwis AGI Pen Test - Professional Report Generator
Multi-format security report generation with PDF support

Features:
- Professional HTML reports with Jarwis branding
- PDF generation via WeasyPrint or fallback to HTML2PDF
- SARIF format for CI/CD integration
- JSON format for programmatic access
- Dynamic report templates
"""

import json
import logging
import base64
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
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
    
    JARWIS_LOGO_SVG_SMALL = '''<svg viewBox="0 0 500 500" width="50" height="50" xmlns="http://www.w3.org/2000/svg">
        <defs>
            <linearGradient id="logoGradSmall" x1="250" y1="111.235" x2="250" y2="383.576" gradientUnits="userSpaceOnUse">
                <stop offset="0" style="stop-color:#00C19F"/>
                <stop offset="1" style="stop-color:#256AD1"/>
            </linearGradient>
        </defs>
        <path fill="url(#logoGradSmall)" d="M343.73,166.48l-12.75-7.4L250,112.35l-25.51,14.73l-12.75,7.33l-80.97,46.8V318.8l25.5,14.72l12.75,7.4l12.75,7.33l12.75,7.39L250,387.65l25.51-14.73l12.75-7.4l12.75-7.33l12.75-7.33l55.47-32.07V181.21L343.73,166.48z M250,127.08l80.97,46.73v14.73l0,0v14.73l0,0v65.29l-12.75,7.14v-94.49l-12.75-7.4l-55.47-32l-12.75-7.33L250,127.08z M250,314.01L194.53,282V218L250,185.99L305.47,218v64.84L250,314.01z M143.53,188.54l80.97-46.73l12.75,7.33h0.07l12.69,7.39l55.47,32.01v14.72l-55.47-32l-12.75-7.4l-12.75-7.33l-12.75,7.4h-0.07l-55.41,32l-12.75,7.4V188.54z M143.53,311.47V218l12.75-7.33l12.75-7.4l55.41-32l12.81,7.4l-55.47,32L169.03,218l-12.75,7.39v93.41L143.53,311.47z M250,372.92l-55.47-32l-12.75-7.4l-12.75-7.33v-93.47l12.75-7.39v93.47v0.06l12.75,7.33L250,358.2l12.75,7.33L250,372.92z M275.51,358.2l-12.75-7.4L250,343.47l-55.47-32v-14.73l55.47,32l12.75,7.4l12.75,7.33l12.75,7.4L275.51,358.2z M356.47,311.47l-55.47,32l-12.75-7.33l55.47-32v-0.07l12.75-7.33V311.47z M356.47,282l-12.75,7.33l-12.75,7.4l-55.47,32l-12.63-7.27l68.09-38.32l12.75-7.14l12.75-7.2V282z M356.47,254.21l-12.75,7.13v-65.41v-14.72l12.75,7.33V254.21z"/>
        <polygon fill="#00C598" points="250,229.09 220.91,245.88 220.91,279.44 250,296.23 279.09,279.88 279.09,245.88"/>
        <path fill="#256AD1" d="M250,208.65c-13.03,0-23.62,10.6-23.62,23.63v5.37l7-4.04v-1.33c0-9.17,7.46-16.63,16.63-16.63c9.16,0,16.63,7.46,16.63,16.63v1.33l7,4.04v-5.37C273.62,219.25,263.02,208.65,250,208.65z"/>
        <polygon fill="#040B28" points="257.37,273.56 242.63,273.56 248,255.24 252,255.24"/>
        <circle fill="#040B28" cx="250" cy="254.83" r="5.69"/>
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
        self._executive_summary = executive_summary or self._generate_default_executive_summary(sorted_findings, context, config)
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
    
    def _generate_default_executive_summary(self, findings: List, context, config: Dict) -> str:
        """Generate a default executive summary based on findings"""
        severity_counts = self._count_by_severity(findings)
        total = len(findings)
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        
        target_url = config.get('target', {}).get('url', 'the target application')
        
        # Determine overall risk level
        if critical > 0:
            risk_level = "CRITICAL"
            risk_description = "The assessment has identified critical security vulnerabilities that pose an immediate and severe risk to the application and its users."
        elif high > 0:
            risk_level = "HIGH"
            risk_description = "The assessment has identified high-severity vulnerabilities that require prompt attention and remediation."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_description = "The assessment has identified moderate security issues that should be addressed in the near term."
        else:
            risk_level = "LOW"
            risk_description = "The assessment found minimal security issues. The application demonstrates good security practices."
        
        summary = f"""Jarwis AGI Security Testing Platform conducted a comprehensive security assessment of {target_url}. 

The assessment identified a total of {total} security findings: {critical} Critical, {high} High, {medium} Medium, {severity_counts.get('low', 0)} Low, and {severity_counts.get('info', 0)} Informational issues.

Overall Risk Assessment: {risk_level}

{risk_description}

The testing covered {len(context.endpoints)} unique endpoints using {"authenticated" if context.authenticated else "unauthenticated"} scanning techniques. All findings have been verified using Jarwis AGI-powered analysis to minimize false positives and provide accurate, actionable remediation guidance.

Immediate action is recommended for all Critical and High severity findings. Please refer to the detailed findings section for specific remediation steps."""
        
        return summary
    
    def _calculate_risk_score(self, findings: List) -> tuple:
        """Calculate overall risk score (0-100) and color"""
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
            color = "#dc2626"  # Critical - Red
            gradient = "#dc2626, #ea580c"
        elif score >= 50:
            color = "#ea580c"  # High - Orange
            gradient = "#ea580c, #d97706"
        elif score >= 25:
            color = "#d97706"  # Medium - Yellow
            gradient = "#d97706, #059669"
        else:
            color = "#059669"  # Low - Green
            gradient = "#059669, #0284c7"
        
        return score, color, gradient
    
    def _generate_professional_html(
        self,
        findings: List,
        context,
        config: Dict,
        base_filename: str,
        traffic_log: List = None
    ) -> Path:
        """Generate professional HTML report using template"""
        severity_counts = self._count_by_severity(findings)
        risk_score, risk_color, risk_gradient = self._calculate_risk_score(findings)
        traffic_log = traffic_log or []
        
        target_url = config['target']['url']
        scan_date = datetime.now().strftime('%B %d, %Y at %H:%M:%S')
        scan_type = config.get('target', {}).get('type', 'Web Application Security Assessment')
        
        # Build the HTML from template
        html = self._get_report_template()
        
        # Replace all placeholders
        replacements = {
            '{{TARGET_NAME}}': self._escape_html(target_url),
            '{{TARGET_URL}}': self._escape_html(target_url),
            '{{SCAN_DATE}}': scan_date,
            '{{REPORT_ID}}': self._report_id,
            '{{SCAN_TYPE}}': scan_type,
            '{{AUTH_STATUS}}': 'Authenticated Scan' if context.authenticated else 'Unauthenticated Scan',
            '{{TOTAL_FINDINGS}}': str(len(findings)),
            '{{CURRENT_YEAR}}': str(datetime.now().year),
            '{{CRITICAL_COUNT}}': str(severity_counts.get('critical', 0)),
            '{{HIGH_COUNT}}': str(severity_counts.get('high', 0)),
            '{{MEDIUM_COUNT}}': str(severity_counts.get('medium', 0)),
            '{{LOW_COUNT}}': str(severity_counts.get('low', 0)),
            '{{INFO_COUNT}}': str(severity_counts.get('info', 0)),
            '{{ENDPOINTS_TESTED}}': str(len(context.endpoints)),
            '{{RISK_SCORE}}': str(risk_score),
            '{{RISK_COLOR}}': risk_color,
            '{{RISK_GRADIENT}}': risk_gradient,
            '{{EXECUTIVE_SUMMARY}}': self._escape_html(self._executive_summary),
            '{{FINDINGS_HTML}}': self._generate_findings_html(findings),
            '{{TRAFFIC_LOG_HTML}}': self._generate_traffic_log_html(traffic_log),
            '{{JARWIS_LOGO_SVG}}': self.JARWIS_LOGO_SVG,
            '{{JARWIS_LOGO_SVG_SMALL}}': self.JARWIS_LOGO_SVG_SMALL,
        }
        
        for placeholder, value in replacements.items():
            html = html.replace(placeholder, value)
        
        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Professional HTML report saved: {path}")
        return path
    
    def _get_report_template(self) -> str:
        """Load report template or use embedded template"""
        template_path = self.template_dir / 'report_template.html'
        
        if template_path.exists():
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Fallback to embedded minimal template
        return self._get_embedded_template()
    
    def _get_embedded_template(self) -> str:
        """Embedded fallback template"""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Jarwis Security Report - {{TARGET_NAME}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #040B28 0%, #16213e 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
        .logo { width: 80px; height: 80px; margin-bottom: 20px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .meta { opacity: 0.8; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: white; border-radius: 10px; padding: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .card .value { font-size: 2.5em; font-weight: bold; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #d97706; }
        .low { color: #059669; }
        .info { color: #0284c7; }
        .finding { background: white; border-radius: 10px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid; }
        .finding.critical { border-left-color: #dc2626; }
        .finding.high { border-left-color: #ea580c; }
        .finding.medium { border-left-color: #d97706; }
        .finding.low { border-left-color: #059669; }
        .finding.info { border-left-color: #0284c7; }
        footer { text-align: center; padding: 40px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo">{{JARWIS_LOGO_SVG_SMALL}}</div>
            <h1>Jarwis Security Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {{TARGET_URL}}</p>
                <p><strong>Date:</strong> {{SCAN_DATE}}</p>
                <p><strong>Report ID:</strong> {{REPORT_ID}}</p>
            </div>
        </header>
        <section class="summary">
            <div class="card"><div class="value">{{TOTAL_FINDINGS}}</div><div>Total Findings</div></div>
            <div class="card"><div class="value critical">{{CRITICAL_COUNT}}</div><div>Critical</div></div>
            <div class="card"><div class="value high">{{HIGH_COUNT}}</div><div>High</div></div>
            <div class="card"><div class="value medium">{{MEDIUM_COUNT}}</div><div>Medium</div></div>
            <div class="card"><div class="value low">{{LOW_COUNT}}</div><div>Low</div></div>
        </section>
        <section>
            <h2>Executive Summary</h2>
            <p style="margin: 20px 0; line-height: 1.8;">{{EXECUTIVE_SUMMARY}}</p>
        </section>
        <section>
            <h2>Findings</h2>
            {{FINDINGS_HTML}}
        </section>
        <footer>
            <p>Generated by Jarwis AGI Security Testing | Report: {{REPORT_ID}}</p>
            <p>[OK]  {{CURRENT_YEAR}} BKD Labs</p>
        </footer>
    </div>
</body>
</html>'''
    
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
                await page.goto(f'file:///{html_path.absolute()}')
                await page.pdf(path=str(pdf_path), format='A4', print_background=True)
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
                page.goto(f'file:///{html_path.absolute()}')
                page.pdf(path=str(pdf_path), format='A4', print_background=True)
                browser.close()
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Playwright sync PDF failed: {e}")
        
        return False
    
    def _generate_findings_html(self, findings: List) -> str:
        """Generate HTML for findings section - Professional style"""
        html_parts = []
        
        for idx, f in enumerate(findings):
            severity = getattr(f, 'severity', 'info')
            poc = getattr(f, 'poc', '') or getattr(f, 'evidence', '') or 'N/A'
            reasoning = getattr(f, 'reasoning', '') or self._generate_reasoning(f)
            request_data = getattr(f, 'request_data', '') or 'N/A'
            response_data = getattr(f, 'response_data', getattr(f, 'response_snippet', '')) or 'N/A'
            cwe_id = getattr(f, 'cwe_id', '') or 'N/A'
            category = getattr(f, 'category', 'Unknown')
            finding_id = f"finding-{idx}"
            
            html_parts.append(f'''
            <div class="finding finding-severity-{severity}">
                <div class="finding-header">
                    <div class="finding-title-section">
                        <div class="finding-title">{self._escape_html(getattr(f, 'title', 'Security Issue'))}</div>
                        <div class="finding-tags">
                            <span class="finding-tag tag-category">{category} - {self.OWASP_CATEGORIES.get(category, 'Security Issue')}</span>
                            <span class="finding-tag tag-cwe">{cwe_id}</span>
                        </div>
                    </div>
                    <span class="severity-badge severity-{severity}">{severity.upper()}</span>
                </div>
                
                <div class="finding-body">
                    <p class="finding-description">{self._escape_html(getattr(f, 'description', 'No description available'))}</p>
                    
                    <div class="finding-details">
                        <div class="finding-detail-row">
                            <span class="finding-detail-label">URL:</span>
                            <span class="finding-detail-value">{self._escape_html(getattr(f, 'url', 'N/A'))}</span>
                        </div>
                        <div class="finding-detail-row">
                            <span class="finding-detail-label">Method:</span>
                            <span class="finding-detail-value">{getattr(f, 'method', 'N/A')}</span>
                        </div>
                        <div class="finding-detail-row">
                            <span class="finding-detail-label">Parameter:</span>
                            <span class="finding-detail-value">{self._escape_html(getattr(f, 'parameter', 'N/A') or 'N/A')}</span>
                        </div>
                    </div>
                    
                    <div class="reasoning-box">
                        <div class="reasoning-header">
                            <span>[!]  
                            <span>AI Verification & Reasoning</span>
                        </div>
                        <p>{self._escape_html(reasoning)}</p>
                    </div>
                    
                    <div class="evidence-box">
                        <div class="evidence-header">
                            <span class="evidence-icon">[!]  
                            <span class="evidence-title">Proof of Concept</span>
                        </div>
                        <pre class="evidence-content">{self._escape_html(poc)}</pre>
                    </div>
                    
                    <div class="http-viewer">
                        <div class="http-viewer-tabs">
                            <button class="http-viewer-tab active" id="{finding_id}-req-btn" onclick="showTab('{finding_id}', 'request')">[OK]  REQUEST</button>
                            <button class="http-viewer-tab" id="{finding_id}-res-btn" onclick="showTab('{finding_id}', 'response')">[OK]  RESPONSE</button>
                        </div>
                        <div id="{finding_id}-request" class="http-viewer-content">{self._escape_html(request_data)}</div>
                        <div id="{finding_id}-response" class="http-viewer-content" style="display: none;">{self._escape_html(response_data)}</div>
                    </div>
                    
                    <div class="remediation-box">
                        <div class="remediation-header">
                            <span>[*]   
                            <span>Remediation</span>
                        </div>
                        <p class="remediation-content">{self._escape_html(getattr(f, 'remediation', 'Review and fix according to OWASP guidelines.'))}</p>
                    </div>
                </div>
            </div>
            ''')
        
        return '\n'.join(html_parts) if html_parts else '<p style="text-align: center; color: #666; padding: 40px;">No vulnerabilities found. Great job!</p>'
    
    def _generate_traffic_log_html(self, traffic_log: List) -> str:
        """Generate HTML for traffic log section"""
        if not traffic_log:
            return '<p style="color: #666; text-align: center; padding: 40px;">No traffic captured during this scan.</p>'
        
        html_parts = [f'<p style="margin-bottom: 20px; color: #6b7280;">Total requests captured: <strong>{len(traffic_log)}</strong></p>']
        
        for i, entry in enumerate(traffic_log[:50]):  # Limit to first 50
            entry_type = entry.get('type', 'unknown')
            is_request = entry_type == 'request'
            
            badge_class = 'traffic-badge-request' if is_request else 'traffic-badge-response'
            badge_text = 'REQUEST' if is_request else 'RESPONSE'
            method = entry.get('method', 'GET') if is_request else ''
            
            headers_html = ''
            headers = entry.get('headers', {})
            for key, value in list(headers.items())[:10]:
                headers_html += f'<div><strong>{self._escape_html(key)}:</strong> {self._escape_html(str(value)[:100])}</div>'
            
            html_parts.append(f'''
            <div class="traffic-entry">
                <div class="traffic-entry-header">
                    {f'<span class="traffic-method">{method}</span>' if method else ''}
                    <span class="{badge_class}">{badge_text}</span>
                    <span class="traffic-url">{self._escape_html(entry.get("url", "N/A"))}</span>
                </div>
                <details>
                    <summary style="cursor: pointer; padding: 10px 0; color: #6b7280;">Headers ({len(headers)} items)</summary>
                    <div style="background: #f8fafc; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.85em;">
                        {headers_html}
                    </div>
                </details>
            </div>
            ''')
        
        if len(traffic_log) > 50:
            html_parts.append(f'<p style="text-align: center; color: #666; margin-top: 20px;">... and {len(traffic_log) - 50} more entries (see JSON report for full log)</p>')
        
        return '\n'.join(html_parts)
    
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
            return f"Jarwis tested the endpoint with SQL injection payloads and observed error messages or behavioral changes indicating the input is being interpreted as SQL code."
        elif 'xss' in title or 'cross-site' in title:
            return f"Jarwis injected XSS payloads and detected that user input is reflected in the response without proper encoding, allowing JavaScript execution."
        elif 'idor' in title:
            return f"Jarwis tested object references by modifying ID parameters and successfully accessed resources belonging to other users."
        elif 'csrf' in title:
            return f"Jarwis tested state-changing requests without CSRF tokens and the server accepted the requests."
        
        return f"Jarwis automated security testing detected this issue. Evidence: {evidence[:200] if evidence else 'See POC for details'}."
    
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
                        "informationUri": "https://bkdlabs.com/jarwis",
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
                "by_severity": self._count_by_severity(findings),
                "by_category": self._count_by_category(findings),
                "endpoints_tested": len(context.endpoints),
                "authenticated_scan": context.authenticated,
                "total_requests_captured": len(traffic_log) if traffic_log else 0,
                "executive_summary": self._executive_summary
            },
            "findings": [self._finding_to_dict(f) for f in findings],
            "traffic_log": traffic_log or []
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
