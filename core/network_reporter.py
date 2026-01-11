"""
Network Security Scan Reporter

Generates professional reports for network security scans.
Extends base reporter with network-specific formatting.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import asdict

from .reporters import ReportGenerator

logger = logging.getLogger(__name__)


class NetworkReportGenerator(ReportGenerator):
    """Specialized reporter for network security scans"""
    
    def __init__(self, output_dir: str, formats: List[str]):
        super().__init__(output_dir, formats)
    
    async def generate_network_report(
        self,
        findings: List,
        scan_config: Dict,
        scan_results: Dict,
        target: str
    ) -> List[str]:
        """
        Generate network security scan reports.
        
        Args:
            findings: List of Finding objects from network scan
            scan_config: Configuration dict with profile, ports, etc.
            scan_results: Raw scan results by tool
            target: Target IP/hostname/CIDR
        
        Returns:
            List of generated report file paths
        """
        generated = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Sanitize target for filename
        safe_target = target.replace('/', '_').replace(':', '_')
        base_filename = f"network_{safe_target}_{timestamp}"
        
        logger.info(f"Generating network report: {base_filename}")
        
        # Sort findings by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: self.SEVERITY_ORDER.get(getattr(f, 'severity', 'info'), 4)
        )
        
        # Build network-specific context
        context = {
            'target': target,
            'profile': scan_config.get('profile', 'standard'),
            'ports_scanned': scan_config.get('ports', 'top 1000'),
            'scan_results': scan_results,
            'scan_date': datetime.now().isoformat(),
        }
        
        for fmt in self.formats:
            if fmt == 'json':
                path = self._generate_network_json(sorted_findings, context, base_filename)
            elif fmt == 'sarif':
                path = self._generate_sarif(sorted_findings, base_filename)
            elif fmt == 'html':
                path = self._generate_network_html(sorted_findings, context, base_filename)
            elif fmt == 'pdf':
                html_path = self._generate_network_html(sorted_findings, context, base_filename)
                if html_path:
                    path = await self._generate_pdf(html_path, base_filename)
            else:
                continue
            
            if path:
                generated.append(str(path))
        
        return generated
    
    def _generate_network_json(
        self,
        findings: List,
        context: Dict,
        base_filename: str
    ) -> Path:
        """Generate JSON report for network scan"""
        severity_counts = self._count_by_severity(findings)
        
        report = {
            'report_type': 'network_security_scan',
            'generated_at': datetime.now().isoformat(),
            'scanner': 'Jarwis AGI Network Security Scanner',
            'target': context['target'],
            'scan_profile': context['profile'],
            'summary': {
                'total_findings': len(findings),
                'critical': severity_counts['critical'],
                'high': severity_counts['high'],
                'medium': severity_counts['medium'],
                'low': severity_counts['low'],
                'info': severity_counts['info'],
            },
            'findings': [self._network_finding_to_dict(f) for f in findings],
            'scan_details': {
                'target': context['target'],
                'profile': context['profile'],
                'ports_scanned': context['ports_scanned'],
                'scan_date': context['scan_date'],
            },
            'tools_used': list(context.get('scan_results', {}).keys()),
        }
        
        path = self.output_dir / f"report_{base_filename}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Generated JSON report: {path}")
        return path
    
    def _generate_network_html(
        self,
        findings: List,
        context: Dict,
        base_filename: str
    ) -> Optional[Path]:
        """Generate HTML report for network scan"""
        severity_counts = self._count_by_severity(findings)
        risk_score, risk_color, risk_gradient, risk_level = self._calculate_risk_score(findings)
        
        # Build statistics
        stats = {
            'total_findings': len(findings),
            'critical': severity_counts['critical'],
            'high': severity_counts['high'],
            'medium': severity_counts['medium'],
            'low': severity_counts['low'],
            'info': severity_counts['info'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
        }
        
        # Group findings by IP/port
        findings_by_target = {}
        for f in findings:
            ip = getattr(f, 'ip_address', 'unknown')
            if ip not in findings_by_target:
                findings_by_target[ip] = []
            findings_by_target[ip].append(f)
        
        # Generate HTML
        html = self._render_network_html_template(
            findings=findings,
            findings_by_target=findings_by_target,
            stats=stats,
            context=context,
        )
        
        path = self.output_dir / f"report_{base_filename}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        logger.info(f"Generated HTML report: {path}")
        return path
    
    def _render_network_html_template(
        self,
        findings: List,
        findings_by_target: Dict,
        stats: Dict,
        context: Dict
    ) -> str:
        """Render network scan HTML template"""
        
        # Build findings HTML
        findings_html = ""
        for ip, ip_findings in findings_by_target.items():
            findings_html += f'''
            <div class="target-section">
                <h3 style="color: #2563eb; border-bottom: 2px solid #2563eb; padding-bottom: 8px;">
                    🎯 Target: {self._escape_html(ip)}
                </h3>
            '''
            
            for f in ip_findings:
                severity = getattr(f, 'severity', 'info').lower()
                severity_colors = {
                    'critical': '#dc2626',
                    'high': '#ea580c',
                    'medium': '#f59e0b',
                    'low': '#eab308',
                    'info': '#6b7280'
                }
                color = severity_colors.get(severity, '#6b7280')
                
                port = getattr(f, 'port', 'N/A')
                service = getattr(f, 'service', 'unknown')
                cve_id = getattr(f, 'cve_id', '')
                cvss_score = getattr(f, 'cvss_score', '')
                
                findings_html += f'''
                <div class="finding-card" style="border-left: 4px solid {color}; margin: 16px 0; padding: 16px; background: #f9fafb; border-radius: 8px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                        <h4 style="margin: 0; color: #111827;">{self._escape_html(getattr(f, 'title', 'Unknown Issue'))}</h4>
                        <span style="background: {color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: bold;">
                            {severity.upper()}
                        </span>
                    </div>
                    
                    <div style="color: #6b7280; font-size: 14px; margin-bottom: 8px;">
                        <strong>Port:</strong> {port} | <strong>Service:</strong> {service}
                        {f' | <strong>CVE:</strong> {cve_id}' if cve_id else ''}
                        {f' | <strong>CVSS:</strong> {cvss_score}' if cvss_score else ''}
                    </div>
                    
                    <p style="color: #374151; line-height: 1.6; margin: 8px 0;">
                        {self._escape_html(getattr(f, 'description', 'No description available'))}
                    </p>
                    
                    {f'<div style="background: #1f2937; color: #e5e7eb; padding: 12px; border-radius: 4px; font-family: monospace; font-size: 13px; overflow-x: auto; margin-top: 8px;"><pre style="margin: 0;">{self._escape_html(getattr(f, "evidence", ""))}</pre></div>' if getattr(f, "evidence", "") else ''}
                    
                    {f'<div style="margin-top: 12px; padding: 12px; background: #dbeafe; border-left: 3px solid #2563eb; border-radius: 4px;"><strong style="color: #1e40af;">💡 Remediation:</strong><br>{self._escape_html(getattr(f, "remediation", ""))}</div>' if getattr(f, "remediation", "") else ''}
                </div>
                '''
            
            findings_html += "</div>"
        
        # Build full HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report - {self._escape_html(context["target"])}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 40px; padding-bottom: 20px; border-bottom: 3px solid #2563eb; }}
        .logo {{ margin-bottom: 20px; }}
        h1 {{ color: #111827; font-size: 32px; margin: 16px 0; }}
        h2 {{ color: #374151; font-size: 24px; margin: 24px 0 16px 0; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ font-size: 36px; margin-bottom: 8px; }}
        .summary-card p {{ font-size: 14px; opacity: 0.9; }}
        .target-section {{ margin: 24px 0; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 2px solid #e5e7eb; text-align: center; color: #6b7280; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">{self.JARWIS_LOGO_SVG}</div>
            <h1>Network Security Scan Report</h1>
            <p style="color: #6b7280; font-size: 16px; margin-top: 8px;">
                Target: <strong>{self._escape_html(context["target"])}</strong><br>
                Scan Profile: <strong>{context["profile"].upper()}</strong><br>
                Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </p>
        </div>
        
        <div class="summary">
            <div class="summary-card" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
                <h3>{stats["total_findings"]}</h3>
                <p>Total Findings</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <h3>{stats["critical"]}</h3>
                <p>Critical</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <h3>{stats["high"]}</h3>
                <p>High</p>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);">
                <h3>{stats["medium"]}</h3>
                <p>Medium</p>
            </div>
        </div>
        
        <h2>🔍 Detailed Findings</h2>
        {findings_html if findings else '<p style="color: #6b7280; text-align: center; padding: 40px;">✅ No vulnerabilities found!</p>'}
        
        <div class="footer">
            <p>Generated by <strong>Jarwis AGI Network Security Scanner</strong></p>
            <p style="margin-top: 8px;">© 2026 Jarwis Security. All rights reserved.</p>
        </div>
    </div>
</body>
</html>'''
        
        return html
    
    def _network_finding_to_dict(self, finding) -> Dict:
        """Convert network finding to dictionary"""
        try:
            return asdict(finding)
        except:
            return {
                'id': getattr(finding, 'id', 'unknown'),
                'title': getattr(finding, 'title', ''),
                'description': getattr(finding, 'description', ''),
                'severity': getattr(finding, 'severity', 'info'),
                'category': getattr(finding, 'category', ''),
                'ip_address': getattr(finding, 'ip_address', ''),
                'port': getattr(finding, 'port', 'N/A'),
                'service': getattr(finding, 'service', 'unknown'),
                'cve_id': getattr(finding, 'cve_id', ''),
                'cvss_score': getattr(finding, 'cvss_score', ''),
                'evidence': getattr(finding, 'evidence', ''),
                'remediation': getattr(finding, 'remediation', ''),
            }
