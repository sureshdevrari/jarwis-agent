// WebSecurity.jsx
// Web Application Security Solution Page

import { 
  SolutionHero, 
  CapabilitiesGrid, 
  AIEngineSection, 
  ScanProcessSteps,
  ComplianceSection,
  SolutionCTA,
  SolutionFooter 
} from '../../components/solutions';
import ScanLayersAnimation from '../../components/solutions/ScanLayersAnimation';
import { ScrollProgressBar, RevealOnScroll } from '../../components/ui';

const WebSecurity = () => {
  const capabilities = [
    {
      title: 'SQL Injection Detection',
      description: 'Advanced SQLi testing including blind, time-based, and error-based injection across all database types.',
      tags: ['OWASP A03', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
        </svg>
      )
    },
    {
      title: 'Cross-Site Scripting (XSS)',
      description: 'Comprehensive XSS detection including reflected, stored, and DOM-based variants with context-aware payloads.',
      tags: ['OWASP A03', 'High'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'Broken Access Control',
      description: 'IDOR, path traversal, privilege escalation, and horizontal access control bypass detection.',
      tags: ['OWASP A01', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      )
    },
    {
      title: 'Authentication Bypass',
      description: 'Brute force, credential stuffing, session hijacking, JWT vulnerabilities, and OAuth misconfigurations.',
      tags: ['OWASP A07', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    },
    {
      title: 'CSRF Protection Testing',
      description: 'Cross-Site Request Forgery detection with token analysis and bypass techniques.',
      tags: ['OWASP A07', 'Medium'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      )
    },
    {
      title: 'SSRF Detection',
      description: 'Server-Side Request Forgery testing including internal network scanning and cloud metadata access.',
      tags: ['OWASP A10', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
      )
    },
    {
      title: 'API Security Testing',
      description: 'REST, GraphQL, and WebSocket security analysis including rate limiting, auth, and data exposure.',
      tags: ['OWASP API', 'High'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Security Headers Analysis',
      description: 'CORS, CSP, HSTS, X-Frame-Options, and other security header misconfiguration detection.',
      tags: ['OWASP A05', 'Medium'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      )
    },
    {
      title: 'File Upload Vulnerabilities',
      description: 'Unrestricted file upload, extension bypass, content-type manipulation, and webshell detection.',
      tags: ['OWASP A04', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
        </svg>
      )
    },
    {
      title: 'Template Injection (SSTI)',
      description: 'Server-Side Template Injection detection across popular frameworks like Jinja2, Twig, and Freemarker.',
      tags: ['OWASP A03', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
        </svg>
      )
    },
    {
      title: 'XXE Injection',
      description: 'XML External Entity injection testing for data exfiltration and SSRF via XML parsers.',
      tags: ['OWASP A05', 'High'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Open Redirect',
      description: 'URL redirection vulnerability detection that can lead to phishing and credential theft.',
      tags: ['OWASP A05', 'Medium'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      )
    }
  ];

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Scroll Progress Bar */}
      <ScrollProgressBar />

      {/* Hero Section */}
      <SolutionHero
        badge="Web Application Security"
        title="Enterprise-Grade"
        titleHighlight="Web Security Testing"
        description="Comprehensive OWASP Top 10 coverage with 99+ security scanners. Automated crawling, authenticated testing, and AI-powered vulnerability verification."
        scanType="web"
        stats={[
          { value: '99+', label: 'Security Scanners' },
          { value: 'OWASP', label: 'Top 10 Coverage' },
          { value: '< 0.5%', label: 'False Positives' }
        ]}
      />

      {/* Scan Layers Demo Section */}
      <section className="py-20 lg:py-32 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Multi-Layer Security Analysis
              </h2>
              <p className="text-lg text-gray-400 mb-8">
                JARWIS doesn't just run surface-level scans. Our engine performs deep, 
                contextual analysis across multiple security layers simultaneously, 
                ensuring no vulnerability goes undetected.
              </p>
              <ul className="space-y-4">
                {[
                  'Pre-login & post-login authenticated scanning',
                  'Automatic session and JWT token management',
                  'MITM proxy for complete request capture',
                  'Checkpoint/resume for long-running scans',
                  'Real-time vulnerability notifications'
                ].map((item, index) => (
                  <li key={index} className="flex items-center gap-3 text-gray-300">
                    <svg className="w-5 h-5 text-cyan-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:pl-8">
              <ScanLayersAnimation scanType="web" />
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <RevealOnScroll animation="fadeUp">
        <CapabilitiesGrid
          title="Complete OWASP Top 10 Coverage"
          subtitle="99+ security scanners covering every attack vector"
          capabilities={capabilities}
          scanType="web"
        />
      </RevealOnScroll>

      {/* AI Engine Section */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="web" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* How It Works */}
      <RevealOnScroll animation="fadeUp">
        <ScanProcessSteps scanType="web" />
      </RevealOnScroll>

      {/* Compliance */}
      <RevealOnScroll animation="fadeUp">
        <ComplianceSection scanType="web" />
      </RevealOnScroll>

      {/* CTA */}
      <RevealOnScroll animation="spring">
        <SolutionCTA
          scanType="web"
          title="Secure Your Web Applications Today"
          subtitle="Start scanning in minutes. No complex setup required."
        />
      </RevealOnScroll>

      {/* Footer */}
      <SolutionFooter />
    </div>
  );
};

export default WebSecurity;
