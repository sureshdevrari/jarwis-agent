// SASTSecurity.jsx
// SAST / Code Security Solution Page

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

const SASTSecurity = () => {
  const capabilities = [
    {
      title: 'Secret Detection',
      description: 'Find hardcoded API keys, tokens, passwords, and credentials across your entire codebase.',
      tags: ['Critical', 'Secrets'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    },
    {
      title: 'Dependency Scanning (SCA)',
      description: 'Identify vulnerable packages in your dependencies with CVE tracking and remediation guidance.',
      tags: ['SCA', 'CVE'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      )
    },
    {
      title: 'SQL Injection Detection',
      description: 'Pattern-based detection of SQL injection vulnerabilities in data access code.',
      tags: ['SQLi', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
        </svg>
      )
    },
    {
      title: 'XSS Vulnerability Detection',
      description: 'Identify cross-site scripting vulnerabilities in template rendering and output encoding.',
      tags: ['XSS', 'High'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'Command Injection',
      description: 'Detect OS command injection vulnerabilities in system calls and subprocess execution.',
      tags: ['CMDi', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Path Traversal',
      description: 'Find file path manipulation vulnerabilities that could expose sensitive files.',
      tags: ['LFI', 'High'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
        </svg>
      )
    },
    {
      title: 'Python Analysis',
      description: 'Deep security analysis for Python code including Django, Flask, and FastAPI frameworks.',
      tags: ['Python', 'Django'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'JavaScript/TypeScript',
      description: 'Security scanning for Node.js, React, Vue, Angular, and browser JavaScript code.',
      tags: ['JS', 'Node.js'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'Java Analysis',
      description: 'Comprehensive security scanning for Java applications including Spring Boot and Jakarta EE.',
      tags: ['Java', 'Spring'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'Go Security Analysis',
      description: 'Static analysis for Go applications with concurrency and memory safety checks.',
      tags: ['Go', 'Golang'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'CI/CD Integration',
      description: 'GitHub Actions, GitLab CI, Jenkins, and Azure DevOps integration with PR comments.',
      tags: ['CI/CD', 'DevSecOps'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      )
    },
    {
      title: 'SBOM Generation',
      description: 'Generate Software Bill of Materials in CycloneDX and SPDX formats for compliance.',
      tags: ['SBOM', 'Compliance'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
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
        badge="Static Application Security Testing"
        title="Secure Code from"
        titleHighlight="Commit to Production"
        description="Comprehensive SAST with secret scanning, dependency analysis, and multi-language support. Integrate into your CI/CD pipeline for shift-left security."
        scanType="sast"
        stats={[
          { value: '4+', label: 'Languages Supported' },
          { value: 'CI/CD', label: 'Pipeline Integration' },
          { value: 'SBOM', label: 'Generation' }
        ]}
      />

      {/* Code Scanning Demo */}
      <section className="py-20 lg:py-32 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Find Vulnerabilities Before They Ship
              </h2>
              <p className="text-lg text-gray-400 mb-8">
                JARWIS SAST analyzes your source code to identify security vulnerabilities 
                during development. From hardcoded secrets to injection flaws, catch issues 
                before they reach production.
              </p>

              {/* Code block example */}
              <div className="code-scan-block p-4 mb-8">
                <div className="code-scan-line"></div>
                <pre className="text-sm text-gray-300 overflow-x-auto">
                  <code>{`# Example: Detected SQL Injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    #        ^^^ Vulnerability: User input in SQL query
    return db.execute(query)

# Remediation: Use parameterized queries
def get_user_safe(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, [user_id])`}</code>
                </pre>
              </div>

              <ul className="space-y-4">
                {[
                  'Hardcoded secrets and credential detection',
                  'Vulnerable dependency identification (SCA)',
                  'Pattern-based vulnerability detection',
                  'Multi-language support (Python, JS, Java, Go)',
                  'CI/CD pipeline integration with blocking'
                ].map((item, index) => (
                  <li key={index} className="flex items-center gap-3 text-gray-300">
                    <svg className="w-5 h-5 text-red-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:pl-8">
              <ScanLayersAnimation scanType="sast" />
            </div>
          </div>
        </div>
      </section>

      {/* Language Support Grid */}
      <section className="py-20 lg:py-32 relative bg-gradient-to-b from-transparent via-gray-950/50 to-transparent">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-4">
              Multi-Language Support
            </h2>
            <p className="text-lg text-gray-400 max-w-2xl mx-auto">
              Deep security analysis tailored for each language and framework
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              { name: 'Python', frameworks: ['Django', 'Flask', 'FastAPI', 'Pyramid'], icon: '🐍', color: 'from-yellow-500 to-blue-500' },
              { name: 'JavaScript', frameworks: ['Node.js', 'React', 'Vue', 'Angular'], icon: '⚡', color: 'from-yellow-400 to-yellow-600' },
              { name: 'Java', frameworks: ['Spring Boot', 'Jakarta EE', 'Struts', 'Hibernate'], icon: '☕', color: 'from-red-500 to-orange-500' },
              { name: 'Go', frameworks: ['Gin', 'Echo', 'Fiber', 'Standard Library'], icon: '🐹', color: 'from-cyan-400 to-blue-500' }
            ].map((lang, index) => (
              <div
                key={index}
                className="group p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-red-500/30 hover:bg-white/8 transition-all duration-300"
              >
                <div className="text-4xl mb-4">{lang.icon}</div>
                <h3 className="text-xl font-semibold text-white mb-3">{lang.name}</h3>
                <div className="flex flex-wrap gap-2">
                  {lang.frameworks.map((fw, fwIndex) => (
                    <span
                      key={fwIndex}
                      className="px-2 py-1 text-xs rounded-md bg-white/10 text-gray-400 border border-white/10"
                    >
                      {fw}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <RevealOnScroll animation="fadeUp">
        <CapabilitiesGrid
          title="Complete Code Security Coverage"
          subtitle="From secrets to dependencies to code vulnerabilities"
          capabilities={capabilities}
          scanType="sast"
        />
      </RevealOnScroll>

      {/* AI Engine Section */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="sast" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* How It Works */}
      <RevealOnScroll animation="fadeUp">
        <ScanProcessSteps scanType="sast" />
      </RevealOnScroll>

      {/* Compliance */}
      <RevealOnScroll animation="fadeUp">
        <ComplianceSection scanType="sast" />
      </RevealOnScroll>

      {/* CTA */}
      <RevealOnScroll animation="spring">
        <SolutionCTA
          scanType="sast"
          title="Secure Your Code Today"
          subtitle="Connect your repository and find vulnerabilities in minutes."
        />
      </RevealOnScroll>

      {/* Footer */}
      <SolutionFooter />
    </div>
  );
};

export default SASTSecurity;
