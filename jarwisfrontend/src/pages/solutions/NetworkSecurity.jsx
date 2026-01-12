// NetworkSecurity.jsx
// Network Security Solution Page

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

const NetworkSecurity = () => {
  const capabilities = [
    {
      title: 'Port Scanning & Discovery',
      description: 'Comprehensive port enumeration using multiple techniques including SYN, TCP connect, and UDP scans.',
      tags: ['Discovery', 'Nmap'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
        </svg>
      )
    },
    {
      title: 'Service Detection',
      description: 'Identify running services, versions, and banners to map your network attack surface.',
      tags: ['Fingerprint', 'Version'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
        </svg>
      )
    },
    {
      title: 'CVE Vulnerability Detection',
      description: 'Match discovered services against known CVE databases for vulnerability identification.',
      tags: ['CVE', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      )
    },
    {
      title: 'OS Fingerprinting',
      description: 'Identify operating systems running on network hosts for targeted vulnerability assessment.',
      tags: ['Detection', 'Recon'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Credential Testing',
      description: 'Test for default credentials, weak passwords, and authentication bypass across network services.',
      tags: ['Auth', 'Brute Force'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    },
    {
      title: 'SSL/TLS Analysis',
      description: 'Test SSL/TLS configurations for weak ciphers, expired certificates, and protocol vulnerabilities.',
      tags: ['Crypto', 'SSL'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      )
    },
    {
      title: 'Internal Network Scanning',
      description: 'Deploy Jarwis Agent for scanning private IPs and internal network segments securely.',
      tags: ['Agent', 'Internal'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
        </svg>
      )
    },
    {
      title: 'Metasploit Integration',
      description: 'Validate exploitability of discovered vulnerabilities with automated Metasploit module execution.',
      tags: ['Exploit', 'Validation'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    },
    {
      title: 'Network Topology Mapping',
      description: 'Visualize network structure with host relationships, routing paths, and segment boundaries.',
      tags: ['Visualization', 'Map'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
        </svg>
      )
    },
    {
      title: 'SMB/RDP Vulnerability Testing',
      description: 'Test Windows-specific protocols for EternalBlue, BlueKeep, and other critical vulnerabilities.',
      tags: ['Windows', 'Critical'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'DNS Security Analysis',
      description: 'Check DNS configurations for zone transfers, subdomain enumeration, and cache poisoning risks.',
      tags: ['DNS', 'Recon'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064" />
        </svg>
      )
    },
    {
      title: 'SNMP Enumeration',
      description: 'Discover SNMP-enabled devices and extract configuration data from community strings.',
      tags: ['SNMP', 'Enum'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
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
        badge="Network Security Testing"
        title="Comprehensive"
        titleHighlight="Network Penetration Testing"
        description="Full network infrastructure assessment including port scanning, CVE detection, service enumeration, and Metasploit exploit validation. Support for internal networks via Jarwis Agent."
        scanType="network"
        stats={[
          { value: 'CVE', label: 'Database Integration' },
          { value: 'Internal', label: 'Network Support' },
          { value: 'Metasploit', label: 'Exploit Validation' }
        ]}
      />

      {/* Scan Layers Demo Section */}
      <section className="py-20 lg:py-32 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Deep Network Reconnaissance
              </h2>
              <p className="text-lg text-gray-400 mb-8">
                From initial host discovery to exploit validation, JARWIS performs 
                a complete network security assessment. Our agent-based approach 
                enables secure scanning of internal networks without VPN complexity.
              </p>
              <ul className="space-y-4">
                {[
                  'Multi-technique port scanning (SYN, TCP, UDP)',
                  'Service and version fingerprinting',
                  'CVE-based vulnerability matching',
                  'Automated credential testing',
                  'Jarwis Agent for internal network access'
                ].map((item, index) => (
                  <li key={index} className="flex items-center gap-3 text-gray-300">
                    <svg className="w-5 h-5 text-green-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:pl-8">
              <ScanLayersAnimation scanType="network" />
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <RevealOnScroll animation="fadeUp">
        <CapabilitiesGrid
          title="Full Network Security Coverage"
          subtitle="From reconnaissance to exploitation validation"
          capabilities={capabilities}
          scanType="network"
        />
      </RevealOnScroll>

      {/* AI Engine Section */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="network" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* How It Works */}
      <RevealOnScroll animation="fadeUp">
        <ScanProcessSteps scanType="network" />
      </RevealOnScroll>

      {/* Compliance */}
      <RevealOnScroll animation="fadeUp">
        <ComplianceSection scanType="network" />
      </RevealOnScroll>

      {/* CTA */}
      <RevealOnScroll animation="spring">
        <SolutionCTA
          scanType="network"
          title="Secure Your Network Infrastructure"
          subtitle="Identify vulnerabilities before attackers do. Start your network assessment today."
        />
      </RevealOnScroll>

      {/* Footer */}
      <SolutionFooter />
    </div>
  );
};

export default NetworkSecurity;
