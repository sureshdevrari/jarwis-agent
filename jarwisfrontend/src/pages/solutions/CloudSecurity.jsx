// CloudSecurity.jsx
// Cloud Security (CNAPP) Solution Page

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

const CloudSecurity = () => {
  const capabilities = [
    {
      title: 'Multi-Cloud Discovery',
      description: 'Automatic asset discovery across AWS, Azure, GCP, and Kubernetes with multi-region support.',
      tags: ['AWS', 'Azure', 'GCP'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
        </svg>
      )
    },
    {
      title: 'CSPM Configuration Scanning',
      description: '1000+ misconfiguration rules to identify security gaps in your cloud infrastructure.',
      tags: ['CSPM', '1000+ Rules'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
        </svg>
      )
    },
    {
      title: 'CIS Benchmark Compliance',
      description: 'Automated compliance checks against CIS Benchmarks for AWS, Azure, GCP, and Kubernetes.',
      tags: ['CIS', 'Compliance'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
        </svg>
      )
    },
    {
      title: 'IAM Policy Analysis (CIEM)',
      description: 'Identify over-privileged roles, unused permissions, and dangerous IAM configurations.',
      tags: ['CIEM', 'IAM'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
        </svg>
      )
    },
    {
      title: 'S3/Blob Storage Security',
      description: 'Detect publicly exposed buckets, missing encryption, and improper access configurations.',
      tags: ['S3', 'Storage'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
        </svg>
      )
    },
    {
      title: 'Container Security',
      description: 'Trivy-based image scanning for CVEs, misconfigurations, and secrets in container images.',
      tags: ['Docker', 'Container'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      )
    },
    {
      title: 'Kubernetes Security',
      description: 'RBAC analysis, pod security policies, network policies, and workload misconfigurations.',
      tags: ['K8s', 'RBAC'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
        </svg>
      )
    },
    {
      title: 'IaC Security Scanning',
      description: 'Analyze Terraform, CloudFormation, and K8s manifests for security issues before deployment.',
      tags: ['Terraform', 'IaC'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
        </svg>
      )
    },
    {
      title: 'Runtime Threat Detection',
      description: 'CloudTrail analysis for suspicious activities, privilege escalation, and data exfiltration.',
      tags: ['Runtime', 'CloudTrail'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
        </svg>
      )
    },
    {
      title: 'Attack Path Analysis',
      description: 'AI-powered graph analysis to identify critical attack paths from exposure to crown jewels.',
      tags: ['AI', 'Graph'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    },
    {
      title: 'SBOM Generation',
      description: 'Generate Software Bill of Materials for complete visibility into software supply chain.',
      tags: ['SBOM', 'Supply Chain'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" />
        </svg>
      )
    },
    {
      title: 'Data Security Posture',
      description: 'Identify sensitive data exposure, encryption gaps, and data residency violations.',
      tags: ['DSPM', 'Data'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
        </svg>
      )
    }
  ];

  const phases = [
    {
      number: '01',
      title: 'Cloud Discovery & Inventory',
      description: 'Multi-region resource enumeration across AWS, Azure, GCP. Complete asset inventory in minutes.',
      icon: '🔍'
    },
    {
      number: '02',
      title: 'CSPM Configuration Analysis',
      description: '1000+ misconfiguration rules, CIS Benchmarks, and custom policy checks.',
      icon: '⚙️'
    },
    {
      number: '03',
      title: 'Code & IaC Scanning',
      description: 'Security analysis of Terraform, CloudFormation, Kubernetes manifests, and Dockerfiles.',
      icon: '📝'
    },
    {
      number: '04',
      title: 'Container & Supply Chain',
      description: 'Trivy-based CVE detection, SBOM generation, and vulnerable dependency identification.',
      icon: '📦'
    },
    {
      number: '05',
      title: 'Runtime Threat Detection',
      description: 'CloudTrail analysis, privilege escalation detection, and anomaly identification.',
      icon: '👁️'
    },
    {
      number: '06',
      title: 'AI Attack Path Analysis',
      description: 'Graph-based risk prioritization connecting exposures to critical assets.',
      icon: '🎯'
    }
  ];

  return (
    <div className="min-h-screen bg-gray-950">
      {/* Scroll Progress Bar */}
      <ScrollProgressBar />

      {/* Hero Section */}
      <SolutionHero
        badge="Cloud Native Application Protection"
        title="Complete CNAPP"
        titleHighlight="Cloud Security Platform"
        description="Unified cloud security across AWS, Azure, GCP, and Kubernetes. CSPM, CIEM, container security, IaC scanning, and AI-powered attack path analysis in one platform."
        scanType="cloud"
        stats={[
          { value: '1000+', label: 'Security Rules' },
          { value: '6-Phase', label: 'Scan Approach' },
          { value: 'Multi-Cloud', label: 'AWS/Azure/GCP/K8s' }
        ]}
      />

      {/* 6-Phase Approach */}
      <section className="py-20 lg:py-32 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-4">
              6-Phase Cloud Security Assessment
            </h2>
            <p className="text-lg text-gray-400 max-w-3xl mx-auto">
              Our comprehensive approach covers every aspect of cloud security, 
              from discovery to runtime protection.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {phases.map((phase, index) => (
              <div
                key={index}
                className="group p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-orange-500/30 hover:bg-white/8 transition-all duration-300"
              >
                <div className="flex items-center gap-4 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center text-2xl">
                    {phase.icon}
                  </div>
                  <span className="text-sm font-medium text-orange-400">Phase {phase.number}</span>
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">{phase.title}</h3>
                <p className="text-sm text-gray-400 leading-relaxed">{phase.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Scan Layers Demo Section */}
      <section className="py-20 lg:py-32 relative bg-gradient-to-b from-transparent via-gray-950/50 to-transparent">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Unified Cloud Security Posture
              </h2>
              <p className="text-lg text-gray-400 mb-8">
                JARWIS consolidates CSPM, CIEM, container security, and IaC scanning 
                into a single platform. Get complete visibility across your entire 
                cloud footprint with AI-powered prioritization.
              </p>
              <ul className="space-y-4">
                {[
                  'AWS, Azure, GCP, and Kubernetes support',
                  'Read-only credentials for secure scanning',
                  'CIS Benchmark compliance automation',
                  'Real-time drift detection',
                  'Attack path visualization with AI insights'
                ].map((item, index) => (
                  <li key={index} className="flex items-center gap-3 text-gray-300">
                    <svg className="w-5 h-5 text-orange-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:pl-8">
              <ScanLayersAnimation scanType="cloud" />
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <RevealOnScroll animation="fadeUp">
        <CapabilitiesGrid
          title="Complete CNAPP Capabilities"
          subtitle="Everything you need for cloud-native security"
          capabilities={capabilities}
          scanType="cloud"
        />
      </RevealOnScroll>

      {/* AI Engine Section */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="cloud" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* Compliance */}
      <RevealOnScroll animation="fadeUp">
        <ComplianceSection scanType="cloud" />
      </RevealOnScroll>

      {/* CTA */}
      <RevealOnScroll animation="spring">
        <SolutionCTA
          scanType="cloud"
          title="Secure Your Cloud Infrastructure"
          subtitle="Connect your cloud accounts and get comprehensive security visibility in minutes."
        />
      </RevealOnScroll>

      {/* Footer */}
      <SolutionFooter />
    </div>
  );
};

export default CloudSecurity;
