// MobileSecurity.jsx
// Mobile Application Security Solution Page

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

const MobileSecurity = () => {
  const capabilities = [
    {
      title: 'APK/IPA Binary Analysis',
      description: 'Deep static analysis of Android APK and iOS IPA files including decompilation and manifest review.',
      tags: ['Static', 'Binary'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Hardcoded Secrets Detection',
      description: 'Find API keys, tokens, credentials, and sensitive data embedded in app code and resources.',
      tags: ['Critical', 'Secrets'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
        </svg>
      )
    },
    {
      title: 'Permission Analysis',
      description: 'Audit dangerous permissions like SMS, contacts, location, camera access for privacy risks.',
      tags: ['Privacy', 'MASTG'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      )
    },
    {
      title: 'SSL Pinning Bypass',
      description: 'Frida-based SSL pinning bypass for complete network traffic interception and analysis.',
      tags: ['Dynamic', 'Network'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      )
    },
    {
      title: 'Runtime Behavior Analysis',
      description: 'Dynamic instrumentation to monitor app behavior, API calls, and data handling at runtime.',
      tags: ['Dynamic', 'Frida'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      )
    },
    {
      title: 'Insecure Data Storage',
      description: 'Detect unencrypted databases, SharedPreferences, Keychain misuse, and sensitive file exposure.',
      tags: ['Storage', 'MASTG'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
        </svg>
      )
    },
    {
      title: 'Deeplink Hijacking',
      description: 'Analyze URL schemes and deeplinks for hijacking vulnerabilities and intent spoofing.',
      tags: ['Android', 'iOS'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
        </svg>
      )
    },
    {
      title: 'Third-Party SDK Audit',
      description: 'Identify vulnerable SDKs, outdated libraries, and risky third-party dependencies.',
      tags: ['Supply Chain', 'SCA'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
        </svg>
      )
    },
    {
      title: 'API Traffic Analysis',
      description: 'Capture and test all mobile API traffic with full web security scanner integration.',
      tags: ['API', 'Network'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
        </svg>
      )
    },
    {
      title: 'Debuggable App Detection',
      description: 'Identify apps with debug flags enabled that allow attachment and runtime manipulation.',
      tags: ['Security', 'Config'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      )
    },
    {
      title: 'Exported Components',
      description: 'Find exposed Activities, Services, Broadcast Receivers, and Content Providers.',
      tags: ['Android', 'IPC'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" />
        </svg>
      )
    },
    {
      title: 'Backup Vulnerability',
      description: 'Detect apps allowing backup that may expose sensitive data to ADB extraction.',
      tags: ['Android', 'Data'],
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
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
        badge="Mobile Application Security"
        title="Complete Mobile"
        titleHighlight="Security Assessment"
        description="Static and dynamic analysis for Android APK and iOS IPA. Frida-based runtime testing, SSL pinning bypass, and comprehensive OWASP MASTG compliance."
        scanType="mobile"
        stats={[
          { value: 'APK + IPA', label: 'Platform Support' },
          { value: 'MASTG', label: 'Compliance' },
          { value: 'Frida', label: 'Instrumentation' }
        ]}
      />

      {/* Scan Layers Demo Section */}
      <section className="py-20 lg:py-32 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl sm:text-4xl font-bold text-white mb-6">
                Static + Dynamic Analysis
              </h2>
              <p className="text-lg text-gray-400 mb-8">
                JARWIS combines static binary analysis with dynamic runtime testing 
                to uncover vulnerabilities that each method alone would miss. 
                Our Frida-based instrumentation provides deep visibility into app behavior.
              </p>
              <ul className="space-y-4">
                {[
                  'Binary decompilation and manifest analysis',
                  'Frida-based runtime instrumentation',
                  'Automatic SSL pinning bypass',
                  'Full API traffic capture and testing',
                  'OWASP MASTG compliance mapping'
                ].map((item, index) => (
                  <li key={index} className="flex items-center gap-3 text-gray-300">
                    <svg className="w-5 h-5 text-purple-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="lg:pl-8">
              <ScanLayersAnimation scanType="mobile" />
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Grid */}
      <RevealOnScroll animation="fadeUp">
        <CapabilitiesGrid
          title="Complete Mobile Security Coverage"
          subtitle="Static analysis, dynamic testing, and API security in one platform"
          capabilities={capabilities}
          scanType="mobile"
        />
      </RevealOnScroll>

      {/* AI Engine Section */}
      <RevealOnScroll animation="zoomIn">
        <AIEngineSection scanType="mobile" showInteractiveDemo={true} />
      </RevealOnScroll>

      {/* How It Works */}
      <RevealOnScroll animation="fadeUp">
        <ScanProcessSteps scanType="mobile" />
      </RevealOnScroll>

      {/* Compliance */}
      <RevealOnScroll animation="fadeUp">
        <ComplianceSection scanType="mobile" />
      </RevealOnScroll>

      {/* CTA */}
      <RevealOnScroll animation="spring">
        <SolutionCTA
          scanType="mobile"
          title="Secure Your Mobile Apps Today"
          subtitle="Upload your APK or IPA and get comprehensive security analysis in minutes."
        />
      </RevealOnScroll>

      {/* Footer */}
      <SolutionFooter />
    </div>
  );
};

export default MobileSecurity;
