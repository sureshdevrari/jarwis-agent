// ComplianceSection.jsx
// Shows compliance standards and certifications covered

import {
  Shield,
  CreditCard,
  Building2,
  CheckCircle,
  Globe2,
  ClipboardList,
  Smartphone,
  Lock,
  Landmark,
  BarChart3,
  Scale,
  Cloud,
  KeyRound,
  Flag,
  Search,
  AlertTriangle,
  Package
} from 'lucide-react';

const ComplianceSection = ({ scanType = 'web' }) => {
  const complianceData = {
    web: {
      standards: [
        { name: 'OWASP Top 10', description: '2021 Edition', icon: Shield },
        { name: 'PCI DSS', description: 'v4.0 Compliant', icon: CreditCard },
        { name: 'HIPAA', description: 'Security Rule', icon: Building2 },
        { name: 'SOC 2', description: 'Type II', icon: CheckCircle },
        { name: 'GDPR', description: 'Article 32', icon: Globe2 },
        { name: 'ISO 27001', description: 'Annex A Controls', icon: ClipboardList }
      ]
    },
    mobile: {
      standards: [
        { name: 'OWASP MASTG', description: 'Mobile Testing Guide', icon: Smartphone },
        { name: 'MASVS', description: 'L1 & L2 Verification', icon: CheckCircle },
        { name: 'PCI DSS', description: 'Mobile Payments', icon: CreditCard },
        { name: 'HIPAA', description: 'Mobile Health Apps', icon: Building2 },
        { name: 'GDPR', description: 'Data Protection', icon: Globe2 },
        { name: 'CCPA', description: 'Consumer Privacy', icon: Lock }
      ]
    },
    network: {
      standards: [
        { name: 'NIST CSF', description: 'Cybersecurity Framework', icon: Landmark },
        { name: 'CIS Controls', description: 'v8 Benchmarks', icon: BarChart3 },
        { name: 'PCI DSS', description: 'Network Security', icon: CreditCard },
        { name: 'ISO 27001', description: 'Network Controls', icon: ClipboardList },
        { name: 'HIPAA', description: 'Technical Safeguards', icon: Building2 },
        { name: 'SOX', description: 'IT Controls', icon: Scale }
      ]
    },
    cloud: {
      standards: [
        { name: 'CIS Benchmarks', description: 'AWS/Azure/GCP', icon: Cloud },
        { name: 'SOC 2', description: 'Cloud Security', icon: CheckCircle },
        { name: 'NIST 800-53', description: 'Federal Controls', icon: Landmark },
        { name: 'CSA CCM', description: 'Cloud Controls', icon: KeyRound },
        { name: 'ISO 27017', description: 'Cloud Security', icon: ClipboardList },
        { name: 'FedRAMP', description: 'Government Cloud', icon: Flag }
      ]
    },
    sast: {
      standards: [
        { name: 'OWASP ASVS', description: 'Code Verification', icon: Search },
        { name: 'CWE Top 25', description: 'Dangerous Errors', icon: AlertTriangle },
        { name: 'SANS Top 25', description: 'Software Errors', icon: BarChart3 },
        { name: 'PCI DSS', description: 'Secure Coding', icon: CreditCard },
        { name: 'NIST SSDF', description: 'Secure Development', icon: Landmark },
        { name: 'SBOM', description: 'Software Bill of Materials', icon: Package }
      ]
    }
  };

  const { standards } = complianceData[scanType];

  return (
    <section className="relative py-20 lg:py-32 bg-gradient-to-b from-transparent via-gray-950/50 to-transparent">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-4">
            Compliance & Standards
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Meet regulatory requirements with automated compliance mapping and reporting
          </p>
        </div>

        {/* Compliance Grid */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          {standards.map((standard, index) => (
            <div
              key={index}
              className="group p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-cyan-500/30 hover:bg-white/8 transition-all duration-300 text-center"
            >
              <div className="flex justify-center mb-3">
                {typeof standard.icon === 'string' ? (
                  <span className="text-4xl">{standard.icon}</span>
                ) : (
                  <standard.icon className="w-10 h-10 text-cyan-400" />
                )}
              </div>
              <h3 className="text-sm font-semibold text-white mb-1">{standard.name}</h3>
              <p className="text-xs text-gray-500">{standard.description}</p>
            </div>
          ))}
        </div>

        {/* Bottom Bar */}
        <div className="mt-12 p-6 rounded-2xl bg-white/5 border border-white/10">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6 text-center md:text-left">
            <div>
              <h3 className="text-lg font-semibold text-white mb-1">Export Compliance Reports</h3>
              <p className="text-sm text-gray-400">
                Generate audit-ready reports in PDF, CSV, or JSON format with evidence mapping
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              {['PDF', 'CSV', 'JSON', 'SARIF'].map((format) => (
                <span
                  key={format}
                  className="px-4 py-2 rounded-lg bg-white/10 text-white text-sm font-medium border border-white/10"
                >
                  {format}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default ComplianceSection;
