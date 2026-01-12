// ScanProcessSteps.jsx
// Visual workflow showing scan process steps

import { motion } from 'framer-motion';
import {
  Target,
  Search,
  Shield,
  Brain,
  FileBarChart,
  Smartphone,
  Microscope,
  Zap,
  Globe,
  ClipboardCheck,
  Bug,
  Unlock,
  TrendingUp,
  Cloud,
  MapPin,
  CheckCircle,
  KeyRound,
  Crosshair,
  Route,
  Monitor,
  FolderGit2,
  Key,
  Package,
  Code2,
  RefreshCw
} from 'lucide-react';

const ScanProcessSteps = ({ 
  title = "How It Works",
  subtitle = "Simple setup, comprehensive results",
  steps = [],
  scanType = 'web'
}) => {
  const gradients = {
    web: 'from-cyan-400 to-blue-500',
    mobile: 'from-purple-400 to-pink-500',
    network: 'from-green-400 to-emerald-500',
    cloud: 'from-orange-400 to-amber-500',
    sast: 'from-red-400 to-rose-500'
  };

  const defaultSteps = {
    web: [
      {
        number: '01',
        title: 'Enter Target URL',
        description: 'Simply provide your web application URL and authentication credentials if needed.',
        icon: Target
      },
      {
        number: '02',
        title: 'Automated Discovery',
        description: 'JARWIS crawls your application, mapping endpoints, forms, and API routes automatically.',
        icon: Search
      },
      {
        number: '03',
        title: 'Multi-Layer Scanning',
        description: 'Our AI engine runs 99+ security checks across OWASP Top 10 and beyond.',
        icon: Shield
      },
      {
        number: '04',
        title: 'AI Verification',
        description: 'Each finding is verified by our Bayesian engine to eliminate false positives.',
        icon: Brain
      },
      {
        number: '05',
        title: 'Detailed Reports',
        description: 'Get actionable reports with proof-of-concept, remediation steps, and priority scores.',
        icon: FileBarChart
      }
    ],
    mobile: [
      {
        number: '01',
        title: 'Upload APK/IPA',
        description: 'Upload your Android APK or iOS IPA file for comprehensive analysis.',
        icon: Smartphone
      },
      {
        number: '02',
        title: 'Static Analysis',
        description: 'Binary decompilation, manifest analysis, and hardcoded secrets detection.',
        icon: Microscope
      },
      {
        number: '03',
        title: 'Dynamic Testing',
        description: 'Runtime behavior analysis with Frida-based instrumentation.',
        icon: Zap
      },
      {
        number: '04',
        title: 'Network Interception',
        description: 'Capture and analyze all API traffic with SSL pinning bypass.',
        icon: Globe
      },
      {
        number: '05',
        title: 'Security Report',
        description: 'Complete mobile security assessment with OWASP MASTG compliance.',
        icon: ClipboardCheck
      }
    ],
    network: [
      {
        number: '01',
        title: 'Define Scope',
        description: 'Enter IP ranges, subnets, or install Jarwis Agent for internal networks.',
        icon: Crosshair
      },
      {
        number: '02',
        title: 'Host Discovery',
        description: 'Identify live hosts and perform OS fingerprinting across your network.',
        icon: Monitor
      },
      {
        number: '03',
        title: 'Port Scanning',
        description: 'Comprehensive port enumeration with service and version detection.',
        icon: Unlock
      },
      {
        number: '04',
        title: 'Vulnerability Detection',
        description: 'CVE-based vulnerability scanning with exploit validation.',
        icon: Bug
      },
      {
        number: '05',
        title: 'Risk Assessment',
        description: 'Prioritized findings with network topology visualization.',
        icon: TrendingUp
      }
    ],
    cloud: [
      {
        number: '01',
        title: 'Connect Cloud Account',
        description: 'Securely connect AWS, Azure, GCP, or Kubernetes with read-only credentials.',
        icon: Cloud
      },
      {
        number: '02',
        title: 'Asset Discovery',
        description: 'Multi-region enumeration of all cloud resources and configurations.',
        icon: MapPin
      },
      {
        number: '03',
        title: 'CSPM Analysis',
        description: '1000+ misconfiguration rules with CIS Benchmark compliance checks.',
        icon: CheckCircle
      },
      {
        number: '04',
        title: 'IAM Review',
        description: 'Permission analysis, over-privileged roles, and access path detection.',
        icon: KeyRound
      },
      {
        number: '05',
        title: 'Attack Path Analysis',
        description: 'AI-powered graph analysis to find critical attack chains.',
        icon: Route
      }
    ],
    sast: [
      {
        number: '01',
        title: 'Connect Repository',
        description: 'Link your GitHub, GitLab, Bitbucket, or provide repository URL.',
        icon: FolderGit2
      },
      {
        number: '02',
        title: 'Secret Scanning',
        description: 'Detect hardcoded API keys, tokens, and credentials across all files.',
        icon: Key
      },
      {
        number: '03',
        title: 'Dependency Analysis',
        description: 'SCA scanning to find vulnerable packages in your dependencies.',
        icon: Package
      },
      {
        number: '04',
        title: 'Code Analysis',
        description: 'Pattern-based security vulnerability detection (SQLi, XSS, CMDi).',
        icon: Code2
      },
      {
        number: '05',
        title: 'CI/CD Integration',
        description: 'Automated security gates with PR comments and blocking rules.',
        icon: RefreshCw
      }
    ]
  };

  const activeSteps = steps.length > 0 ? steps : defaultSteps[scanType];

  return (
    <section className="relative py-20 lg:py-32">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-4">
            {title}
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            {subtitle}
          </p>
        </div>

        {/* Steps */}
        <div className="relative">
          {/* Connection Line */}
          <div className="absolute left-8 top-0 bottom-0 w-px bg-gradient-to-b from-transparent via-white/20 to-transparent hidden md:block" />

          <div className="space-y-8">
            {activeSteps.map((step, index) => (
              <motion.div
                key={index}
                className="relative flex flex-col md:flex-row gap-6 md:gap-8"
                initial={{ opacity: 0, x: -30 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true, margin: "-100px" }}
                transition={{ 
                  duration: 0.5, 
                  delay: index * 0.15,
                  ease: "easeOut"
                }}
              >
                {/* Step Number */}
                <div className="flex-shrink-0 relative z-10">
                  <motion.div 
                    className={`w-16 h-16 rounded-2xl bg-gradient-to-br ${gradients[scanType]} flex items-center justify-center text-white font-bold text-lg shadow-lg`}
                    whileHover={{ scale: 1.1 }}
                    transition={{ type: "spring", stiffness: 300 }}
                  >
                    {step.icon ? (
                      typeof step.icon === 'string' ? step.icon : <step.icon className="w-7 h-7" />
                    ) : step.number}
                  </motion.div>
                </div>

                {/* Step Content */}
                <div className="flex-1 pb-8">
                  <motion.div 
                    className="p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-white/20 transition-all duration-300"
                    whileHover={{ y: -5, boxShadow: "0 10px 40px -10px rgba(6, 182, 212, 0.2)" }}
                  >
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-sm font-medium text-gray-500">Step {step.number}</span>
                    </div>
                    <h3 className="text-xl font-semibold text-white mb-2">{step.title}</h3>
                    <p className="text-gray-400">{step.description}</p>
                  </motion.div>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};

export default ScanProcessSteps;
