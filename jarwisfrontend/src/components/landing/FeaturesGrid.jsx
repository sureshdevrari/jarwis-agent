// src/components/landing/FeaturesGrid.jsx
// Devin.ai-inspired features grid with glassmorphism cards

import { motion } from "framer-motion";
import {
  Brain,
  Zap,
  Shield,
  Globe,
  Smartphone,
  Network,
  Cloud,
  Bot
} from "lucide-react";

const features = [
  {
    icon: Globe,
    title: "Web Application Security",
    description: "Full OWASP Top 10 coverage including SQL injection, XSS, CSRF, broken authentication, and security misconfigurations.",
    gradient: "from-cyan-500 to-blue-500"
  },
  {
    icon: Smartphone,
    title: "Mobile App Security",
    description: "APK & IPA analysis for Android and iOS. Detect hardcoded secrets, insecure storage, and vulnerable SDKs.",
    gradient: "from-purple-500 to-pink-500"
  },
  {
    icon: Network,
    title: "Network Security",
    description: "Port scanning, service detection, CVE identification, and OS fingerprinting with agent-based internal scanning.",
    gradient: "from-green-500 to-emerald-500"
  },
  {
    icon: Cloud,
    title: "Cloud Security Posture",
    description: "AWS, Azure & GCP misconfiguration detection. IAM analysis, compliance checks, and cost optimization.",
    gradient: "from-orange-500 to-amber-500"
  },
  {
    icon: Bot,
    title: "AI Security Assistant",
    description: "Get instant vulnerability explanations, remediation guidance, and code fixes through natural language chat.",
    gradient: "from-blue-500 to-violet-500"
  },
  {
    icon: Brain,
    title: "True AGI Intelligence",
    description: "Thinks like an expert security engineer, understanding business logic to find vulnerabilities others miss.",
    gradient: "from-rose-500 to-pink-500"
  },
  {
    icon: Zap,
    title: "10x Faster Testing",
    description: "Complete comprehensive security assessments in hours, not weeks. Continuous testing at development speed.",
    gradient: "from-yellow-500 to-orange-500"
  },
  {
    icon: Shield,
    title: "Actionable Reports",
    description: "Detailed findings with proof-of-concept exploits, CVSS scores, and step-by-step remediation guidance.",
    gradient: "from-teal-500 to-cyan-500"
  }
];

const FeaturesGrid = () => {
  return (
    <section className="py-20 lg:py-32 relative">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-gray-900/50 to-transparent pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 0.5 }}
          className="text-center mb-16"
        >
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4">
            Why Teams Choose{" "}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Jarwis
            </span>
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            Complete security coverage for Web, Mobile, Network, Cloud, and AI-powered remediation
          </p>
        </motion.div>

        {/* Features grid */}
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-50px" }}
              transition={{ delay: index * 0.05, duration: 0.4 }}
              className="group"
            >
              <div className="
                relative h-full p-6 rounded-2xl
                bg-white/[0.02] hover:bg-white/[0.05]
                border border-white/[0.05] hover:border-white/[0.1]
                transition-all duration-300
                hover:-translate-y-1 hover:shadow-xl hover:shadow-black/20
              ">
                {/* Icon */}
                <div className={`
                  w-12 h-12 rounded-xl mb-4
                  bg-gradient-to-br ${feature.gradient}
                  bg-opacity-10 border border-white/10
                  flex items-center justify-center
                  group-hover:scale-110 transition-transform duration-300
                `} style={{ background: `linear-gradient(135deg, ${feature.gradient.includes('cyan') ? 'rgba(6,182,212,0.15)' : feature.gradient.includes('purple') ? 'rgba(168,85,247,0.15)' : feature.gradient.includes('green') ? 'rgba(34,197,94,0.15)' : feature.gradient.includes('orange') ? 'rgba(249,115,22,0.15)' : feature.gradient.includes('blue') ? 'rgba(59,130,246,0.15)' : feature.gradient.includes('rose') ? 'rgba(244,63,94,0.15)' : feature.gradient.includes('yellow') ? 'rgba(234,179,8,0.15)' : 'rgba(20,184,166,0.15)'}, transparent)` }}>
                  <feature.icon className={`w-6 h-6 ${
                    feature.gradient.includes('cyan') ? 'text-cyan-400' : 
                    feature.gradient.includes('purple') ? 'text-purple-400' : 
                    feature.gradient.includes('green') ? 'text-emerald-400' : 
                    feature.gradient.includes('orange') ? 'text-orange-400' : 
                    feature.gradient.includes('blue') && feature.gradient.includes('violet') ? 'text-blue-400' :
                    feature.gradient.includes('rose') ? 'text-rose-400' : 
                    feature.gradient.includes('yellow') ? 'text-amber-400' : 
                    'text-teal-400'
                  }`} />
                </div>

                {/* Content */}
                <h3 className="text-lg font-semibold text-white mb-2">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-400 leading-relaxed">
                  {feature.description}
                </p>

                {/* Hover glow effect */}
                <div className={`
                  absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100
                  bg-gradient-to-br ${feature.gradient}
                  blur-xl transition-opacity duration-500
                  -z-10 scale-90
                `} style={{ opacity: 0.05 }} />
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesGrid;
