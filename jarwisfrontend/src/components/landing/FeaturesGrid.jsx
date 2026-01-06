// src/components/landing/FeaturesGrid.jsx
// Devin.ai-inspired features grid with glassmorphism cards

import { motion } from "framer-motion";
import {
  Brain,
  Zap,
  Shield,
  Globe,
  Lock,
  BarChart3,
  RefreshCw,
  Code2
} from "lucide-react";

const features = [
  {
    icon: Brain,
    title: "True AGI Intelligence",
    description: "Thinks like an expert security engineer, understanding business logic and context to find complex vulnerabilities others miss.",
    gradient: "from-cyan-500 to-blue-500"
  },
  {
    icon: Zap,
    title: "10x Faster Testing",
    description: "Complete comprehensive security assessments in hours, not weeks. Continuous testing that keeps pace with your development.",
    gradient: "from-yellow-500 to-orange-500"
  },
  {
    icon: Shield,
    title: "OWASP Top 10 Coverage",
    description: "Thorough detection of injection, broken auth, XSS, CSRF, and all critical vulnerabilities with 99.8% accuracy.",
    gradient: "from-green-500 to-emerald-500"
  },
  {
    icon: Globe,
    title: "Works Everywhere",
    description: "Web apps, REST APIs, GraphQL, mobile backends, and cloud infrastructure. One tool for all your security needs.",
    gradient: "from-blue-500 to-violet-500"
  },
  {
    icon: Lock,
    title: "Zero False Positives",
    description: "AI-verified findings mean your team focuses on real threats. Every vulnerability is validated before reporting.",
    gradient: "from-rose-500 to-pink-500"
  },
  {
    icon: RefreshCw,
    title: "Always Learning",
    description: "Continuously evolves with new attack patterns. Adapts to your codebase and learns from each engagement.",
    gradient: "from-violet-500 to-purple-500"
  },
  {
    icon: Code2,
    title: "Natural Language",
    description: "Describe what you want to test in plain English. No complex configurations or scripting required.",
    gradient: "from-teal-500 to-cyan-500"
  },
  {
    icon: BarChart3,
    title: "Actionable Reports",
    description: "Detailed findings with proof-of-concept exploits, risk scores, and step-by-step remediation guidance.",
    gradient: "from-amber-500 to-yellow-500"
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
            Unlike traditional scanners, Jarwis understands context, logic, and intent
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
                  flex items-center justify-center
                  shadow-lg group-hover:scale-110 transition-transform duration-300
                `}>
                  <feature.icon className="w-6 h-6 text-white" />
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
