// src/components/landing/WorkflowSteps.jsx
// Devin.ai-inspired workflow steps section

import { motion } from "framer-motion";
import { MessageSquare, FileSearch, Shield, FileCheck } from "lucide-react";

const steps = [
  {
    number: 1,
    icon: MessageSquare,
    title: "Describe Your Target",
    description: "Simply tell Jarwis what to test in plain English. No complex configurations needed.",
    color: "cyan"
  },
  {
    number: 2,
    icon: FileSearch,
    title: "AI Analyzes & Plans",
    description: "Jarwis understands your app's logic and creates a comprehensive test strategy.",
    color: "blue"
  },
  {
    number: 3,
    icon: Shield,
    title: "Autonomous Testing",
    description: "OWASP Top 10 & SANS 25 vulnerabilities are discovered with near-zero false positives.",
    color: "violet"
  },
  {
    number: 4,
    icon: FileCheck,
    title: "Actionable Reports",
    description: "Get detailed findings with remediation guidance and proof-of-concept examples.",
    color: "emerald"
  }
];

const colorClasses = {
  cyan: {
    border: "border-cyan-500/30",
    bg: "bg-cyan-500/10",
    text: "text-cyan-400",
    glow: "shadow-cyan-500/20"
  },
  blue: {
    border: "border-blue-500/30",
    bg: "bg-blue-500/10",
    text: "text-blue-400",
    glow: "shadow-blue-500/20"
  },
  violet: {
    border: "border-violet-500/30",
    bg: "bg-violet-500/10",
    text: "text-violet-400",
    glow: "shadow-violet-500/20"
  },
  emerald: {
    border: "border-emerald-500/30",
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    glow: "shadow-emerald-500/20"
  }
};

const WorkflowSteps = () => {
  return (
    <section className="py-20 lg:py-32 relative overflow-hidden">
      {/* Background accent */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[600px] bg-gradient-to-r from-cyan-500/5 via-blue-500/5 to-violet-500/5 rounded-full blur-3xl pointer-events-none" />

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
            How{" "}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Jarwis
            </span>{" "}
            Works
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            From prompt to protection in four simple steps. No security expertise required.
          </p>
        </motion.div>

        {/* Steps grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 lg:gap-8">
          {steps.map((step, index) => {
            const colors = colorClasses[step.color];
            return (
              <motion.div
                key={step.number}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-50px" }}
                transition={{ delay: index * 0.1, duration: 0.5 }}
                className="group relative"
              >
                {/* Connecting line for desktop */}
                {index < steps.length - 1 && (
                  <div className="hidden lg:block absolute top-12 left-[calc(50%+40px)] w-[calc(100%-80px)] h-[2px] bg-gradient-to-r from-white/10 to-white/5" />
                )}

                <div className={`
                  relative p-6 rounded-2xl 
                  bg-white/[0.02] hover:bg-white/[0.05]
                  border border-white/[0.05] hover:${colors.border}
                  transition-all duration-300
                  hover:shadow-xl ${colors.glow}
                `}>
                  {/* Step number */}
                  <div className={`
                    w-14 h-14 rounded-xl mb-5
                    ${colors.bg} ${colors.border} border
                    flex items-center justify-center
                    group-hover:scale-110 transition-transform duration-300
                  `}>
                    <step.icon className={`w-6 h-6 ${colors.text}`} />
                  </div>

                  {/* Number badge */}
                  <div className={`
                    absolute top-4 right-4
                    w-8 h-8 rounded-full
                    bg-white/5 border border-white/10
                    flex items-center justify-center
                    text-sm font-semibold text-gray-500
                  `}>
                    {step.number}
                  </div>

                  <h3 className="text-lg font-semibold text-white mb-2">
                    {step.title}
                  </h3>
                  <p className="text-sm text-gray-400 leading-relaxed">
                    {step.description}
                  </p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
};

export default WorkflowSteps;
