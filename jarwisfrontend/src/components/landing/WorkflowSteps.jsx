// src/components/landing/WorkflowSteps.jsx
// Verification-style sequential workflow animation

import { motion, useInView } from "framer-motion";
import { MessageSquare, FileSearch, Shield, FileCheck, Check } from "lucide-react";
import { useRef, useState, useEffect } from "react";

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
    border: "border-cyan-500/50",
    bg: "bg-cyan-500/20",
    text: "text-cyan-400",
    glow: "shadow-cyan-500/30",
    gradient: "from-cyan-500 to-cyan-400",
    line: "bg-gradient-to-r from-cyan-500 to-blue-500"
  },
  blue: {
    border: "border-blue-500/50",
    bg: "bg-blue-500/20",
    text: "text-blue-400",
    glow: "shadow-blue-500/30",
    gradient: "from-blue-500 to-blue-400",
    line: "bg-gradient-to-r from-blue-500 to-violet-500"
  },
  violet: {
    border: "border-violet-500/50",
    bg: "bg-violet-500/20",
    text: "text-violet-400",
    glow: "shadow-violet-500/30",
    gradient: "from-violet-500 to-violet-400",
    line: "bg-gradient-to-r from-violet-500 to-emerald-500"
  },
  emerald: {
    border: "border-emerald-500/50",
    bg: "bg-emerald-500/20",
    text: "text-emerald-400",
    glow: "shadow-emerald-500/30",
    gradient: "from-emerald-500 to-emerald-400",
    line: "bg-emerald-500"
  }
};

const ConnectingLine = ({ isVisible, color }) => {
  return (
    <div className="hidden lg:block absolute top-12 left-[calc(50%+40px)] w-[calc(100%-40px)] h-[3px] bg-white/10 rounded-full overflow-hidden z-10">
      <motion.div
        className={`h-full ${colorClasses[color].line} rounded-full`}
        initial={{ scaleX: 0 }}
        animate={{ scaleX: isVisible ? 1 : 0 }}
        style={{ transformOrigin: "left" }}
        transition={{ duration: 0.6, ease: "easeOut" }}
      />
    </div>
  );
};

const StepCard = ({ step, state }) => {
  const colors = colorClasses[step.color];
  const isActive = state === "active";
  const isCompleted = state === "completed";
  const isPending = state === "pending";

  const spinnerColor = step.color === "cyan" ? "#22d3ee" : step.color === "blue" ? "#3b82f6" : step.color === "violet" ? "#8b5cf6" : "#10b981";

  return (
    <motion.div
      initial={{ opacity: 0, y: 30, scale: 0.9 }}
      animate={{
        opacity: isPending ? 0.4 : 1,
        y: isPending ? 20 : 0,
        scale: isPending ? 0.95 : 1
      }}
      transition={{ duration: 0.5, ease: "easeOut" }}
      className="relative"
    >
      <div
        className={`relative p-6 rounded-2xl transition-all duration-500 ${isPending ? "bg-white/[0.02]" : "bg-white/[0.05]"} border ${isActive ? colors.border : isCompleted ? colors.border : "border-white/[0.08]"} ${isActive ? "shadow-lg " + colors.glow : ""}`}
      >
        {isActive && (
          <motion.div
            className={`absolute inset-0 rounded-2xl bg-gradient-to-r ${colors.gradient} opacity-10`}
            animate={{ opacity: [0.05, 0.15, 0.05] }}
            transition={{ duration: 1.5, repeat: Infinity }}
          />
        )}

        <div className={`relative w-14 h-14 rounded-xl mb-5 ${colors.bg} border ${colors.border} flex items-center justify-center transition-all duration-300 ${isActive ? "scale-110" : ""}`}>
          {isCompleted ? (
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              transition={{ type: "spring", stiffness: 200, damping: 15 }}
            >
              <Check className={`w-6 h-6 ${colors.text}`} strokeWidth={3} />
            </motion.div>
          ) : (
            <step.icon className={`w-6 h-6 ${colors.text} ${isPending ? "opacity-40" : ""}`} />
          )}

          {isActive && (
            <motion.div
              className="absolute inset-0 rounded-xl border-2 border-transparent"
              style={{ borderTopColor: spinnerColor }}
              animate={{ rotate: 360 }}
              transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
            />
          )}
        </div>

        <div className={`absolute top-4 right-4 w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold transition-all duration-500 ${isCompleted ? "bg-gradient-to-r " + colors.gradient + " text-white shadow-lg" : isActive ? colors.bg + " " + colors.text + " border " + colors.border : "bg-white/5 text-gray-500 border border-white/10"}`}>
          {isCompleted ? (
            <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring" }}>
              <Check className="w-4 h-4" />
            </motion.div>
          ) : (
            step.number
          )}
        </div>

        <h3 className={`text-lg font-semibold mb-2 transition-colors duration-300 ${isPending ? "text-gray-600" : "text-white"}`}>
          {step.title}
        </h3>

        <p className={`text-sm leading-relaxed transition-colors duration-300 ${isPending ? "text-gray-700" : "text-gray-400"}`}>
          {step.description}
        </p>

        {isActive && (
          <div className="absolute bottom-0 left-0 right-0 h-1 rounded-b-2xl overflow-hidden">
            <motion.div
              className={`h-full bg-gradient-to-r ${colors.gradient}`}
              initial={{ width: "0%" }}
              animate={{ width: "100%" }}
              transition={{ duration: 1.2, ease: "easeInOut" }}
            />
          </div>
        )}
      </div>
    </motion.div>
  );
};

const WorkflowSteps = () => {
  const containerRef = useRef(null);
  const isInView = useInView(containerRef, { once: true, amount: 0.3 });
  const [stepStates, setStepStates] = useState(["pending", "pending", "pending", "pending"]);
  const [lineStates, setLineStates] = useState([false, false, false]);
  const [showComplete, setShowComplete] = useState(false);
  const hasAnimated = useRef(false);

  useEffect(() => {
    if (!isInView || hasAnimated.current) return;
    hasAnimated.current = true;

    const STEP_DELAY = 1200;
    const LINE_DURATION = 400;

    steps.forEach((_, index) => {
      setTimeout(() => {
        setStepStates((prev) => {
          const next = [...prev];
          next[index] = "active";
          return next;
        });
      }, index * STEP_DELAY);

      if (index < steps.length - 1) {
        setTimeout(() => {
          setStepStates((prev) => {
            const next = [...prev];
            next[index] = "completed";
            return next;
          });
          setLineStates((prev) => {
            const next = [...prev];
            next[index] = true;
            return next;
          });
        }, (index + 1) * STEP_DELAY - LINE_DURATION);
      }
    });

    setTimeout(() => {
      setStepStates(["completed", "completed", "completed", "completed"]);
      setShowComplete(true);
    }, steps.length * STEP_DELAY + 300);
  }, [isInView]);

  return (
    <section ref={containerRef} className="py-20 lg:py-32 relative overflow-hidden">
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[1000px] h-[600px] bg-gradient-to-r from-cyan-500/5 via-blue-500/5 to-violet-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
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

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 lg:gap-4">
          {steps.map((step, index) => (
            <div key={step.number} className="relative">
              {index < steps.length - 1 && (
                <ConnectingLine isVisible={lineStates[index]} color={step.color} />
              )}
              <StepCard step={step} state={stepStates[index]} />
            </div>
          ))}
        </div>

        <motion.div
          initial={{ opacity: 0, y: 20, scale: 0.9 }}
          animate={showComplete ? { opacity: 1, y: 0, scale: 1 } : {}}
          transition={{ duration: 0.5, type: "spring" }}
          className="text-center mt-12"
        >
          {showComplete && (
            <div className="inline-flex items-center gap-3 px-6 py-3 rounded-full bg-emerald-500/10 border border-emerald-500/30">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ delay: 0.2, type: "spring", stiffness: 300 }}
              >
                <Check className="w-5 h-5 text-emerald-400" />
              </motion.div>
              <span className="text-emerald-400 font-medium">Security Assessment Complete</span>
            </div>
          )}
        </motion.div>
      </div>
    </section>
  );
};

export default WorkflowSteps;
