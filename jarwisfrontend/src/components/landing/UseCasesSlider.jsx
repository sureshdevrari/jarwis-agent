// src/components/landing/UseCasesSlider.jsx
// Devin.ai-inspired use cases slider showcasing all scan types

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Globe, 
  Smartphone, 
  Network, 
  Cloud,
  Bot,
  Shield,
  CheckCircle2
} from "lucide-react";

const useCases = [
  {
    id: "web",
    title: "Web Application Security",
    icon: Globe,
    color: "cyan",
    gradient: "from-cyan-500 to-blue-500",
    image: "/mockups/web.png",
    features: [
      "OWASP Top 10 vulnerability detection",
      "SQL injection & XSS scanning",
      "Authentication & session testing",
      "API security assessment",
      "Automated crawling & discovery"
    ]
  },
  {
    id: "mobile",
    title: "Mobile App Security",
    icon: Smartphone,
    color: "purple",
    gradient: "from-purple-500 to-pink-500",
    image: "/mockups/mobile.png",
    features: [
      "APK & IPA static analysis",
      "Permission vulnerability detection",
      "Hardcoded secrets scanning",
      "Third-party SDK risk assessment",
      "Binary protection analysis"
    ]
  },
  {
    id: "network",
    title: "Network Security",
    icon: Network,
    color: "green",
    gradient: "from-green-500 to-emerald-500",
    image: "/mockups/network.png",
    features: [
      "Port scanning & service detection",
      "CVE vulnerability identification",
      "OS fingerprinting",
      "Network topology mapping",
      "Agent-based internal scanning"
    ]
  },
  {
    id: "cloud",
    title: "Cloud Security Posture",
    icon: Cloud,
    color: "orange",
    gradient: "from-orange-500 to-amber-500",
    image: "/mockups/cloud.png",
    features: [
      "AWS, Azure & GCP scanning",
      "Misconfiguration detection",
      "IAM policy analysis",
      "Compliance framework checks",
      "Cost optimization insights"
    ]
  },
  {
    id: "ai",
    title: "AI Security Assistant",
    icon: Bot,
    color: "blue",
    gradient: "from-blue-500 to-violet-500",
    image: "/mockups/chatbot1.png",
    features: [
      "Instant vulnerability explanations",
      "Step-by-step remediation guidance",
      "Code fix suggestions",
      "Security best practices",
      "Natural language interaction"
    ]
  }
];

const colorClasses = {
  cyan: {
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/30",
    text: "text-cyan-400",
    activeBg: "bg-cyan-500",
    glow: "shadow-cyan-500/30"
  },
  purple: {
    bg: "bg-purple-500/10",
    border: "border-purple-500/30",
    text: "text-purple-400",
    activeBg: "bg-purple-500",
    glow: "shadow-purple-500/30"
  },
  green: {
    bg: "bg-green-500/10",
    border: "border-green-500/30",
    text: "text-green-400",
    activeBg: "bg-green-500",
    glow: "shadow-green-500/30"
  },
  orange: {
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    text: "text-orange-400",
    activeBg: "bg-orange-500",
    glow: "shadow-orange-500/30"
  },
  blue: {
    bg: "bg-blue-500/10",
    border: "border-blue-500/30",
    text: "text-blue-400",
    activeBg: "bg-blue-500",
    glow: "shadow-blue-500/30"
  }
};

const UseCasesSlider = () => {
  const [activeIndex, setActiveIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const intervalRef = useRef(null);
  const progressRef = useRef(null);
  const SLIDE_DURATION = 5000; // 5 seconds per slide

  const activeCase = useCases[activeIndex];
  const colors = colorClasses[activeCase.color];

  // Auto-advance slides
  useEffect(() => {
    const startProgress = () => {
      setProgress(0);
      progressRef.current = setInterval(() => {
        setProgress(prev => {
          if (prev >= 100) {
            return 0;
          }
          return prev + (100 / (SLIDE_DURATION / 50));
        });
      }, 50);
    };

    const advanceSlide = () => {
      setActiveIndex(prev => (prev + 1) % useCases.length);
    };

    startProgress();
    intervalRef.current = setInterval(advanceSlide, SLIDE_DURATION);

    return () => {
      clearInterval(intervalRef.current);
      clearInterval(progressRef.current);
    };
  }, [activeIndex]);

  const handleSlideClick = (index) => {
    clearInterval(intervalRef.current);
    clearInterval(progressRef.current);
    setActiveIndex(index);
    setProgress(0);
  };

  return (
    <section className="py-20 lg:py-32 relative overflow-hidden">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-gray-900/50 via-transparent to-gray-900/50 pointer-events-none" />
      
      {/* Accent glow */}
      <div className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-gradient-to-r ${activeCase.gradient} opacity-5 rounded-full blur-3xl pointer-events-none transition-all duration-700`} />

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
            Complete Security{" "}
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Coverage
            </span>
          </h2>
          <p className="text-lg text-gray-400 max-w-2xl mx-auto">
            From web apps to cloud infrastructure, Jarwis protects your entire digital ecosystem
          </p>
        </motion.div>

        {/* Main slider content */}
        <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 items-center">
          {/* Left side - Content */}
          <div className="order-2 lg:order-1">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeCase.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.3 }}
              >
                {/* Title with icon */}
                <div className="flex items-center gap-3 sm:gap-4 mb-6">
                  <div className={`w-12 h-12 sm:w-14 sm:h-14 rounded-xl sm:rounded-2xl bg-gradient-to-br ${activeCase.gradient} flex items-center justify-center shadow-lg ${colors.glow}`}>
                    <activeCase.icon className="w-6 h-6 sm:w-7 sm:h-7 text-white" />
                  </div>
                  <h3 className="text-xl sm:text-2xl md:text-3xl font-bold text-white">
                    {activeCase.title}
                  </h3>
                </div>

                {/* Features list */}
                <ul className="space-y-4">
                  {activeCase.features.map((feature, index) => (
                    <motion.li
                      key={feature}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: index * 0.1 }}
                      className="flex items-center gap-3"
                    >
                      <div className={`w-6 h-6 rounded-full ${colors.bg} ${colors.border} border flex items-center justify-center flex-shrink-0`}>
                        <CheckCircle2 className={`w-4 h-4 ${colors.text}`} />
                      </div>
                      <span className="text-gray-300">{feature}</span>
                    </motion.li>
                  ))}
                </ul>
              </motion.div>
            </AnimatePresence>

            {/* Slide indicators / tabs */}
            <div className="flex gap-3 mt-10">
              {useCases.map((useCase, index) => {
                const tabColors = colorClasses[useCase.color];
                const isActive = index === activeIndex;
                return (
                  <button
                    key={useCase.id}
                    onClick={() => handleSlideClick(index)}
                    className={`
                      relative flex-1 h-1.5 rounded-full overflow-hidden
                      transition-all duration-300
                      ${isActive ? tabColors.activeBg : 'bg-white/10 hover:bg-white/20'}
                    `}
                  >
                    {/* Progress fill for active slide */}
                    {isActive && (
                      <div
                        className="absolute inset-0 bg-white/30 rounded-full origin-left"
                        style={{ transform: `scaleX(${progress / 100})` }}
                      />
                    )}
                  </button>
                );
              })}
            </div>

            {/* Tab labels */}
            <div className="flex gap-3 mt-3">
              {useCases.map((useCase, index) => {
                const tabColors = colorClasses[useCase.color];
                const isActive = index === activeIndex;
                return (
                  <button
                    key={useCase.id}
                    onClick={() => handleSlideClick(index)}
                    className={`
                      flex-1 text-xs font-medium transition-colors duration-300
                      ${isActive ? tabColors.text : 'text-gray-500 hover:text-gray-400'}
                    `}
                  >
                    <span className="hidden sm:inline">{useCase.title.split(' ')[0]}</span>
                    <useCase.icon className="w-4 h-4 mx-auto sm:hidden" />
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right side - Image/Visual */}
          <div className="order-1 lg:order-2">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeCase.id}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.3 }}
                className={`
                  relative aspect-[16/10] sm:aspect-[4/3] rounded-xl sm:rounded-2xl overflow-hidden
                  bg-gradient-to-br ${activeCase.gradient} p-[1px]
                `}
              >
                <div className="absolute inset-[1px] bg-gray-900 rounded-xl sm:rounded-2xl overflow-hidden">
                  {/* Screenshot image */}
                  <img 
                    src={activeCase.image} 
                    alt={`${activeCase.title} Dashboard`}
                    className="w-full h-full object-contain"
                  />
                  
                  {/* Overlay gradient */}
                  <div className="absolute inset-0 bg-gradient-to-t from-gray-900/80 via-transparent to-transparent" />

                  {/* Badge at bottom */}
                  <div className="absolute bottom-3 left-3 right-3 sm:bottom-6 sm:left-6 sm:right-6">
                    <div className={`
                      inline-flex items-center gap-1.5 sm:gap-2 px-3 py-1.5 sm:px-4 sm:py-2 rounded-full
                      ${colors.bg} ${colors.border} border backdrop-blur-sm
                    `}>
                      <Shield className={`w-3 h-3 sm:w-4 sm:h-4 ${colors.text}`} />
                      <span className={`text-xs sm:text-sm font-medium ${colors.text}`}>
                        {activeCase.title} Dashboard
                      </span>
                    </div>
                  </div>
                </div>
              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </section>
  );
};

export default UseCasesSlider;
