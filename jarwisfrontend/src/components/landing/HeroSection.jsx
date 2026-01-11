// src/components/landing/HeroSection.jsx
// Devin.ai-inspired hero section for Jarwis landing page

import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Zap, Lock, ArrowRight } from "lucide-react";

const HeroSection = () => {
  const navigate = useNavigate();

  return (
    <section className="relative min-h-[90vh] flex items-center justify-center overflow-hidden">
      {/* Background gradient orbs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-[600px] h-[600px] bg-cyan-500/10 rounded-full blur-[120px] animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-blue-500/10 rounded-full blur-[100px] animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-violet-500/5 rounded-full blur-[150px]" />
      </div>

      {/* Grid pattern overlay */}
      <div 
        className="absolute inset-0 opacity-[0.02]"
        style={{
          backgroundImage: `
            linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px'
        }}
      />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 lg:py-20">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left content */}
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
            className="text-center lg:text-left"
          >
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1, duration: 0.4 }}
              className="inline-flex items-center gap-2 px-4 py-2 mb-6 rounded-full bg-white/5 border border-white/10 backdrop-blur-sm"
            >
              <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
              <span className="text-sm text-gray-300 font-medium">
                AI-Powered Security Testing
              </span>
            </motion.div>

            {/* Main headline */}
            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="text-4xl sm:text-5xl lg:text-6xl xl:text-7xl font-bold leading-[1.1] tracking-tight mb-6"
            >
              Meet{" "}
              <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-violet-500 bg-clip-text text-transparent">
                Jarwis
              </span>
              <br />
              <span className="text-white/90">Your AI Security</span>
              <br />
              <span className="text-white/90">Engineer</span>
            </motion.h1>

            {/* Subtitle */}
            <motion.p
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.5 }}
              className="text-lg sm:text-xl text-gray-400 max-w-xl mx-auto lg:mx-0 mb-8 leading-relaxed"
            >
              The world's first human-like AI security engineer that discovers and
              fixes OWASP Top 10 vulnerabilities autonomously. Just describe what
              you need, Jarwis handles the rest.
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4, duration: 0.5 }}
              className="flex flex-col sm:flex-row gap-4 justify-center lg:justify-start"
            >
              <button
                onClick={() => navigate("/request-trial")}
                className="group inline-flex items-center justify-center gap-2 px-8 py-4 text-base font-semibold text-white bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all duration-300 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:-translate-y-0.5"
              >
                Request Trial Access
                <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
              </button>
              <button
                onClick={() => navigate("/about")}
                className="inline-flex items-center justify-center gap-2 px-8 py-4 text-base font-semibold text-gray-300 bg-white/5 border border-white/10 rounded-xl hover:bg-white/10 hover:border-white/20 transition-all duration-300"
              >
                Learn More
              </button>
            </motion.div>

            {/* Trust indicators */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.6, duration: 0.5 }}
              className="mt-12 flex flex-wrap items-center justify-center lg:justify-start gap-6 text-sm text-gray-500"
            >
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>SOC 2 Compliant</span>
              </div>
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Enterprise Ready</span>
              </div>
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-cyan-400" />
                <span>10x Faster Scans</span>
              </div>
            </motion.div>
          </motion.div>

          {/* Right content - Demo/Visual */}
          <motion.div
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="relative mt-12 lg:mt-0"
          >
            {/* Floating cards mockup */}
            <div className="relative max-w-md mx-auto lg:max-w-none">
              {/* Main card */}
              <div className="relative z-10 p-4 sm:p-6 rounded-xl sm:rounded-2xl bg-gradient-to-br from-gray-900/90 to-gray-800/90 border border-white/10 backdrop-blur-xl shadow-2xl">
                <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4">
                  <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-red-500" />
                  <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-yellow-500" />
                  <div className="w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full bg-green-500" />
                </div>
                <div className="space-y-2 sm:space-y-3">
                  <div className="flex items-center gap-2 sm:gap-3 p-2 sm:p-3 rounded-lg bg-white/5 border border-white/5 overflow-x-auto">
                    <span className="text-cyan-400 font-mono text-xs sm:text-sm flex-shrink-0">$</span>
                    <span className="text-gray-300 font-mono text-xs sm:text-sm whitespace-nowrap">
                      jarwis scan https://example.com
                    </span>
                  </div>
                  <div className="space-y-1.5 sm:space-y-2 font-mono text-[10px] sm:text-xs">
                    <div className="text-green-400">✓ Discovering endpoints...</div>
                    <div className="text-green-400">✓ Testing authentication flows...</div>
                    <div className="text-cyan-400">&gt; Analyzing for SQL injection...</div>
                    <div className="text-gray-500 hidden xs:block">o XSS detection pending</div>
                    <div className="text-gray-500 hidden sm:block">o CSRF validation pending</div>
                  </div>
                </div>
              </div>

              {/* Floating badge - Top right */}
              <div className="absolute -top-2 -right-2 sm:-top-4 sm:-right-4 z-20 px-2 py-1 sm:px-4 sm:py-2 rounded-lg sm:rounded-xl bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 backdrop-blur-sm">
                <div className="flex items-center gap-1.5 sm:gap-2">
                  <div className="w-1.5 h-1.5 sm:w-2 sm:h-2 bg-green-400 rounded-full animate-pulse" />
                  <span className="text-green-400 text-[10px] sm:text-sm font-medium">3 vulnerabilities found</span>
                </div>
              </div>

              {/* Floating card - Bottom left - Hidden on very small screens */}
              <div className="hidden xs:block absolute -bottom-4 -left-4 sm:-bottom-6 sm:-left-8 z-20 p-2 sm:p-4 rounded-lg sm:rounded-xl bg-gradient-to-br from-violet-500/20 to-purple-500/20 border border-violet-500/30 backdrop-blur-sm">
                <div className="flex items-center gap-2 sm:gap-3">
                  <div className="w-8 h-8 sm:w-10 sm:h-10 rounded-lg bg-violet-500/20 flex items-center justify-center">
                    <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-violet-400" />
                  </div>
                  <div>
                    <div className="text-xs sm:text-sm font-medium text-white">OWASP A03</div>
                    <div className="text-[10px] sm:text-xs text-gray-400">SQL Injection detected</div>
                  </div>
                </div>
              </div>

              {/* Glow effect behind main card */}
              <div className="absolute inset-0 -z-10 blur-3xl bg-gradient-to-r from-cyan-500/20 via-blue-500/20 to-violet-500/20 rounded-3xl transform scale-110" />
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;
