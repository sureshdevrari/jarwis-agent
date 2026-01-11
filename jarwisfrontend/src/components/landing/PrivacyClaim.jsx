// src/components/landing/PrivacyClaim.jsx
// Bold privacy statement section above footer

import { motion } from "framer-motion";
import { ShieldCheck, Lock } from "lucide-react";

const PrivacyClaim = () => {
  return (
    <section className="py-20 lg:py-28 relative overflow-hidden">
      {/* Animated background gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-gray-950 via-gray-900 to-gray-950" />
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyan-900/20 via-transparent to-transparent" />
      
      {/* Floating orbs */}
      <motion.div
        animate={{
          scale: [1, 1.2, 1],
          opacity: [0.3, 0.5, 0.3]
        }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
        className="absolute left-1/4 top-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl"
      />
      <motion.div
        animate={{
          scale: [1.2, 1, 1.2],
          opacity: [0.2, 0.4, 0.2]
        }}
        transition={{ duration: 5, repeat: Infinity, ease: "easeInOut" }}
        className="absolute right-1/4 top-1/2 -translate-y-1/2 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl"
      />

      <div className="relative max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Shield Icon */}
        <motion.div
          initial={{ opacity: 0, scale: 0.5 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 mb-8 shadow-lg shadow-cyan-500/30"
        >
          <ShieldCheck className="w-10 h-10 text-white" />
        </motion.div>

        {/* Main claim - Crossed out vs Correct */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="mb-8"
        >
          {/* Wrong statement */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-4 mb-4">
            <span className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-medium text-gray-500 line-through decoration-red-500/70 decoration-2 text-center">
              Jarwis will never see your data
            </span>
            <span className="text-2xl sm:text-3xl lg:text-4xl">❌</span>
          </div>

          {/* Correct statement */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-4">
            <span className="text-lg sm:text-2xl md:text-3xl lg:text-4xl font-bold bg-gradient-to-r from-cyan-400 via-blue-400 to-cyan-400 bg-clip-text text-transparent text-center">
              Jarwis cannot even see your data
            </span>
            <span className="text-2xl sm:text-3xl lg:text-4xl">✅</span>
          </div>
        </motion.div>

        {/* Encryption badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="inline-flex items-center gap-2 sm:gap-3 px-4 sm:px-6 py-2 sm:py-3 rounded-full bg-white/[0.03] border border-white/10 backdrop-blur-sm"
        >
          <Lock className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
          <span className="text-base sm:text-lg md:text-xl text-gray-300 font-medium">
            Your scans are end-to-end encrypted
          </span>
        </motion.div>

        {/* Trust indicators */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5, delay: 0.5 }}
          className="mt-8 sm:mt-10 flex flex-col sm:flex-row flex-wrap items-center justify-center gap-4 sm:gap-6 text-xs sm:text-sm text-gray-500"
        >
          <span className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            Zero-knowledge architecture
          </span>
          <span className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            SOC 2 Type II compliant
          </span>
          <span className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-500" />
            GDPR ready
          </span>
        </motion.div>
      </div>
    </section>
  );
};

export default PrivacyClaim;
