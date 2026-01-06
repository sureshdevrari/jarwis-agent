// src/components/landing/CTASection.jsx
// Final call-to-action section with Devin.ai-inspired styling

import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowRight, Sparkles } from "lucide-react";

const CTASection = () => {
  const navigate = useNavigate();

  return (
    <section className="py-24 lg:py-32 relative overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-violet-500/10 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.4 }}
          className="inline-flex items-center gap-2 px-4 py-2 mb-6 rounded-full bg-white/5 border border-white/10"
        >
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span className="text-sm text-gray-300">Start protecting your apps today</span>
        </motion.div>

        {/* Heading */}
        <motion.h2
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.1, duration: 0.5 }}
          className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6"
        >
          Ready to experience{" "}
          <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
            AI-powered
          </span>{" "}
          security?
        </motion.h2>

        {/* Description */}
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.2, duration: 0.5 }}
          className="text-lg text-gray-400 max-w-2xl mx-auto mb-10"
        >
          Join forward-thinking teams who trust Jarwis to find vulnerabilities before attackers do.
          Request trial access for your organization today.
        </motion.p>

        {/* CTA Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.3, duration: 0.5 }}
          className="flex flex-col sm:flex-row gap-4 justify-center px-4"
        >
          <button
            onClick={() => navigate("/request-trial")}
            className="group inline-flex items-center justify-center gap-2 px-6 sm:px-8 py-3.5 sm:py-4 text-sm sm:text-base font-semibold text-white bg-gradient-to-r from-cyan-500 to-blue-600 rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all duration-300 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:-translate-y-0.5 min-h-[48px] touch-target active:scale-[0.98]"
          >
            Request Trial Access
            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </button>
          <button
            onClick={() => navigate("/contact")}
            className="inline-flex items-center justify-center gap-2 px-6 sm:px-8 py-3.5 sm:py-4 text-sm sm:text-base font-semibold text-gray-300 bg-white/5 border border-white/10 rounded-xl hover:bg-white/10 hover:border-white/20 transition-all duration-300 min-h-[48px] touch-target active:scale-[0.98]"
          >
            Contact Sales
          </button>
        </motion.div>

        {/* Enterprise note */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ delay: 0.5, duration: 0.5 }}
          className="mt-16 p-6 rounded-2xl bg-white/[0.02] border border-white/[0.05]"
        >
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="text-left">
              <h3 className="text-xl font-semibold text-white mb-2">
                Need Jarwis for your enterprise?
              </h3>
              <p className="text-gray-400">
                Custom deployments, VPC hosting, dedicated support, and more.
              </p>
            </div>
            <button
              onClick={() => navigate("/contact")}
              className="whitespace-nowrap px-6 py-3 text-sm font-medium text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/10 transition-colors"
            >
              Learn About Enterprise &rarr;
            </button>
          </div>
        </motion.div>
      </div>
    </section>
  );
};

export default CTASection;
