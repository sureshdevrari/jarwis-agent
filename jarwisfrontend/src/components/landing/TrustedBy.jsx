// src/components/landing/TrustedBy.jsx
// Scrolling logo marquee inspired by Devin.ai's integrations section

import { motion } from "framer-motion";

// Placeholder logos - replace with actual partner/technology logos
const logos = [
  { name: "AWS", icon: "☁️" },
  { name: "Azure", icon: "☁️" },
  { name: "GCP", icon: "☁️" },
  { name: "Kubernetes", icon: "⎈" },
  { name: "Docker", icon: "🐳" },
  { name: "GitHub", icon: "🐙" },
  { name: "GitLab", icon: "🦊" },
  { name: "Jenkins", icon: "🔧" },
  { name: "Terraform", icon: "🏗️" },
  { name: "Ansible", icon: "🤖" },
];

const LogoItem = ({ name, icon }) => (
  <div className="flex items-center gap-2 sm:gap-3 px-4 sm:px-6 py-2 sm:py-3 mx-2 sm:mx-4 rounded-lg sm:rounded-xl bg-white/[0.02] border border-white/[0.05] hover:border-white/[0.1] transition-colors">
    <span className="text-xl sm:text-2xl">{icon}</span>
    <span className="text-xs sm:text-sm font-medium text-gray-400 whitespace-nowrap">{name}</span>
  </div>
);

const TrustedBy = () => {
  return (
    <section className="py-16 border-y border-white/[0.05] bg-black/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mb-8">
        <motion.p
          initial={{ opacity: 0, y: 10 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="text-center text-sm font-medium text-gray-500 uppercase tracking-wider"
        >
          Works with your existing stack
        </motion.p>
      </div>

      {/* Marquee container */}
      <div className="relative overflow-hidden">
        {/* Fade edges */}
        <div className="absolute left-0 top-0 bottom-0 w-16 sm:w-32 bg-gradient-to-r from-gray-950 to-transparent z-10 pointer-events-none" />
        <div className="absolute right-0 top-0 bottom-0 w-16 sm:w-32 bg-gradient-to-l from-gray-950 to-transparent z-10 pointer-events-none" />

        {/* Scrolling track */}
        <motion.div
          className="flex"
          animate={{ x: [0, -1000] }}
          transition={{
            x: {
              repeat: Infinity,
              repeatType: "loop",
              duration: 30,
              ease: "linear",
            },
          }}
        >
          {/* Double the logos for seamless loop */}
          {[...logos, ...logos, ...logos].map((logo, index) => (
            <LogoItem key={`${logo.name}-${index}`} {...logo} />
          ))}
        </motion.div>
      </div>
    </section>
  );
};

export default TrustedBy;
