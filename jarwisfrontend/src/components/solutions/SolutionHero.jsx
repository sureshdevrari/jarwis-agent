// SolutionHero.jsx
// Reusable hero section for solution pages

import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Globe, Smartphone, Server, Cloud, Code2 } from 'lucide-react';
import '../../styles/scan-animations.css';

// Icon mapping for scan types
const scanTypeIcons = {
  web: Globe,
  mobile: Smartphone,
  network: Server,
  cloud: Cloud,
  sast: Code2
};

const SolutionHero = ({ 
  badge,
  title,
  titleHighlight,
  description,
  primaryCTA = { text: 'Start Free Scan', link: '/login' },
  secondaryCTA = { text: 'View Pricing', link: '/pricing' },
  scanType = 'web', // web, mobile, network, cloud, sast
  stats = []
}) => {
  const gradientMap = {
    web: 'from-cyan-400 via-blue-500 to-cyan-400',
    mobile: 'from-purple-400 via-pink-500 to-purple-400',
    network: 'from-green-400 via-emerald-500 to-green-400',
    cloud: 'from-orange-400 via-amber-500 to-orange-400',
    sast: 'from-red-400 via-rose-500 to-red-400'
  };

  const glowColorMap = {
    web: 'rgba(6, 182, 212, 0.3)',
    mobile: 'rgba(139, 92, 246, 0.3)',
    network: 'rgba(34, 197, 94, 0.3)',
    cloud: 'rgba(249, 115, 22, 0.3)',
    sast: 'rgba(239, 68, 68, 0.3)'
  };

  const badgeColorMap = {
    web: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400',
    mobile: 'bg-purple-500/10 border-purple-500/30 text-purple-400',
    network: 'bg-green-500/10 border-green-500/30 text-green-400',
    cloud: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    sast: 'bg-red-500/10 border-red-500/30 text-red-400'
  };

  return (
    <section className="relative min-h-[90vh] flex items-center overflow-hidden">
      {/* Background Grid */}
      <div className="grid-pattern" />
      
      {/* Gradient Orbs */}
      <div 
        className="solution-hero-orb orb-1"
        style={{ background: `radial-gradient(circle, ${glowColorMap[scanType]}, transparent 70%)` }}
      />
      <div 
        className="solution-hero-orb orb-2"
        style={{ background: `radial-gradient(circle, ${glowColorMap[scanType].replace('0.3', '0.2')}, transparent 70%)` }}
      />

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="grid lg:grid-cols-2 gap-12 lg:gap-16 items-center">
          {/* Left Content */}
          <motion.div 
            className="space-y-8"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, ease: "easeOut" }}
          >
            {/* Badge */}
            <motion.div 
              className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border ${badgeColorMap[scanType]}`}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1, duration: 0.4 }}
            >
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${scanType === 'web' ? 'bg-cyan-400' : scanType === 'mobile' ? 'bg-purple-400' : scanType === 'network' ? 'bg-green-400' : scanType === 'cloud' ? 'bg-orange-400' : 'bg-red-400'}`}></span>
                <span className={`relative inline-flex rounded-full h-2 w-2 ${scanType === 'web' ? 'bg-cyan-400' : scanType === 'mobile' ? 'bg-purple-400' : scanType === 'network' ? 'bg-green-400' : scanType === 'cloud' ? 'bg-orange-400' : 'bg-red-400'}`}></span>
              </span>
              {(() => {
                const IconComponent = scanTypeIcons[scanType];
                return IconComponent ? <IconComponent className="w-4 h-4" /> : null;
              })()}
              <span className="text-sm font-medium">{badge}</span>
            </motion.div>

            {/* Title */}
            <motion.h1 
              className="text-4xl sm:text-5xl lg:text-6xl font-bold leading-tight"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2, duration: 0.5 }}
            >
              <span className="text-white">{title}</span>
              {titleHighlight && (
                <>
                  <br />
                  <span className={`bg-gradient-to-r ${gradientMap[scanType]} bg-clip-text text-transparent`}>
                    {titleHighlight}
                  </span>
                </>
              )}
            </motion.h1>

            {/* Description */}
            <motion.p 
              className="text-lg sm:text-xl text-gray-400 max-w-xl leading-relaxed"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.5 }}
            >
              {description}
            </motion.p>

            {/* CTAs */}
            <div className="flex flex-wrap gap-4">
              <Link
                to={primaryCTA.link}
                className={`group relative px-8 py-4 rounded-xl font-semibold text-white overflow-hidden transition-all duration-300 hover:scale-105 ${
                  scanType === 'web' ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:shadow-lg hover:shadow-cyan-500/25' :
                  scanType === 'mobile' ? 'bg-gradient-to-r from-purple-500 to-pink-600 hover:shadow-lg hover:shadow-purple-500/25' :
                  scanType === 'network' ? 'bg-gradient-to-r from-green-500 to-emerald-600 hover:shadow-lg hover:shadow-green-500/25' :
                  scanType === 'cloud' ? 'bg-gradient-to-r from-orange-500 to-amber-600 hover:shadow-lg hover:shadow-orange-500/25' :
                  'bg-gradient-to-r from-red-500 to-rose-600 hover:shadow-lg hover:shadow-red-500/25'
                }`}
              >
                <span className="relative z-10 flex items-center gap-2">
                  {primaryCTA.text}
                  <svg className="w-5 h-5 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                </span>
              </Link>
              
              <Link
                to={secondaryCTA.link}
                className="px-8 py-4 rounded-xl font-semibold text-white bg-white/5 border border-white/10 hover:bg-white/10 hover:border-white/20 transition-all duration-300"
              >
                {secondaryCTA.text}
              </Link>
            </div>

            {/* Stats */}
            {stats.length > 0 && (
              <motion.div 
                className="flex flex-wrap gap-8 pt-4"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.5, duration: 0.5 }}
              >
                {stats.map((stat, index) => (
                  <motion.div 
                    key={index} 
                    className="text-center"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.5 + index * 0.1, duration: 0.4 }}
                  >
                    <div className={`text-3xl font-bold bg-gradient-to-r ${gradientMap[scanType]} bg-clip-text text-transparent`}>
                      {stat.value}
                    </div>
                    <div className="text-sm text-gray-500">{stat.label}</div>
                  </motion.div>
                ))}
              </motion.div>
            )}
          </motion.div>

          {/* Right Side - Scan Animation */}
          <motion.div 
            className="relative lg:pl-8"
            initial={{ opacity: 0, x: 30 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
          >
            <div className={`scan-layers-container scan-${scanType}`}>
              {/* Multi-layer scanning rings */}
              <div className="scan-layer scan-layer-1"></div>
              <div className="scan-layer scan-layer-2"></div>
              <div className="scan-layer scan-layer-3"></div>
              <div className="scan-layer scan-layer-4"></div>
              <div className="scan-layer scan-layer-5"></div>
              
              {/* Rotating scanner line */}
              <div className="scanner-line-container">
                <div className="scanner-line"></div>
              </div>
              
              {/* Data particles */}
              <div className="data-particles">
                <div className="data-particle"></div>
                <div className="data-particle"></div>
                <div className="data-particle"></div>
                <div className="data-particle"></div>
                <div className="data-particle"></div>
                <div className="data-particle"></div>
              </div>
              
              {/* Core glow */}
              <div className="scan-core"></div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
};

export default SolutionHero;
