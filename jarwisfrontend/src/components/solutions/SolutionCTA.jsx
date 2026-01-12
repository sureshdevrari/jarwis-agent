// SolutionCTA.jsx
// Call-to-action section for solution pages

import { Link } from 'react-router-dom';
import { Lock, Zap, Bot, BarChart3 } from 'lucide-react';

const SolutionCTA = ({ 
  scanType = 'web',
  title = "Ready to Secure Your Application?",
  subtitle = "Start your security assessment today with JARWIS AI-powered scanning.",
  primaryCTA = { text: 'Start Free Scan', link: '/login' },
  secondaryCTA = { text: 'Schedule Demo', link: '/contact' }
}) => {
  const gradients = {
    web: 'from-cyan-500 to-blue-600',
    mobile: 'from-purple-500 to-pink-600',
    network: 'from-green-500 to-emerald-600',
    cloud: 'from-orange-500 to-amber-600',
    sast: 'from-red-500 to-rose-600'
  };

  const glows = {
    web: 'rgba(6, 182, 212, 0.2)',
    mobile: 'rgba(139, 92, 246, 0.2)',
    network: 'rgba(34, 197, 94, 0.2)',
    cloud: 'rgba(249, 115, 22, 0.2)',
    sast: 'rgba(239, 68, 68, 0.2)'
  };

  return (
    <section className="relative py-20 lg:py-32 overflow-hidden">
      {/* Background Glow */}
      <div 
        className="absolute inset-0"
        style={{
          background: `radial-gradient(ellipse at center, ${glows[scanType]}, transparent 70%)`
        }}
      />

      <div className="relative z-10 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-white/5 border border-white/10 mb-8">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
          </span>
          <span className="text-sm text-gray-400">Free tier available • No credit card required</span>
        </div>

        {/* Title */}
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-white mb-6">
          {title}
        </h2>

        {/* Subtitle */}
        <p className="text-lg text-gray-400 mb-10 max-w-2xl mx-auto">
          {subtitle}
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            to={primaryCTA.link}
            className={`group relative px-8 py-4 rounded-xl font-semibold text-white overflow-hidden transition-all duration-300 hover:scale-105 bg-gradient-to-r ${gradients[scanType]} hover:shadow-xl`}
            style={{ boxShadow: `0 10px 40px ${glows[scanType]}` }}
          >
            <span className="relative z-10 flex items-center justify-center gap-2">
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

        {/* Trust Indicators */}
        <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-6">
          {[
            { icon: Lock, text: 'SOC 2 Compliant' },
            { icon: Zap, text: 'Results in Minutes' },
            { icon: Bot, text: 'AI-Powered Analysis' },
            { icon: BarChart3, text: 'Detailed Reports' }
          ].map((item, index) => {
            const IconComponent = item.icon;
            return (
              <div key={index} className="flex items-center justify-center gap-2 text-gray-400">
                <IconComponent className="w-5 h-5 text-cyan-400" />
                <span className="text-sm">{item.text}</span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};

export default SolutionCTA;
