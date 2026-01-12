// AIEngineSection.jsx
// Showcases JARWIS AI capabilities - No LLMs, Built by BKD Labs
// Enhanced with prominent branding and interactive demo

import { useReducedMotion } from '../../hooks/useReducedMotion';
import InteractiveScanPreview from './InteractiveScanPreview';
import { AIModelsSection } from '../icons/custom/AIModelBadge';
import { Lock, Zap, Target, Shield } from 'lucide-react';
import '../../styles/scan-animations.css';

const AIEngineSection = ({ scanType = 'web', showInteractiveDemo = true }) => {
  const prefersReducedMotion = useReducedMotion();
  const gradients = {
    web: 'from-cyan-400 to-blue-500',
    mobile: 'from-purple-400 to-pink-500',
    network: 'from-green-400 to-emerald-500',
    cloud: 'from-orange-400 to-amber-500',
    sast: 'from-red-400 to-rose-500'
  };

  const features = [
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
        </svg>
      ),
      title: "Pure Algorithmic Intelligence",
      description: "No OpenAI, no Gemini, no external APIs. Our AI is built from the ground up using proprietary algorithms."
    },
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
        </svg>
      ),
      title: "Bayesian Confidence Scoring",
      description: "Statistical probability-based vulnerability detection with confidence levels from LOW to VERY_HIGH."
    },
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      ),
      title: "Self-Improving Accuracy",
      description: "Learns from user feedback loops to continuously improve detection rates and reduce false positives."
    },
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      ),
      title: "Zero Data Leakage",
      description: "All processing happens locally. Your security data never leaves your environment. Complete privacy."
    },
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
        </svg>
      ),
      title: "Attack Chain Detection",
      description: "Combines multiple vulnerabilities to find compound attack paths that maximize impact assessment."
    },
    {
      icon: (
        <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
        </svg>
      ),
      title: "Evidence-Based Findings",
      description: "Step-by-step reasoning chain explains exactly why each vulnerability was flagged with proof."
    }
  ];

  return (
    <section className="relative py-20 lg:py-32 overflow-hidden">
      {/* Background Gradient */}
      <div className="absolute inset-0 bg-gradient-to-b from-transparent via-gray-950/50 to-transparent" />
      
      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 mb-6">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
            </span>
            <span className="text-sm font-medium text-cyan-400">Built by BKD Labs</span>
          </div>
          
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-6">
            <span className="text-white">Powered by </span>
            <span className={`bg-gradient-to-r ${gradients[scanType]} bg-clip-text text-transparent`}>
              JARWIS AI Engine
            </span>
          </h2>
          
          <p className="text-lg text-gray-400 max-w-3xl mx-auto">
            Our proprietary AI engine doesn't rely on any external LLMs or APIs. 
            Every analysis is performed using custom algorithms developed in-house, 
            ensuring complete privacy and consistent accuracy.
          </p>

          {/* AI Models Branding */}
          <div className="mt-8">
            <AIModelsSection showDescription={true} />
          </div>
        </div>

        {/* Stats Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mb-16">
          {[
            { value: '99.8%', label: 'Detection Accuracy' },
            { value: '< 0.5%', label: 'False Positive Rate' },
            { value: '10x', label: 'Faster Than Manual' },
            { value: '0', label: 'External API Calls' }
          ].map((stat, index) => (
            <div key={index} className="text-center p-6 rounded-2xl bg-white/5 border border-white/10">
              <div className={`text-3xl sm:text-4xl font-bold bg-gradient-to-r ${gradients[scanType]} bg-clip-text text-transparent`}>
                {stat.value}
              </div>
              <div className="text-sm text-gray-500 mt-2">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <div
              key={index}
              className={`group p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-cyan-500/30 hover:bg-white/8 ${
                prefersReducedMotion ? '' : 'transition-all duration-300'
              }`}
            >
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${gradients[scanType]} bg-opacity-20 flex items-center justify-center mb-4 text-white`}>
                {feature.icon}
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">{feature.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{feature.description}</p>
            </div>
          ))}
        </div>

        {/* Interactive Demo Section */}
        {showInteractiveDemo && (
          <div className="mt-16 grid lg:grid-cols-2 gap-8 items-start">
            <div className="order-2 lg:order-1">
              <InteractiveScanPreview 
                scanType={scanType} 
                autoPlay={true}
                showControls={true}
                className="w-full"
              />
            </div>
            <div className="order-1 lg:order-2 flex flex-col justify-center">
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20 mb-4 w-fit">
                <span className="w-2 h-2 rounded-full bg-green-500"></span>
                <span className="text-xs font-medium text-green-400">Live Demo</span>
              </div>
              <h3 className="text-2xl font-bold text-white mb-4">See JARWIS in Action</h3>
              <p className="text-gray-400 mb-6">
                Watch how our multi-layer scanning engine systematically analyzes your application, 
                from reconnaissance to AI-powered verification. Each layer runs in parallel for 
                maximum efficiency while ensuring zero data leaves your environment.
              </p>
              <div className="space-y-3">
                {[
                  { icon: Lock, text: 'All processing happens locally' },
                  { icon: Zap, text: '10x faster than traditional tools' },
                  { icon: Target, text: '99.8% detection accuracy' },
                  { icon: Shield, text: 'Zero false positive guarantee' }
                ].map((item, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <item.icon className="w-5 h-5 text-cyan-400" />
                    <span className="text-sm text-gray-300">{item.text}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* BKD Labs Branding Banner */}
        <div className="mt-16 relative overflow-hidden rounded-2xl">
          {/* Animated gradient background */}
          <div className={`absolute inset-0 bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 ${
            prefersReducedMotion ? '' : 'animate-gradient-x'
          }`}></div>
          <div className="absolute inset-0 bg-black/40"></div>
          
          <div className="relative z-10 p-8 md:p-12">
            <div className="flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="text-center md:text-left">
                <div className="flex items-center justify-center md:justify-start gap-3 mb-4">
                  <div className="w-12 h-12 rounded-xl bg-white/20 backdrop-blur flex items-center justify-center">
                    <span className="text-2xl">🧠</span>
                  </div>
                  <div>
                    <p className="text-xs text-cyan-200 uppercase tracking-wider">Built by</p>
                    <p className="text-xl font-bold text-white">BKD Labs</p>
                  </div>
                </div>
                <h3 className="text-2xl md:text-3xl font-bold text-white mb-3">
                  No LLMs. No External APIs.<br />
                  <span className="text-cyan-300">Just Pure Intelligence.</span>
                </h3>
                <p className="text-white/80 max-w-xl">
                  Unlike tools that send your code to OpenAI, Gemini, or other third-party services, 
                  JARWIS AI is built entirely in-house. Your security data never leaves your environment.
                </p>
              </div>
              
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="px-6 py-4 rounded-xl bg-white/10 backdrop-blur border border-white/20 text-center">
                  <p className="text-3xl font-bold text-white">0</p>
                  <p className="text-xs text-white/70">External API Calls</p>
                </div>
                <div className="px-6 py-4 rounded-xl bg-white/10 backdrop-blur border border-white/20 text-center">
                  <p className="text-3xl font-bold text-white">100%</p>
                  <p className="text-xs text-white/70">Data Privacy</p>
                </div>
                <div className="px-6 py-4 rounded-xl bg-white/10 backdrop-blur border border-white/20 text-center">
                  <p className="text-3xl font-bold text-white">0</p>
                  <p className="text-xs text-white/70">Data Leakage</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AIEngineSection;
