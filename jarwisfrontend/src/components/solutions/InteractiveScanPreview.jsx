// InteractiveScanPreview.jsx
// Interactive scan visualization showing layers activating in sequence
// Respects prefers-reduced-motion accessibility preference

import { useState, useEffect, useCallback } from 'react';
import { useReducedMotion } from '../../hooks/useReducedMotion';
import {
  Search,
  Bug,
  KeyRound,
  Syringe,
  Brain,
  Smartphone,
  FileText,
  Play,
  Radio,
  Cloud,
  Shield,
  Users,
  Package,
  Monitor,
  Plug,
  AlertTriangle,
  Zap,
  Download,
  Key,
  Code
} from 'lucide-react';

// Icon mapping for scan layers
const iconMap = {
  '🔍': Search,
  '🕷️': Bug,
  '🔐': KeyRound,
  '💉': Syringe,
  '🧠': Brain,
  '📱': Smartphone,
  '📄': FileText,
  '▶️': Play,
  '📡': Radio,
  '☁️': Cloud,
  '🛡️': Shield,
  '👥': Users,
  '📦': Package,
  '🖥️': Monitor,
  '🔌': Plug,
  '⚠️': AlertTriangle,
  '💥': Zap,
  '📥': Download,
  '🔑': Key,
  '💻': Code
};

const InteractiveScanPreview = ({ 
  scanType = 'web',
  autoPlay = true,
  showControls = true,
  onComplete = () => {},
  className = ''
}) => {
  const prefersReducedMotion = useReducedMotion();
  const [currentLayer, setCurrentLayer] = useState(0);
  const [layerProgress, setLayerProgress] = useState({});
  const [findings, setFindings] = useState([]);
  const [phase, setPhase] = useState('idle'); // idle, scanning, analyzing, complete

  // Scan layers configuration per scan type
  const scanLayers = {
    web: [
      { id: 'recon', name: 'Reconnaissance', icon: '🔍', color: 'cyan', duration: 2000 },
      { id: 'crawl', name: 'Smart Crawling', icon: '🕷️', color: 'blue', duration: 2500 },
      { id: 'auth', name: 'Auth Analysis', icon: '🔐', color: 'purple', duration: 1800 },
      { id: 'inject', name: 'Injection Testing', icon: '💉', color: 'red', duration: 3000 },
      { id: 'ai', name: 'AI Verification', icon: '🧠', color: 'green', duration: 2000 }
    ],
    mobile: [
      { id: 'binary', name: 'Binary Analysis', icon: '📱', color: 'purple', duration: 2200 },
      { id: 'static', name: 'Static Scan', icon: '📄', color: 'blue', duration: 2000 },
      { id: 'dynamic', name: 'Dynamic Testing', icon: '▶️', color: 'cyan', duration: 2800 },
      { id: 'network', name: 'Traffic Analysis', icon: '📡', color: 'green', duration: 2000 },
      { id: 'ai', name: 'AI Verification', icon: '🧠', color: 'emerald', duration: 1800 }
    ],
    cloud: [
      { id: 'discover', name: 'Asset Discovery', icon: '☁️', color: 'orange', duration: 2000 },
      { id: 'cspm', name: 'CSPM Scan', icon: '🛡️', color: 'amber', duration: 2500 },
      { id: 'iam', name: 'IAM Analysis', icon: '👥', color: 'yellow', duration: 2200 },
      { id: 'container', name: 'Container Scan', icon: '📦', color: 'blue', duration: 2000 },
      { id: 'ai', name: 'AI Verification', icon: '🧠', color: 'green', duration: 1800 }
    ],
    network: [
      { id: 'host', name: 'Host Discovery', icon: '🖥️', color: 'green', duration: 1800 },
      { id: 'port', name: 'Port Scanning', icon: '🔌', color: 'emerald', duration: 2500 },
      { id: 'vuln', name: 'Vuln Detection', icon: '⚠️', color: 'yellow', duration: 3000 },
      { id: 'exploit', name: 'Exploit Check', icon: '💥', color: 'red', duration: 2200 },
      { id: 'ai', name: 'AI Verification', icon: '🧠', color: 'cyan', duration: 1800 }
    ],
    sast: [
      { id: 'clone', name: 'Repo Clone', icon: '📥', color: 'slate', duration: 1500 },
      { id: 'secrets', name: 'Secret Scan', icon: '🔑', color: 'red', duration: 2000 },
      { id: 'deps', name: 'Dependency Audit', icon: '📦', color: 'orange', duration: 2200 },
      { id: 'code', name: 'Code Analysis', icon: '💻', color: 'blue', duration: 3000 },
      { id: 'ai', name: 'AI Verification', icon: '🧠', color: 'green', duration: 1800 }
    ]
  };

  // Mock findings that appear during scan
  const mockFindings = {
    web: [
      { severity: 'critical', name: 'SQL Injection', layer: 'inject' },
      { severity: 'high', name: 'XSS Reflected', layer: 'inject' },
      { severity: 'medium', name: 'Missing CSRF Token', layer: 'auth' }
    ],
    mobile: [
      { severity: 'high', name: 'Insecure Storage', layer: 'static' },
      { severity: 'medium', name: 'SSL Pinning Bypass', layer: 'network' }
    ],
    cloud: [
      { severity: 'critical', name: 'Public S3 Bucket', layer: 'cspm' },
      { severity: 'high', name: 'Overprivileged IAM', layer: 'iam' }
    ],
    network: [
      { severity: 'critical', name: 'Open RDP Port', layer: 'port' },
      { severity: 'high', name: 'Default Credentials', layer: 'vuln' }
    ],
    sast: [
      { severity: 'critical', name: 'Hardcoded API Key', layer: 'secrets' },
      { severity: 'high', name: 'Vulnerable Dependency', layer: 'deps' }
    ]
  };

  const layers = scanLayers[scanType] || scanLayers.web;
  const mockFindingsData = mockFindings[scanType] || mockFindings.web;

  // Color classes mapping
  const colorClasses = {
    cyan: { bg: 'bg-cyan-500', text: 'text-cyan-400', border: 'border-cyan-500', glow: 'shadow-cyan-500/50' },
    blue: { bg: 'bg-blue-500', text: 'text-blue-400', border: 'border-blue-500', glow: 'shadow-blue-500/50' },
    purple: { bg: 'bg-purple-500', text: 'text-purple-400', border: 'border-purple-500', glow: 'shadow-purple-500/50' },
    red: { bg: 'bg-red-500', text: 'text-red-400', border: 'border-red-500', glow: 'shadow-red-500/50' },
    green: { bg: 'bg-green-500', text: 'text-green-400', border: 'border-green-500', glow: 'shadow-green-500/50' },
    emerald: { bg: 'bg-emerald-500', text: 'text-emerald-400', border: 'border-emerald-500', glow: 'shadow-emerald-500/50' },
    orange: { bg: 'bg-orange-500', text: 'text-orange-400', border: 'border-orange-500', glow: 'shadow-orange-500/50' },
    amber: { bg: 'bg-amber-500', text: 'text-amber-400', border: 'border-amber-500', glow: 'shadow-amber-500/50' },
    yellow: { bg: 'bg-yellow-500', text: 'text-yellow-400', border: 'border-yellow-500', glow: 'shadow-yellow-500/50' },
    slate: { bg: 'bg-slate-500', text: 'text-slate-400', border: 'border-slate-500', glow: 'shadow-slate-500/50' }
  };

  const severityColors = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500'
  };

  // Run scan animation
  const runScan = useCallback(() => {
    if (prefersReducedMotion) {
      // Instant completion for reduced motion users
      setPhase('complete');
      setLayerProgress(layers.reduce((acc, l) => ({ ...acc, [l.id]: 100 }), {}));
      setFindings(mockFindingsData);
      setCurrentLayer(layers.length - 1);
      onComplete();
      return;
    }

    setPhase('scanning');
    setFindings([]);
    setLayerProgress({});
    setCurrentLayer(0);

    let layerIndex = 0;
    
    const processLayer = () => {
      if (layerIndex >= layers.length) {
        setPhase('analyzing');
        setTimeout(() => {
          setPhase('complete');
          onComplete();
        }, 1000);
        return;
      }

      const layer = layers[layerIndex];
      setCurrentLayer(layerIndex);
      
      // Animate progress for this layer
      const startTime = Date.now();
      const animateProgress = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(100, (elapsed / layer.duration) * 100);
        
        setLayerProgress(prev => ({ ...prev, [layer.id]: progress }));
        
        // Add finding when layer completes
        if (progress >= 100) {
          const layerFindings = mockFindingsData.filter(f => f.layer === layer.id);
          if (layerFindings.length > 0) {
            setFindings(prev => [...prev, ...layerFindings]);
          }
          layerIndex++;
          setTimeout(processLayer, 300);
        } else {
          requestAnimationFrame(animateProgress);
        }
      };
      
      requestAnimationFrame(animateProgress);
    };

    processLayer();
  }, [layers, mockFindingsData, prefersReducedMotion, onComplete]);

  // Start scan on mount if autoPlay
  useEffect(() => {
    if (autoPlay) {
      const timer = setTimeout(runScan, 500);
      return () => clearTimeout(timer);
    }
  }, [autoPlay, runScan]);

  // Reset and restart
  const handleRestart = () => {
    setPhase('idle');
    setCurrentLayer(0);
    setLayerProgress({});
    setFindings([]);
    setTimeout(runScan, 300);
  };

  return (
    <div className={`relative rounded-2xl bg-gray-900/80 border border-white/10 overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className={`relative flex h-3 w-3 ${phase === 'scanning' ? '' : 'opacity-50'}`}>
            {phase === 'scanning' && !prefersReducedMotion && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            )}
            <span className={`relative inline-flex rounded-full h-3 w-3 ${
              phase === 'complete' ? 'bg-green-500' : 
              phase === 'scanning' ? 'bg-cyan-500' : 'bg-gray-500'
            }`}></span>
          </div>
          <span className="text-sm font-medium text-white">
            {phase === 'idle' && 'Ready to Scan'}
            {phase === 'scanning' && `Scanning: ${layers[currentLayer]?.name || 'Initializing...'}`}
            {phase === 'analyzing' && 'AI Analyzing Results...'}
            {phase === 'complete' && `Scan Complete • ${findings.length} Issues Found`}
          </span>
        </div>
        
        {showControls && (
          <button
            onClick={handleRestart}
            className="px-3 py-1.5 text-xs font-medium rounded-lg bg-white/10 hover:bg-white/20 text-white transition-colors"
          >
            {phase === 'complete' ? 'Scan Again' : 'Restart'}
          </button>
        )}
      </div>

      {/* Scan Layers Visualization */}
      <div className="p-6 space-y-4">
        {layers.map((layer, index) => {
          const progress = layerProgress[layer.id] || 0;
          const isActive = index === currentLayer && phase === 'scanning';
          const isComplete = progress >= 100;
          const isPending = progress === 0 && index > currentLayer;
          const colors = colorClasses[layer.color] || colorClasses.cyan;

          return (
            <div 
              key={layer.id}
              className={`relative transition-all duration-300 ${
                isPending ? 'opacity-40' : 'opacity-100'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className={`${isActive ? colors.text : 'text-gray-400'}`}>
                    {(() => {
                      const IconComponent = iconMap[layer.icon];
                      return IconComponent ? <IconComponent className="w-5 h-5" /> : layer.icon;
                    })()}
                  </span>
                  <span className={`text-sm font-medium ${isActive ? colors.text : 'text-gray-300'}`}>
                    {layer.name}
                  </span>
                  {isActive && !prefersReducedMotion && (
                    <span className="flex items-center gap-1 text-xs text-gray-500">
                      <span className="animate-pulse">●</span> Active
                    </span>
                  )}
                </div>
                <span className={`text-sm font-mono ${isComplete ? 'text-green-400' : colors.text}`}>
                  {isComplete ? <span className="text-green-400">✓</span> : `${Math.round(progress)}%`}
                </span>
              </div>
              
              {/* Progress Bar */}
              <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                <div 
                  className={`h-full rounded-full transition-all ${
                    prefersReducedMotion ? 'duration-0' : 'duration-100'
                  } ${isComplete ? 'bg-green-500' : colors.bg} ${
                    isActive && !prefersReducedMotion ? `shadow-lg ${colors.glow}` : ''
                  }`}
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Findings Panel */}
      {findings.length > 0 && (
        <div className="border-t border-white/10 p-4">
          <div className="text-xs font-medium text-gray-400 mb-3">VULNERABILITIES DETECTED</div>
          <div className="space-y-2">
            {findings.map((finding, index) => (
              <div 
                key={index}
                className={`flex items-center gap-3 p-2 rounded-lg bg-white/5 ${
                  prefersReducedMotion ? '' : 'animate-fadeIn'
                }`}
                style={{ animationDelay: prefersReducedMotion ? '0ms' : `${index * 100}ms` }}
              >
                <span className={`w-2 h-2 rounded-full ${severityColors[finding.severity]}`}></span>
                <span className="text-sm text-white">{finding.name}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${
                  finding.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  finding.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  'bg-yellow-500/20 text-yellow-400'
                }`}>
                  {finding.severity.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI Engine Badge */}
      <div className="absolute bottom-4 right-4 flex items-center gap-2 px-3 py-1.5 rounded-full bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20">
        <span className="text-xs">🧠</span>
        <span className="text-xs text-cyan-400 font-medium">JARWIS AI</span>
      </div>
    </div>
  );
};

export default InteractiveScanPreview;
