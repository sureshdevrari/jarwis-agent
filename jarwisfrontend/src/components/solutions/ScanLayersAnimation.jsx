// ScanLayersAnimation.jsx
// Animated visualization of multi-layer scanning process

import '../../styles/scan-animations.css';

const ScanLayersAnimation = ({ scanType = 'web', layers = [] }) => {
  const defaultLayers = {
    web: [
      { name: 'Reconnaissance', width: 95, description: 'Crawling & Discovery' },
      { name: 'Authentication', width: 88, description: 'Session Analysis' },
      { name: 'Injection Testing', width: 92, description: 'SQLi, XSS, SSTI' },
      { name: 'Access Control', width: 85, description: 'IDOR, Path Traversal' },
      { name: 'API Security', width: 90, description: 'REST, GraphQL, WebSocket' }
    ],
    mobile: [
      { name: 'Static Analysis', width: 94, description: 'Binary & Manifest' },
      { name: 'Permission Audit', width: 88, description: 'Dangerous Permissions' },
      { name: 'Dynamic Analysis', width: 91, description: 'Runtime Behavior' },
      { name: 'Network Traffic', width: 86, description: 'API Interception' },
      { name: 'Storage Analysis', width: 89, description: 'Data Protection' }
    ],
    network: [
      { name: 'Host Discovery', width: 96, description: 'Subnet Enumeration' },
      { name: 'Port Scanning', width: 93, description: 'Service Detection' },
      { name: 'Vulnerability Scan', width: 89, description: 'CVE Detection' },
      { name: 'Credential Testing', width: 84, description: 'Auth Bypass' },
      { name: 'Exploit Validation', width: 87, description: 'Risk Verification' }
    ],
    cloud: [
      { name: 'Asset Discovery', width: 97, description: 'Multi-Region Scan' },
      { name: 'CSPM Analysis', width: 92, description: '1000+ Rules' },
      { name: 'IAM Review', width: 88, description: 'Permission Analysis' },
      { name: 'Container Security', width: 90, description: 'Image Scanning' },
      { name: 'Runtime Protection', width: 85, description: 'Threat Detection' }
    ],
    sast: [
      { name: 'Repository Clone', width: 98, description: 'Secure Checkout' },
      { name: 'Secret Scanning', width: 95, description: 'Credential Detection' },
      { name: 'Dependency Audit', width: 91, description: 'SCA Analysis' },
      { name: 'Code Analysis', width: 88, description: 'Pattern Matching' },
      { name: 'Language Analysis', width: 86, description: 'Deep Inspection' }
    ]
  };

  const activeLayers = layers.length > 0 ? layers : defaultLayers[scanType];

  const colorClasses = {
    web: ['layer-1', 'layer-2', 'layer-3', 'layer-4', 'layer-5'],
    mobile: ['layer-2', 'layer-1', 'layer-2', 'layer-3', 'layer-4'],
    network: ['layer-3', 'layer-1', 'layer-3', 'layer-4', 'layer-5'],
    cloud: ['layer-4', 'layer-1', 'layer-4', 'layer-2', 'layer-3'],
    sast: ['layer-5', 'layer-1', 'layer-5', 'layer-2', 'layer-3']
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex h-3 w-3">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
        </div>
        <span className="text-sm font-medium text-gray-400">Multi-Layer Scanning in Progress</span>
      </div>

      <div className="scan-progress-layers">
        {activeLayers.map((layer, index) => (
          <div key={index} className="space-y-2">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-white">{layer.name}</span>
                <span className="text-xs text-gray-500">• {layer.description}</span>
              </div>
              <span className={`text-sm font-bold ${
                scanType === 'web' ? 'text-cyan-400' :
                scanType === 'mobile' ? 'text-purple-400' :
                scanType === 'network' ? 'text-green-400' :
                scanType === 'cloud' ? 'text-orange-400' :
                'text-red-400'
              }`}>{layer.width}%</span>
            </div>
            <div className="layer-bar">
              <div 
                className={`layer-bar-fill ${colorClasses[scanType][index % 5]}`}
                style={{ '--layer-width': `${layer.width}%` }}
              />
            </div>
          </div>
        ))}
      </div>

      <div className="mt-8 p-4 rounded-xl bg-white/5 border border-white/10">
        <div className="flex items-start gap-3">
          <div className={`p-2 rounded-lg ${
            scanType === 'web' ? 'bg-cyan-500/20 text-cyan-400' :
            scanType === 'mobile' ? 'bg-purple-500/20 text-purple-400' :
            scanType === 'network' ? 'bg-green-500/20 text-green-400' :
            scanType === 'cloud' ? 'bg-orange-500/20 text-orange-400' :
            'bg-red-500/20 text-red-400'
          }`}>
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-medium text-white">Powered by JARWIS AI Engine</p>
            <p className="text-xs text-gray-500 mt-1">
              Custom-built by BKD Labs • No external LLMs • Zero data leakage
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanLayersAnimation;
