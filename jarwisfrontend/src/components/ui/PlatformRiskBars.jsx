// Platform risk breakdown visualization (horizontal bars)
import React from 'react';
import EnterpriseCard from './EnterpriseCard';
import SecurityScoreBar from './SecurityScoreBar';

const PlatformRiskBars = ({ data, onPlatformClick }) => {
  if (!data || !data.platforms) {
    return (
      <EnterpriseCard>
        <div className="text-center py-8 text-gray-400">
          No platform data available
        </div>
      </EnterpriseCard>
    );
  }

  const { platforms } = data;

  const platformConfig = {
    web: { label: 'Web Security', icon: '🌐', color: 'text-blue-400' },
    mobile: { label: 'Mobile Security', icon: '📱', color: 'text-purple-400' },
    cloud: { label: 'Cloud Security', icon: '☁️', color: 'text-cyan-400' },
    network: { label: 'Network Security', icon: '🔌', color: 'text-green-400' }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Never';
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  return (
    <EnterpriseCard>
      <h3 className="text-lg font-semibold text-gray-200 mb-4">Platform Risk Overview</h3>
      
      <div className="space-y-6">
        {platforms.map(platform => {
          const config = platformConfig[platform.name] || { 
            label: platform.name, 
            icon: '📊', 
            color: 'text-gray-400' 
          };

          return (
            <div 
              key={platform.name}
              className="group cursor-pointer"
              onClick={() => onPlatformClick && onPlatformClick(platform.name)}
            >
              {/* Platform header */}
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{config.icon}</span>
                  <div>
                    <h4 className={`text-sm font-semibold ${config.color} group-hover:underline`}>
                      {config.label}
                    </h4>
                    <p className="text-xs text-gray-500">
                      {platform.scan_count} scan{platform.scan_count !== 1 ? 's' : ''} • 
                      Last: {formatDate(platform.last_scan)}
                    </p>
                  </div>
                </div>

                {/* Stats badges */}
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-xs text-gray-500">Vulnerabilities</div>
                    <div className="text-sm font-semibold text-gray-200">
                      {platform.vulnerability_count}
                    </div>
                  </div>
                  {platform.critical_count > 0 && (
                    <div className="px-2 py-1 bg-red-950 border border-red-800 rounded text-xs font-semibold text-red-400">
                      {platform.critical_count} Critical
                    </div>
                  )}
                </div>
              </div>

              {/* Risk score bar (inverted - higher is worse) */}
              <SecurityScoreBar
                score={platform.risk_score}
                label=""
                showLabel={false}
                showScore={false}
                height="h-3"
              />
              <div className="flex justify-between items-center mt-1">
                <span className="text-xs text-gray-500">
                  {platform.risk_score === 0 ? 'No risks detected' : 'Risk Score'}
                </span>
                <span className={`text-xs font-semibold ${
                  platform.risk_score < 30 ? 'text-green-400' :
                  platform.risk_score < 60 ? 'text-yellow-400' :
                  platform.risk_score < 80 ? 'text-orange-400' :
                  'text-red-400'
                }`}>
                  {platform.risk_score > 0 ? `${platform.risk_score}/100` : 'Secure'}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {platforms.length === 0 && (
        <div className="text-center py-8">
          <p className="text-gray-400 mb-2">No scans performed yet</p>
          <p className="text-sm text-gray-500">Start a scan to see platform risk breakdown</p>
        </div>
      )}
    </EnterpriseCard>
  );
};

export default PlatformRiskBars;
