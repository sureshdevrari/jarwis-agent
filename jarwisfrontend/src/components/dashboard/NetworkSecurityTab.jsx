// Network Security Tab - Port scanning and CVE analysis
import React, { useState, useEffect } from 'react';
import { networkScanAPI } from '../../services/api';
import { useTheme } from '../../context/ThemeContext';
import EnterpriseCard from '../ui/EnterpriseCard';
import StatCard from '../ui/StatCard';

const NetworkSecurityTab = () => {
  const { isDarkMode } = useTheme();
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchNetworkData();
  }, []);

  const fetchNetworkData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch dashboard summary from real API
      const summaryResponse = await networkScanAPI.getDashboardSummary();
      if (summaryResponse.success && summaryResponse.data) {
        setDashboardData(summaryResponse.data);
      }
      
      // Also fetch scans list
      const scansResponse = await networkScanAPI.listScans();
      if (scansResponse.scans) {
        setScans(scansResponse.scans);
      }
    } catch (err) {
      console.error('Error fetching network data:', err);
      setError('Failed to load network security data');
      // Set default empty state
      setDashboardData(null);
    } finally {
      setLoading(false);
    }
  };

  // Use real data from API or fallback to empty state
  const cveStats = dashboardData?.cve_stats || {
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0
  };

  // Transform cve_stats keys to Title Case for display
  const displayCveStats = {
    'Critical': cveStats.critical || 0,
    'High': cveStats.high || 0,
    'Medium': cveStats.medium || 0,
    'Low': cveStats.low || 0
  };

  const totalCVEs = dashboardData?.total_cves || Object.values(displayCveStats).reduce((sum, count) => sum + count, 0);
  const openPorts = dashboardData?.open_ports_count || 0;
  const vulnerableServices = dashboardData?.vulnerable_services_count || 0;

  // Use real port data from API or show empty state message
  const commonPorts = dashboardData?.open_ports || [];
  const hasRealData = dashboardData && dashboardData.scans_analyzed > 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-green-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className={`text-2xl font-bold flex items-center gap-2 ${isDarkMode ? 'text-gray-100' : 'text-gray-900'}`}>
            <span>🔌</span> Network Security Dashboard
          </h2>
          <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Infrastructure vulnerability assessment
          </p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Open Ports"
          value={openPorts}
          icon="🔓"
          isDarkMode={isDarkMode}
        />
        <StatCard
          title="Vulnerable Services"
          value={vulnerableServices}
          icon="⚠️"
          variant={vulnerableServices > 5 ? 'warning' : 'default'}
          isDarkMode={isDarkMode}
        />
        <StatCard
          title="Total CVEs"
          value={totalCVEs}
          icon="🔍"
          isDarkMode={isDarkMode}
        />
        <StatCard
          title="Critical CVEs"
          value={displayCveStats.Critical}
          icon="🔴"
          variant={displayCveStats.Critical > 0 ? 'critical' : 'default'}
          isDarkMode={isDarkMode}
        />
      </div>

      {/* No Data Message */}
      {!hasRealData && !loading && (
        <EnterpriseCard isDarkMode={isDarkMode}>
          <div className={`text-center py-8 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
            <div className="text-4xl mb-4">🔌</div>
            <h3 className={`text-lg font-semibold mb-2 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>
              No Network Scan Data Yet
            </h3>
            <p className="mb-4">Run a network scan to see vulnerability data and open ports.</p>
            <button
              onClick={() => window.location.href = '/dashboard/new-scan?type=network'}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              Start Network Scan
            </button>
          </div>
        </EnterpriseCard>
      )}

      {/* CVE Severity Distribution */}
      {hasRealData && (
      <EnterpriseCard isDarkMode={isDarkMode}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>CVE Severity Distribution</h3>
        
        <div className="space-y-3">
          {Object.entries(displayCveStats).map(([severity, count]) => {
            const percentage = totalCVEs > 0 ? (count / totalCVEs * 100) : 0;
            const getColor = (sev) => {
              if (sev === 'Critical') return 'bg-red-500';
              if (sev === 'High') return 'bg-orange-500';
              if (sev === 'Medium') return 'bg-yellow-500';
              return 'bg-blue-500';
            };
            
            return (
              <div key={severity}>
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>{severity} Severity</span>
                  <span className={`text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>{count} CVEs</span>
                </div>
                
                <div className={`h-6 rounded-lg overflow-hidden ${isDarkMode ? 'bg-gray-700' : 'bg-gray-200'}`}>
                  <div
                    className={`h-full ${getColor(severity)} flex items-center justify-end pr-2 transition-all duration-500`}
                    style={{ width: `${percentage}%` }}
                  >
                    {percentage > 10 && (
                      <span className="text-xs font-semibold text-white">
                        {Math.round(percentage)}%
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </EnterpriseCard>
      )}

      {/* Open Ports Table */}
      {hasRealData && commonPorts.length > 0 && (
      <EnterpriseCard isDarkMode={isDarkMode}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>Open Ports & Services</h3>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className={`border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
                <th className={`text-left p-3 text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Port</th>
                <th className={`text-left p-3 text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Host</th>
                <th className={`text-left p-3 text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Service</th>
                <th className={`text-left p-3 text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Status</th>
                <th className={`text-left p-3 text-sm font-semibold ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>Risk Level</th>
              </tr>
            </thead>
            <tbody>
              {commonPorts.map((port, idx) => (
                <tr key={idx} className={`border-b ${isDarkMode ? 'border-gray-700 hover:bg-gray-800' : 'border-gray-100 hover:bg-gray-50'}`}>
                  <td className="p-3">
                    <span className={`text-sm font-mono font-semibold ${isDarkMode ? 'text-gray-200' : 'text-gray-900'}`}>
                      {port.port}
                    </span>
                  </td>
                  <td className={`p-3 text-sm font-mono ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>{port.host || '-'}</td>
                  <td className={`p-3 text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>{port.service}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${isDarkMode ? 'bg-green-950 text-green-400' : 'bg-green-100 text-green-700'}`}>
                      {port.status}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      port.risk === 'high' 
                        ? (isDarkMode ? 'bg-red-950 text-red-400' : 'bg-red-100 text-red-700')
                        : port.risk === 'medium' 
                        ? (isDarkMode ? 'bg-yellow-950 text-yellow-400' : 'bg-yellow-100 text-yellow-700')
                        : (isDarkMode ? 'bg-blue-950 text-blue-400' : 'bg-blue-100 text-blue-700')
                    }`}>
                      {port.risk}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </EnterpriseCard>
      )}

      {/* Vulnerable Services List */}
      {hasRealData && dashboardData?.vulnerable_services?.length > 0 && (
      <EnterpriseCard isDarkMode={isDarkMode}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>Vulnerable Services Detected</h3>
        <div className="flex flex-wrap gap-2">
          {dashboardData.vulnerable_services.map((service, idx) => (
            <span key={idx} className={`px-3 py-1 rounded-full text-sm font-medium ${isDarkMode ? 'bg-red-950 text-red-400' : 'bg-red-100 text-red-700'}`}>
              {service}
            </span>
          ))}
        </div>
      </EnterpriseCard>
      )}

      {/* Quick Actions */}
      <div className="grid grid-cols-2 gap-4">
        <EnterpriseCard isDarkMode={isDarkMode} hover onClick={() => window.location.href = '/dashboard/new-scan?type=network'}>
          <div className="text-center py-4">
            <div className="text-3xl mb-2">🔍</div>
            <h4 className={`font-semibold mb-1 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>Quick Scan</h4>
            <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Fast port scan</p>
          </div>
        </EnterpriseCard>
        
        <EnterpriseCard isDarkMode={isDarkMode} hover onClick={() => window.location.href = '/dashboard/new-scan?type=network&mode=full'}>
          <div className="text-center py-4">
            <div className="text-3xl mb-2">🎯</div>
            <h4 className={`font-semibold mb-1 ${isDarkMode ? 'text-gray-200' : 'text-gray-800'}`}>Full Scan</h4>
            <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>Deep analysis with CVE detection</p>
          </div>
        </EnterpriseCard>
      </div>
    </div>
  );
};

export default NetworkSecurityTab;
