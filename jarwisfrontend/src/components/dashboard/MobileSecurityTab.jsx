// Mobile Security Tab - APK/IPA analysis dashboard
import React, { useState, useEffect } from 'react';
import { mobileScanAPI } from '../../services/api';
import EnterpriseCard from '../ui/EnterpriseCard';
import StatCard from '../ui/StatCard';

const MobileSecurityTab = () => {
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState([]);

  useEffect(() => {
    fetchMobileScans();
  }, []);

  const fetchMobileScans = async () => {
    try {
      setLoading(true);
      const response = await mobileScanAPI.listScans();
      
      if (response.success && response.data) {
        setScans(response.data.scans || []);
      }
    } catch (error) {
      console.error('Error fetching mobile scans:', error);
    } finally {
      setLoading(false);
    }
  };

  // Calculate category stats
  const categoryStats = {
    'Insecure Storage': 0,
    'Certificate Pinning': 0,
    'Root Detection': 0,
    'Code Obfuscation': 0,
    'API Security': 0,
    'Data Leakage': 0
  };

  scans.forEach(scan => {
    if (scan.findings) {
      scan.findings.forEach(finding => {
        const category = finding.category || 'Other';
        if (categoryStats[category] !== undefined) {
          categoryStats[category]++;
        }
      });
    }
  });

  const totalFindings = Object.values(categoryStats).reduce((sum, count) => sum + count, 0);
  const staticScans = scans.filter(s => s.scan_mode === 'static').length;
  const dynamicScans = scans.filter(s => s.scan_mode === 'dynamic').length;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span>📱</span> Mobile Security Dashboard
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            {scans.length} total scans • {totalFindings} findings
          </p>
        </div>
      </div>

      {/* Summary Stats with Verification Badges */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={scans.length}
          icon="📱"
        />
        <StatCard
          title="Static Analysis"
          value={staticScans}
          icon="📄"
          subtitle={
            <span className="inline-flex items-center gap-1 mt-1">
              <span className="w-2 h-2 bg-blue-500 rounded-full"></span>
              <span className="text-xs">Static Verified</span>
            </span>
          }
        />
        <StatCard
          title="Dynamic Analysis"
          value={dynamicScans}
          icon="⚡"
          subtitle={
            <span className="inline-flex items-center gap-1 mt-1">
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              <span className="text-xs">Dynamic Verified</span>
            </span>
          }
        />
        <StatCard
          title="Total Findings"
          value={totalFindings}
          icon="🔍"
          variant={totalFindings > 10 ? 'warning' : 'default'}
        />
      </div>

      {/* Category Breakdown */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Security Category Breakdown</h3>
        
        {totalFindings === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No findings yet. Upload an APK or IPA file to start mobile security analysis.
          </div>
        ) : (
          <div className="space-y-3">
            {Object.entries(categoryStats).map(([category, count]) => {
              const percentage = totalFindings > 0 ? (count / totalFindings * 100) : 0;
              
              return (
                <div key={category}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-gray-300">{category}</span>
                    <span className="text-sm font-semibold text-gray-300">{count}</span>
                  </div>
                  
                  <div className="h-6 bg-gray-700 rounded-lg overflow-hidden">
                    <div
                      className="h-full bg-purple-500 flex items-center justify-end pr-2 transition-all duration-500"
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
        )}
      </EnterpriseCard>

      {/* Recent Scans with Verification Badges */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Recent Mobile Scans</h3>
        
        {scans.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No mobile scans yet. Upload an APK or IPA file to begin.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">App Name</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Type</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Mode</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Verification</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Findings</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Date</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Status</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 10).map((scan, idx) => {
                  const isStatic = scan.scan_mode === 'static';
                  const isDynamic = scan.scan_mode === 'dynamic';
                  
                  return (
                    <tr key={idx} className="border-b border-gray-700 hover:bg-gray-800">
                      <td className="p-3 text-sm text-gray-200">{scan.app_name || 'Unknown'}</td>
                      <td className="p-3">
                        <span className="text-xs px-2 py-1 bg-gray-700 text-gray-300 rounded">
                          {scan.file_type || 'APK'}
                        </span>
                      </td>
                      <td className="p-3 text-sm text-gray-400 capitalize">{scan.scan_mode || 'static'}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          {isStatic && (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-blue-950 border border-blue-800 rounded text-xs text-blue-400">
                              <span className="w-1.5 h-1.5 bg-blue-400 rounded-full"></span>
                              Static Verified
                            </span>
                          )}
                          {isDynamic && (
                            <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-950 border border-green-800 rounded text-xs text-green-400">
                              <span className="w-1.5 h-1.5 bg-green-400 rounded-full"></span>
                              Dynamic Verified
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3 text-sm font-semibold text-gray-300">
                        {scan.findings?.length || 0}
                      </td>
                      <td className="p-3 text-sm text-gray-400">
                        {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : 'N/A'}
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          scan.status === 'completed' ? 'bg-green-950 text-green-400' :
                          scan.status === 'running' ? 'bg-blue-950 text-blue-400' :
                          scan.status === 'failed' ? 'bg-red-950 text-red-400' :
                          'bg-gray-700 text-gray-400'
                        }`}>
                          {scan.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </EnterpriseCard>
    </div>
  );
};

export default MobileSecurityTab;
