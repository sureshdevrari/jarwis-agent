// Cloud Security Tab - AWS/Azure/GCP dashboard with compliance
import React, { useState, useEffect } from 'react';
import { cloudScanAPI } from '../../services/api';
import EnterpriseCard from '../ui/EnterpriseCard';
import StatCard from '../ui/StatCard';

const CloudSecurityTab = () => {
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState([]);

  useEffect(() => {
    fetchCloudScans();
  }, []);

  const fetchCloudScans = async () => {
    try {
      setLoading(true);
      const response = await cloudScanAPI.listScans();
      
      if (response.success && response.data) {
        setScans(response.data.scans || []);
      }
    } catch (error) {
      console.error('Error fetching cloud scans:', error);
    } finally {
      setLoading(false);
    }
  };

  // Calculate stats
  const totalFindings = scans.reduce((sum, scan) => sum + (scan.findings?.length || 0), 0);
  const awsScans = scans.filter(s => s.provider === 'aws').length;
  const azureScans = scans.filter(s => s.provider === 'azure').length;
  const gcpScans = scans.filter(s => s.provider === 'gcp').length;

  // Category stats
  const categoryStats = {
    'IAM Misconfiguration': 0,
    'Public Exposure': 0,
    'Encryption Issues': 0,
    'Network Security': 0,
    'Logging & Monitoring': 0,
    'Storage Security': 0
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

  // Mock compliance scores (would come from backend in real implementation)
  const complianceScores = {
    'CIS Benchmark': 78,
    'ISO 27001': 82,
    'SOC 2': 85,
    'NIST': 75
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span>☁️</span> Cloud Security Dashboard
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            {scans.length} total scans • {totalFindings} findings
          </p>
        </div>
      </div>

      {/* Summary Stats by Provider */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="AWS Scans"
          value={awsScans}
          icon="🟧"
        />
        <StatCard
          title="Azure Scans"
          value={azureScans}
          icon="🔵"
        />
        <StatCard
          title="GCP Scans"
          value={gcpScans}
          icon="🔴"
        />
        <StatCard
          title="Total Findings"
          value={totalFindings}
          icon="🔍"
          variant={totalFindings > 20 ? 'warning' : 'default'}
        />
      </div>

      {/* Compliance Scores */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Compliance Frameworks</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {Object.entries(complianceScores).map(([framework, score]) => {
            const getScoreColor = (score) => {
              if (score >= 90) return 'text-green-400';
              if (score >= 80) return 'text-lime-400';
              if (score >= 70) return 'text-yellow-400';
              return 'text-orange-400';
            };

            const getBarColor = (score) => {
              if (score >= 90) return 'bg-green-500';
              if (score >= 80) return 'bg-lime-500';
              if (score >= 70) return 'bg-yellow-500';
              return 'bg-orange-500';
            };

            return (
              <div key={framework}>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-gray-300">{framework}</span>
                  <span className={`text-lg font-bold ${getScoreColor(score)}`}>
                    {score}%
                  </span>
                </div>
                <div className="h-3 bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${getBarColor(score)} transition-all duration-500`}
                    style={{ width: `${score}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </EnterpriseCard>

      {/* Category Breakdown */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Security Category Breakdown</h3>
        
        {totalFindings === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No findings yet. Connect a cloud provider to start security analysis.
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
                      className="h-full bg-cyan-500 flex items-center justify-end pr-2 transition-all duration-500"
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

      {/* Resource Exposure Graph (Mock) */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Resource Exposure Overview</h3>
        
        {scans.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No cloud scans performed yet.
          </div>
        ) : (
          <div className="grid grid-cols-3 gap-4">
            <div className="text-center p-4 bg-gray-750 rounded-lg">
              <div className="text-3xl mb-2">🌐</div>
              <div className="text-2xl font-bold text-orange-400">
                {scans.filter(s => s.findings?.some(f => f.category?.includes('Public'))).length}
              </div>
              <div className="text-sm text-gray-400">Public Resources</div>
            </div>
            
            <div className="text-center p-4 bg-gray-750 rounded-lg">
              <div className="text-3xl mb-2">🔓</div>
              <div className="text-2xl font-bold text-red-400">
                {scans.filter(s => s.findings?.some(f => f.severity === 'critical')).length}
              </div>
              <div className="text-sm text-gray-400">Critical Issues</div>
            </div>
            
            <div className="text-center p-4 bg-gray-750 rounded-lg">
              <div className="text-3xl mb-2">🔐</div>
              <div className="text-2xl font-bold text-green-400">
                {scans.filter(s => s.status === 'completed' && (!s.findings || s.findings.length === 0)).length}
              </div>
              <div className="text-sm text-gray-400">Secure Resources</div>
            </div>
          </div>
        )}
      </EnterpriseCard>

      {/* Recent Scans */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Recent Cloud Scans</h3>
        
        {scans.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No cloud scans yet. Connect AWS, Azure, or GCP to begin.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Provider</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Account</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Region</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Findings</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Date</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Status</th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 10).map((scan, idx) => (
                  <tr key={idx} className="border-b border-gray-700 hover:bg-gray-800">
                    <td className="p-3">
                      <span className={`text-xs px-2 py-1 rounded font-semibold ${
                        scan.provider === 'aws' ? 'bg-orange-950 text-orange-400' :
                        scan.provider === 'azure' ? 'bg-blue-950 text-blue-400' :
                        scan.provider === 'gcp' ? 'bg-red-950 text-red-400' :
                        'bg-gray-700 text-gray-400'
                      }`}>
                        {scan.provider?.toUpperCase() || 'N/A'}
                      </span>
                    </td>
                    <td className="p-3 text-sm text-gray-200">{scan.account_id || 'N/A'}</td>
                    <td className="p-3 text-sm text-gray-400">{scan.region || 'global'}</td>
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </EnterpriseCard>
    </div>
  );
};

export default CloudSecurityTab;
