// Web Security Tab - OWASP Top 10 focused dashboard
import React, { useState, useEffect } from 'react';
import { scanAPI } from '../../services/api';
import EnterpriseCard from '../ui/EnterpriseCard';
import StatCard from '../ui/StatCard';

const WebSecurityTab = () => {
  const [loading, setLoading] = useState(true);
  const [scans, setScans] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [owaspStats, setOwaspStats] = useState({});

  useEffect(() => {
    fetchWebScans();
  }, []);

  const fetchWebScans = async () => {
    try {
      setLoading(true);
      // Fetch web scans
      const scansResponse = await scanAPI.listScans({ 
        type: 'web',
        limit: 50 
      });
      
      if (scansResponse.success && scansResponse.data) {
        const webScans = scansResponse.data.scans || [];
        setScans(webScans);

        // Aggregate vulnerabilities from all web scans
        const allVulns = [];
        for (const scan of webScans) {
          if (scan.status === 'completed') {
            try {
              const findingsResponse = await scanAPI.getScanFindings(scan.id);
              if (findingsResponse.success && findingsResponse.data) {
                const findings = findingsResponse.data.vulnerabilities || findingsResponse.data.findings || [];
                allVulns.push(...findings);
              }
            } catch (err) {
              console.error(`Error fetching findings for scan ${scan.id}:`, err);
            }
          }
        }
        
        setVulnerabilities(allVulns);
        calculateOwaspStats(allVulns);
      }
    } catch (error) {
      console.error('Error fetching web scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const calculateOwaspStats = (vulns) => {
    // Map vulnerabilities to OWASP Top 10 categories
    const owaspCategories = {
      'A01': { name: 'Broken Access Control', count: 0, severity: {} },
      'A02': { name: 'Cryptographic Failures', count: 0, severity: {} },
      'A03': { name: 'Injection', count: 0, severity: {} },
      'A04': { name: 'Insecure Design', count: 0, severity: {} },
      'A05': { name: 'Security Misconfiguration', count: 0, severity: {} },
      'A06': { name: 'Vulnerable Components', count: 0, severity: {} },
      'A07': { name: 'Authentication Failures', count: 0, severity: {} },
      'A08': { name: 'Data Integrity Failures', count: 0, severity: {} },
      'A09': { name: 'Logging Failures', count: 0, severity: {} },
      'A10': { name: 'SSRF', count: 0, severity: {} }
    };

    vulns.forEach(vuln => {
      const category = vuln.category || vuln.owasp_category || 'A05'; // Default to misconfiguration
      if (owaspCategories[category]) {
        owaspCategories[category].count++;
        const severity = vuln.severity?.toLowerCase() || 'low';
        owaspCategories[category].severity[severity] = 
          (owaspCategories[category].severity[severity] || 0) + 1;
      }
    });

    setOwaspStats(owaspCategories);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500',
      info: 'bg-gray-500'
    };
    return colors[severity] || 'bg-gray-500';
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.9) return 'text-green-400';
    if (confidence >= 0.7) return 'text-yellow-400';
    return 'text-orange-400';
  };

  // Calculate summary stats
  const totalVulns = vulnerabilities.length;
  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
  const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
  const avgConfidence = vulnerabilities.length > 0
    ? (vulnerabilities.reduce((sum, v) => sum + (v.confidence_score || 0.8), 0) / vulnerabilities.length)
    : 0;

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span>🌐</span> Web Security Dashboard
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            {scans.length} total scans • {totalVulns} findings
          </p>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Findings"
          value={totalVulns}
          icon="🔍"
        />
        <StatCard
          title="Critical"
          value={criticalCount}
          icon="🔴"
          variant={criticalCount > 0 ? 'critical' : 'default'}
        />
        <StatCard
          title="High"
          value={highCount}
          icon="🟠"
          variant={highCount > 0 ? 'warning' : 'default'}
        />
        <StatCard
          title="Medium"
          value={mediumCount}
          icon="🟡"
        />
        <StatCard
          title="Avg Confidence"
          value={`${Math.round(avgConfidence * 100)}%`}
          icon="📊"
          subtitle="Jarwis USP"
        />
      </div>

      {/* OWASP Top 10 Bar Chart */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">OWASP Top 10 Distribution</h3>
        
        {totalVulns === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No vulnerabilities found. Run a web scan to see OWASP mapping.
          </div>
        ) : (
          <div className="space-y-3">
            {Object.entries(owaspStats).map(([code, data]) => {
              const percentage = totalVulns > 0 ? (data.count / totalVulns * 100) : 0;
              const hasCritical = data.severity.critical > 0;
              const hasHigh = data.severity.high > 0;
              
              return (
                <div key={code}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-mono font-semibold text-gray-300">{code}</span>
                      <span className="text-sm text-gray-400">{data.name}</span>
                      {hasCritical && (
                        <span className="px-2 py-0.5 bg-red-950 border border-red-800 rounded text-xs text-red-400">
                          {data.severity.critical} Critical
                        </span>
                      )}
                      {hasHigh && (
                        <span className="px-2 py-0.5 bg-orange-950 border border-orange-800 rounded text-xs text-orange-400">
                          {data.severity.high} High
                        </span>
                      )}
                    </div>
                    <span className="text-sm font-semibold text-gray-300">{data.count}</span>
                  </div>
                  
                  <div className="h-8 bg-gray-700 rounded-lg overflow-hidden flex">
                    {/* Severity breakdown within bar */}
                    {data.severity.critical > 0 && (
                      <div
                        className="bg-red-500 flex items-center justify-center text-xs text-white font-semibold"
                        style={{ width: `${(data.severity.critical / data.count) * percentage}%` }}
                        title={`${data.severity.critical} Critical`}
                      >
                        {data.severity.critical > 0 && data.severity.critical}
                      </div>
                    )}
                    {data.severity.high > 0 && (
                      <div
                        className="bg-orange-500 flex items-center justify-center text-xs text-white font-semibold"
                        style={{ width: `${(data.severity.high / data.count) * percentage}%` }}
                        title={`${data.severity.high} High`}
                      >
                        {data.severity.high > 0 && data.severity.high}
                      </div>
                    )}
                    {data.severity.medium > 0 && (
                      <div
                        className="bg-yellow-500 flex items-center justify-center text-xs text-white font-semibold"
                        style={{ width: `${(data.severity.medium / data.count) * percentage}%` }}
                        title={`${data.severity.medium} Medium`}
                      >
                        {data.severity.medium > 0 && data.severity.medium}
                      </div>
                    )}
                    {data.severity.low > 0 && (
                      <div
                        className="bg-blue-500 flex items-center justify-center text-xs text-white font-semibold"
                        style={{ width: `${(data.severity.low / data.count) * percentage}%` }}
                        title={`${data.severity.low} Low`}
                      >
                        {data.severity.low > 0 && data.severity.low}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </EnterpriseCard>

      {/* Recent Vulnerabilities with Confidence Scores */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">
          Recent Findings with Confidence Scores
        </h3>
        
        {vulnerabilities.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No findings yet. Start a web scan to discover vulnerabilities.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Severity</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Title</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">OWASP</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">Confidence</th>
                  <th className="text-left p-3 text-sm font-semibold text-gray-300">URL</th>
                </tr>
              </thead>
              <tbody>
                {vulnerabilities.slice(0, 10).map((vuln, idx) => {
                  const confidence = vuln.confidence_score || 0.8;
                  return (
                    <tr key={idx} className="border-b border-gray-700 hover:bg-gray-800">
                      <td className="p-3">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          vuln.severity === 'critical' ? 'bg-red-950 text-red-400' :
                          vuln.severity === 'high' ? 'bg-orange-950 text-orange-400' :
                          vuln.severity === 'medium' ? 'bg-yellow-950 text-yellow-400' :
                          'bg-blue-950 text-blue-400'
                        }`}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td className="p-3 text-sm text-gray-200">{vuln.title}</td>
                      <td className="p-3 text-sm text-gray-400 font-mono">
                        {vuln.category || vuln.owasp_category || 'N/A'}
                      </td>
                      <td className="p-3">
                        <span className={`text-sm font-semibold ${getConfidenceColor(confidence)}`}>
                          {Math.round(confidence * 100)}%
                        </span>
                      </td>
                      <td className="p-3 text-sm text-gray-400 truncate max-w-xs">
                        {vuln.url || 'N/A'}
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

export default WebSecurityTab;
