// Risk heatmap table component (Platform × Severity matrix)
import React from 'react';
import EnterpriseCard from './EnterpriseCard';

const RiskHeatmap = ({ data, onCellClick }) => {
  if (!data || !data.matrix) {
    return (
      <EnterpriseCard>
        <div className="text-center py-8 text-gray-400">
          No vulnerability data available
        </div>
      </EnterpriseCard>
    );
  }

  const { matrix, totals } = data;

  // Severity column configuration
  const severityColumns = [
    { key: 'critical', label: 'Critical', color: 'text-red-400', bgHover: 'hover:bg-red-950' },
    { key: 'high', label: 'High', color: 'text-orange-400', bgHover: 'hover:bg-orange-950' },
    { key: 'medium', label: 'Medium', color: 'text-yellow-400', bgHover: 'hover:bg-yellow-950' },
    { key: 'low', label: 'Low', color: 'text-blue-400', bgHover: 'hover:bg-blue-950' }
  ];

  // Platform row configuration
  const platformConfig = {
    web: { label: 'Web Security', icon: '🌐' },
    mobile: { label: 'Mobile Security', icon: '📱' },
    cloud: { label: 'Cloud Security', icon: '☁️' },
    network: { label: 'Network Security', icon: '🔌' }
  };

  // Determine cell intensity based on count
  const getCellOpacity = (count, maxCount) => {
    if (count === 0) return 'opacity-30';
    if (count < maxCount * 0.3) return 'opacity-50';
    if (count < maxCount * 0.6) return 'opacity-75';
    return 'opacity-100';
  };

  // Find max count for normalization
  const maxCount = Math.max(...matrix.flatMap(row => 
    severityColumns.map(col => row[col.key] || 0)
  ), 1);

  const handleCellClick = (platform, severity, count) => {
    if (count > 0 && onCellClick) {
      onCellClick({ platform, severity, count });
    }
  };

  return (
    <EnterpriseCard noPadding>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-700">
              <th className="text-left p-4 text-sm font-semibold text-gray-300">
                Platform
              </th>
              {severityColumns.map(col => (
                <th key={col.key} className={`text-center p-4 text-sm font-semibold ${col.color}`}>
                  {col.label}
                </th>
              ))}
              <th className="text-center p-4 text-sm font-semibold text-gray-300">
                Total
              </th>
            </tr>
          </thead>
          <tbody>
            {matrix.map(row => {
              const config = platformConfig[row.platform] || { label: row.platform, icon: '📊' };
              return (
                <tr key={row.platform} className="border-b border-gray-700 last:border-0">
                  <td className="p-4">
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{config.icon}</span>
                      <span className="text-sm font-medium text-gray-200">{config.label}</span>
                    </div>
                  </td>
                  {severityColumns.map(col => {
                    const count = row[col.key] || 0;
                    const opacity = getCellOpacity(count, maxCount);
                    return (
                      <td
                        key={col.key}
                        className={`text-center p-4 ${count > 0 ? `cursor-pointer ${col.bgHover}` : ''} transition-colors`}
                        onClick={() => handleCellClick(row.platform, col.key, count)}
                      >
                        <div
                          className={`inline-flex items-center justify-center w-12 h-12 rounded-lg border ${
                            count > 0 ? `${col.color} border-current ${opacity}` : 'text-gray-600 border-gray-700'
                          } font-bold text-lg`}
                        >
                          {count}
                        </div>
                      </td>
                    );
                  })}
                  <td className="text-center p-4">
                    <span className="font-bold text-gray-200 text-lg">{row.total || 0}</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
          <tfoot>
            <tr className="bg-gray-750 border-t-2 border-gray-600">
              <td className="p-4 text-sm font-semibold text-gray-300">Total</td>
              {severityColumns.map(col => (
                <td key={col.key} className={`text-center p-4 font-bold ${col.color}`}>
                  {totals[col.key] || 0}
                </td>
              ))}
              <td className="text-center p-4 font-bold text-gray-200 text-lg">
                {totals.total || 0}
              </td>
            </tr>
          </tfoot>
        </table>
      </div>
    </EnterpriseCard>
  );
};

export default RiskHeatmap;
