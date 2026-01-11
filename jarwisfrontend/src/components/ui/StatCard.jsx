// Stat card component for displaying key metrics
import React from 'react';
import EnterpriseCard from './EnterpriseCard';

const StatCard = ({
  title,
  value,
  icon,
  trend,
  trendValue,
  variant = 'default',
  subtitle,
  onClick,
  isDarkMode = true  // Default to dark mode for backward compatibility
}) => {
  const getTrendColor = () => {
    if (!trend) return isDarkMode ? 'text-gray-400' : 'text-gray-500';
    return trend === 'up' ? 'text-green-400' : trend === 'down' ? 'text-red-400' : (isDarkMode ? 'text-gray-400' : 'text-gray-500');
  };

  const getTrendIcon = () => {
    if (!trend) return null;
    return trend === 'up' ? '↑' : trend === 'down' ? '↓' : '→';
  };

  return (
    <EnterpriseCard variant={variant} onClick={onClick} hover={!!onClick} isDarkMode={isDarkMode}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className={`text-sm font-medium mb-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>{title}</p>
          <p className={`text-3xl font-bold mb-1 ${isDarkMode ? 'text-gray-100' : 'text-gray-900'}`}>{value}</p>
          {subtitle && (
            <p className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>{subtitle}</p>
          )}
          {trend && trendValue && (
            <div className={`flex items-center gap-1 text-sm ${getTrendColor()} mt-2`}>
              <span>{getTrendIcon()}</span>
              <span>{trendValue}</span>
            </div>
          )}
        </div>
        {icon && (
          <div className="text-3xl opacity-50">
            {icon}
          </div>
        )}
      </div>
    </EnterpriseCard>
  );
};

export default StatCard;
