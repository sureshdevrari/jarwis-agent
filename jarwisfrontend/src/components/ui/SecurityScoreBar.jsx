// Security score horizontal progress bar with color-coded risk levels
import React from 'react';

const SecurityScoreBar = ({ 
  score = 0, 
  label = '', 
  showDelta = false, 
  delta = 0,
  height = 'h-4',
  showLabel = true,
  showScore = true
}) => {
  // Determine color based on score (green → yellow → orange → red)
  const getColorClass = (score) => {
    if (score >= 90) return 'bg-green-500';
    if (score >= 80) return 'bg-lime-500';
    if (score >= 70) return 'bg-yellow-500';
    if (score >= 60) return 'bg-orange-500';
    return 'bg-red-500';
  };

  const getGradeClass = (score) => {
    if (score >= 90) return 'text-green-400';
    if (score >= 80) return 'text-lime-400';
    if (score >= 70) return 'text-yellow-400';
    if (score >= 60) return 'text-orange-400';
    return 'text-red-400';
  };

  const colorClass = getColorClass(score);
  const gradeClass = getGradeClass(score);

  const deltaColor = delta > 0 ? 'text-green-400' : delta < 0 ? 'text-red-400' : 'text-gray-400';
  const deltaIcon = delta > 0 ? '↑' : delta < 0 ? '↓' : '→';

  return (
    <div className="w-full">
      {/* Label and Score */}
      {(showLabel || showScore) && (
        <div className="flex justify-between items-center mb-2">
          {showLabel && <span className="text-sm font-medium text-gray-300">{label}</span>}
          <div className="flex items-center gap-2">
            {showScore && (
              <span className={`text-lg font-bold ${gradeClass}`}>{score}/100</span>
            )}
            {showDelta && delta !== 0 && (
              <span className={`text-sm ${deltaColor}`}>
                {deltaIcon} {Math.abs(delta)}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Progress Bar */}
      <div className={`w-full bg-gray-700 rounded-full overflow-hidden ${height}`}>
        <div
          className={`${height} ${colorClass} transition-all duration-500 ease-out flex items-center justify-end pr-2`}
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
        >
          {score > 10 && (
            <span className="text-xs font-semibold text-white opacity-90">
              {Math.round(score)}%
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityScoreBar;
