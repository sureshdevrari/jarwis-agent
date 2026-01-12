// Jarwis Logo as SVG React Component
export const JarwisLogo = ({ 
  className = '', 
  size = 40,
  variant = 'full', // 'full', 'icon', 'text'
  ...props 
}) => {
  if (variant === 'icon') {
    return (
      <svg 
        width={size} 
        height={size} 
        viewBox="0 0 40 40" 
        fill="none" 
        className={className}
        {...props}
      >
        <defs>
          <linearGradient id="jarwis-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#06b6d4" />
            <stop offset="50%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
        <circle cx="20" cy="20" r="18" stroke="url(#jarwis-gradient)" strokeWidth="2" fill="none" />
        <path 
          d="M12 20C12 15.5817 15.5817 12 20 12C24.4183 12 28 15.5817 28 20C28 24.4183 24.4183 28 20 28" 
          stroke="url(#jarwis-gradient)" 
          strokeWidth="2" 
          strokeLinecap="round"
        />
        <circle cx="20" cy="20" r="4" fill="url(#jarwis-gradient)" />
      </svg>
    );
  }

  return (
    <svg 
      width={size * 3} 
      height={size} 
      viewBox="0 0 120 40" 
      fill="none" 
      className={className}
      {...props}
    >
      <defs>
        <linearGradient id="jarwis-text-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#06b6d4" />
          <stop offset="100%" stopColor="#8b5cf6" />
        </linearGradient>
      </defs>
      {/* Icon */}
      <circle cx="20" cy="20" r="16" stroke="url(#jarwis-text-gradient)" strokeWidth="2" fill="none" />
      <circle cx="20" cy="20" r="4" fill="url(#jarwis-text-gradient)" />
      {/* Text */}
      <text 
        x="44" 
        y="26" 
        fill="url(#jarwis-text-gradient)" 
        fontFamily="system-ui, -apple-system, sans-serif" 
        fontSize="18" 
        fontWeight="700"
      >
        JARWIS
      </text>
    </svg>
  );
};

export default JarwisLogo;
