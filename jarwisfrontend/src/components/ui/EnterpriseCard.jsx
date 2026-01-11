// Enterprise-style card component (minimal, flat design)
import React from 'react';

const EnterpriseCard = ({ 
  children, 
  className = '', 
  noPadding = false,
  variant = 'default',
  onClick,
  hover = false,
  isDarkMode = true  // Default to dark mode for backward compatibility
}) => {
  const darkVariants = {
    default: 'bg-gray-800 border-gray-700',
    elevated: 'bg-gray-800 border-gray-700 shadow-lg',
    critical: 'bg-red-950 border-red-800',
    warning: 'bg-orange-950 border-orange-800',
    success: 'bg-green-950 border-green-800',
    info: 'bg-blue-950 border-blue-800'
  };

  const lightVariants = {
    default: 'bg-white border-gray-200',
    elevated: 'bg-white border-gray-200 shadow-lg',
    critical: 'bg-red-50 border-red-200',
    warning: 'bg-orange-50 border-orange-200',
    success: 'bg-green-50 border-green-200',
    info: 'bg-blue-50 border-blue-200'
  };

  const variants = isDarkMode ? darkVariants : lightVariants;

  const baseStyles = 'border rounded-lg transition-all duration-200';
  const paddingStyles = noPadding ? '' : 'p-6';
  const interactiveStyles = onClick || hover 
    ? isDarkMode 
      ? 'cursor-pointer hover:border-gray-600 hover:shadow-md' 
      : 'cursor-pointer hover:border-gray-300 hover:shadow-md'
    : '';
  const variantStyles = variants[variant] || variants.default;

  return (
    <div
      className={`${baseStyles} ${paddingStyles} ${variantStyles} ${interactiveStyles} ${className}`}
      onClick={onClick}
    >
      {children}
    </div>
  );
};

export default EnterpriseCard;
