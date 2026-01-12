// Icon wrapper component for consistent sizing and styling
import { forwardRef } from 'react';
import * as LucideIcons from 'lucide-react';

// Standard icon sizes
export const iconSizes = {
  xs: 'w-3 h-3',
  sm: 'w-4 h-4',
  md: 'w-5 h-5',
  lg: 'w-6 h-6',
  xl: 'w-8 h-8',
  '2xl': 'w-10 h-10',
  '3xl': 'w-12 h-12',
};

// Icon component that wraps Lucide icons with consistent styling
export const Icon = forwardRef(({ 
  name, 
  size = 'md', 
  className = '',
  color,
  strokeWidth = 2,
  ...props 
}, ref) => {
  const LucideIcon = LucideIcons[name];
  
  if (!LucideIcon) {
    console.warn(`Icon "${name}" not found in lucide-react`);
    return null;
  }
  
  const sizeClass = iconSizes[size] || iconSizes.md;
  const colorClass = color ? `text-${color}` : '';
  
  return (
    <LucideIcon 
      ref={ref}
      className={`${sizeClass} ${colorClass} ${className}`.trim()}
      strokeWidth={strokeWidth}
      {...props}
    />
  );
});

Icon.displayName = 'Icon';

// Animated icon wrapper with hover effects
export const AnimatedIcon = forwardRef(({
  name,
  size = 'md',
  className = '',
  hoverScale = 1.1,
  ...props
}, ref) => {
  return (
    <span 
      ref={ref}
      className={`inline-flex transition-transform duration-200 hover:scale-[${hoverScale}] ${className}`}
    >
      <Icon name={name} size={size} {...props} />
    </span>
  );
});

AnimatedIcon.displayName = 'AnimatedIcon';

// Icon with background container
export const IconBox = ({
  name,
  size = 'md',
  variant = 'default',
  className = '',
  iconClassName = '',
  ...props
}) => {
  const variants = {
    default: 'bg-white/5 border border-white/10',
    cyan: 'bg-cyan-500/20 border border-cyan-500/30 text-cyan-400',
    blue: 'bg-blue-500/20 border border-blue-500/30 text-blue-400',
    violet: 'bg-violet-500/20 border border-violet-500/30 text-violet-400',
    emerald: 'bg-emerald-500/20 border border-emerald-500/30 text-emerald-400',
    amber: 'bg-amber-500/20 border border-amber-500/30 text-amber-400',
    red: 'bg-red-500/20 border border-red-500/30 text-red-400',
    gradient: 'bg-gradient-to-br from-cyan-500/20 to-violet-500/20 border border-white/10',
  };

  const boxSizes = {
    xs: 'w-6 h-6 rounded',
    sm: 'w-8 h-8 rounded-lg',
    md: 'w-10 h-10 rounded-lg',
    lg: 'w-12 h-12 rounded-xl',
    xl: 'w-14 h-14 rounded-xl',
    '2xl': 'w-16 h-16 rounded-2xl',
  };

  return (
    <div 
      className={`
        ${boxSizes[size]} ${variants[variant]}
        flex items-center justify-center
        transition-all duration-300
        ${className}
      `}
    >
      <Icon name={name} size={size} className={iconClassName} {...props} />
    </div>
  );
};

export default Icon;
