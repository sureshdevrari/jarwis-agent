// Premium Card Components with enhanced glassmorphism, gradients, and glow effects
import { motion } from 'framer-motion';
import { forwardRef } from 'react';

// Card variant configurations
const cardVariants = {
  default: {
    base: 'bg-white/[0.02] border-white/[0.08]',
    hover: 'hover:bg-white/[0.05] hover:border-white/[0.15]',
    shadow: '',
  },
  glass: {
    base: 'bg-gradient-to-br from-white/[0.08] to-white/[0.02] backdrop-blur-xl backdrop-saturate-150 border-white/[0.12]',
    hover: 'hover:from-white/[0.12] hover:to-white/[0.04] hover:border-white/[0.20]',
    shadow: 'shadow-xl shadow-black/5',
  },
  gradient: {
    base: 'bg-gradient-to-br from-cyan-500/10 via-blue-500/5 to-violet-500/10 border-cyan-500/20',
    hover: 'hover:from-cyan-500/15 hover:to-violet-500/15 hover:border-cyan-500/30',
    shadow: '',
  },
  glow: {
    base: 'bg-white/[0.03] border-white/[0.08]',
    hover: 'hover:bg-white/[0.06] hover:border-cyan-500/30 hover:shadow-glow-cyan',
    shadow: '',
  },
  glowViolet: {
    base: 'bg-white/[0.03] border-white/[0.08]',
    hover: 'hover:bg-white/[0.06] hover:border-violet-500/30 hover:shadow-glow-violet',
    shadow: '',
  },
  solid: {
    base: 'bg-gray-900/80 border-gray-800',
    hover: 'hover:bg-gray-900 hover:border-gray-700',
    shadow: 'shadow-lg shadow-black/20',
  },
  elevated: {
    base: 'bg-gradient-to-b from-gray-800/50 to-gray-900/50 border-gray-700/50',
    hover: 'hover:from-gray-800/70 hover:to-gray-900/70 hover:border-gray-600/50',
    shadow: 'shadow-2xl shadow-black/30',
  },
};

// Size configurations
const cardSizes = {
  sm: 'p-4 rounded-xl',
  md: 'p-6 rounded-2xl',
  lg: 'p-8 rounded-2xl',
  xl: 'p-10 rounded-3xl',
};

// Premium Card Component
export const PremiumCard = forwardRef(({
  variant = 'default',
  size = 'md',
  hover = true,
  animated = true,
  glowOnHover = false,
  gradientBorder = false,
  children,
  className = '',
  ...props
}, ref) => {
  const v = cardVariants[variant] || cardVariants.default;
  const s = cardSizes[size] || cardSizes.md;

  const baseClasses = `
    relative border transition-all duration-300
    ${s} ${v.base} ${v.shadow}
    ${hover ? v.hover : ''}
    ${glowOnHover ? 'hover:shadow-glow-cyan' : ''}
  `;

  const content = (
    <div ref={ref} className={`${baseClasses} ${className}`} {...props}>
      {children}
    </div>
  );

  if (gradientBorder) {
    return (
      <div className="relative p-[1px] rounded-2xl bg-gradient-to-r from-cyan-500/50 via-blue-500/50 to-violet-500/50">
        {content}
      </div>
    );
  }

  if (animated) {
    return (
      <motion.div
        whileHover={hover ? { y: -4, scale: 1.01 } : {}}
        transition={{ type: 'spring', stiffness: 300, damping: 20 }}
        className="h-full"
      >
        {content}
      </motion.div>
    );
  }

  return content;
});

PremiumCard.displayName = 'PremiumCard';

// Feature Card with icon slot
export const FeatureCard = ({
  icon: Icon,
  iconColor = 'text-cyan-400',
  iconBg = 'bg-cyan-500/20 border-cyan-500/30',
  title,
  description,
  variant = 'glass',
  className = '',
  children,
  ...props
}) => {
  return (
    <PremiumCard variant={variant} className={className} {...props}>
      {/* Icon */}
      {Icon && (
        <div className={`
          w-12 h-12 rounded-xl mb-4
          ${iconBg} border
          flex items-center justify-center
          transition-transform duration-300 group-hover:scale-110
        `}>
          <Icon className={`w-6 h-6 ${iconColor}`} />
        </div>
      )}

      {/* Title */}
      {title && (
        <h3 className="text-lg font-semibold text-white mb-2">
          {title}
        </h3>
      )}

      {/* Description */}
      {description && (
        <p className="text-gray-400 text-sm leading-relaxed">
          {description}
        </p>
      )}

      {children}
    </PremiumCard>
  );
};

// Stat Card with number display
export const StatCard = ({
  value,
  label,
  icon: Icon,
  trend,
  trendValue,
  variant = 'glass',
  color = 'cyan',
  className = '',
}) => {
  const colors = {
    cyan: { text: 'text-cyan-400', bg: 'bg-cyan-500/20', border: 'border-cyan-500/30' },
    blue: { text: 'text-blue-400', bg: 'bg-blue-500/20', border: 'border-blue-500/30' },
    violet: { text: 'text-violet-400', bg: 'bg-violet-500/20', border: 'border-violet-500/30' },
    emerald: { text: 'text-emerald-400', bg: 'bg-emerald-500/20', border: 'border-emerald-500/30' },
    amber: { text: 'text-amber-400', bg: 'bg-amber-500/20', border: 'border-amber-500/30' },
    red: { text: 'text-red-400', bg: 'bg-red-500/20', border: 'border-red-500/30' },
  };

  const c = colors[color] || colors.cyan;

  return (
    <PremiumCard variant={variant} className={className}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-400 mb-1">{label}</p>
          <p className={`text-3xl font-bold ${c.text}`}>{value}</p>
          {trend && (
            <p className={`text-sm mt-1 ${trend === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
              {trend === 'up' ? '↑' : '↓'} {trendValue}
            </p>
          )}
        </div>
        {Icon && (
          <div className={`${c.bg} ${c.border} border p-2 rounded-lg`}>
            <Icon className={`w-5 h-5 ${c.text}`} />
          </div>
        )}
      </div>
    </PremiumCard>
  );
};

// Animated Border Card (Linear.app style)
export const AnimatedBorderCard = ({
  children,
  className = '',
  borderColors = ['#06b6d4', '#3b82f6', '#8b5cf6'],
  duration = 4,
  ...props
}) => {
  return (
    <div className="relative p-[1px] rounded-2xl overflow-hidden">
      {/* Animated gradient border */}
      <motion.div
        className="absolute inset-0"
        animate={{
          background: [
            `linear-gradient(0deg, ${borderColors.join(', ')})`,
            `linear-gradient(90deg, ${borderColors.join(', ')})`,
            `linear-gradient(180deg, ${borderColors.join(', ')})`,
            `linear-gradient(270deg, ${borderColors.join(', ')})`,
            `linear-gradient(360deg, ${borderColors.join(', ')})`,
          ],
        }}
        transition={{
          duration,
          repeat: Infinity,
          ease: 'linear',
        }}
      />

      {/* Content */}
      <div className={`relative bg-gray-900 rounded-2xl ${className}`} {...props}>
        {children}
      </div>
    </div>
  );
};

// Glassmorphism Card with blur
export const GlassCard = forwardRef(({
  blur = 'xl',
  opacity = 0.08,
  children,
  className = '',
  ...props
}, ref) => {
  const blurLevels = {
    sm: 'backdrop-blur-sm',
    md: 'backdrop-blur-md',
    lg: 'backdrop-blur-lg',
    xl: 'backdrop-blur-xl',
    '2xl': 'backdrop-blur-2xl',
  };

  return (
    <motion.div
      ref={ref}
      whileHover={{ y: -2 }}
      className={`
        relative p-6 rounded-2xl
        bg-white/[${opacity}] ${blurLevels[blur]}
        border border-white/[0.12]
        shadow-xl shadow-black/5
        transition-all duration-300
        hover:bg-white/[${opacity + 0.04}] hover:border-white/[0.2]
        ${className}
      `}
      {...props}
    >
      {children}
    </motion.div>
  );
});

GlassCard.displayName = 'GlassCard';

export default PremiumCard;
