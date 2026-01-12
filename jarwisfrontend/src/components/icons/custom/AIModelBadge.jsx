// AI Model Badge Component - Suru 1.1 & Savi 2.1 Thinking by BKD Labs
import { motion } from 'framer-motion';
import { Brain, Sparkles, Cpu, Zap } from 'lucide-react';

// AI Model configurations
const AI_MODELS = {
  suru: {
    name: 'Suru 1.1',
    description: 'Fast Analysis Engine',
    icon: Zap,
    color: 'cyan',
    gradient: 'from-cyan-500 to-blue-500',
    bgGradient: 'from-cyan-500/20 to-blue-500/20',
    borderColor: 'border-cyan-500/30',
    textColor: 'text-cyan-400',
  },
  savi: {
    name: 'Savi 2.1',
    subtitle: 'Thinking',
    description: 'Deep Reasoning Engine',
    icon: Brain,
    color: 'violet',
    gradient: 'from-violet-500 to-purple-500',
    bgGradient: 'from-violet-500/20 to-purple-500/20',
    borderColor: 'border-violet-500/30',
    textColor: 'text-violet-400',
  },
};

// Individual AI Model Badge
export const AIModelBadge = ({ 
  model = 'suru', 
  size = 'md', 
  showDescription = false,
  animated = true,
  className = '' 
}) => {
  const config = AI_MODELS[model] || AI_MODELS.suru;
  const IconComponent = config.icon;

  const sizes = {
    sm: {
      container: 'px-2.5 py-1 gap-1.5',
      icon: 'w-3.5 h-3.5',
      text: 'text-xs',
      subtitle: 'text-[10px]',
    },
    md: {
      container: 'px-3 py-1.5 gap-2',
      icon: 'w-4 h-4',
      text: 'text-sm',
      subtitle: 'text-xs',
    },
    lg: {
      container: 'px-4 py-2 gap-2.5',
      icon: 'w-5 h-5',
      text: 'text-base',
      subtitle: 'text-sm',
    },
  };

  const s = sizes[size] || sizes.md;

  const content = (
    <span className={`
      inline-flex items-center ${s.container}
      bg-gradient-to-r ${config.bgGradient}
      border ${config.borderColor} rounded-full
      ${className}
    `}>
      <IconComponent className={`${s.icon} ${config.textColor}`} />
      <span className="flex flex-col leading-none">
        <span className={`${s.text} font-semibold ${config.textColor}`}>
          {config.name}
        </span>
        {config.subtitle && (
          <span className={`${s.subtitle} text-white/60`}>
            {config.subtitle}
          </span>
        )}
      </span>
    </span>
  );

  if (animated) {
    return (
      <motion.span
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.98 }}
        className="inline-flex"
      >
        {content}
      </motion.span>
    );
  }

  return content;
};

// AI Models Section Component
export const AIModelsSection = ({ className = '' }) => {
  return (
    <div className={`flex flex-col items-center gap-4 ${className}`}>
      <p className="text-sm text-gray-400 uppercase tracking-wider">
        Powered by BKD Labs AI
      </p>
      <div className="flex flex-wrap items-center justify-center gap-3">
        <AIModelBadge model="suru" size="md" />
        <span className="text-gray-600">+</span>
        <AIModelBadge model="savi" size="md" />
      </div>
    </div>
  );
};

// AI Model Card Component (for features section)
export const AIModelCard = ({ model = 'suru', className = '' }) => {
  const config = AI_MODELS[model] || AI_MODELS.suru;
  const IconComponent = config.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      whileHover={{ y: -4, scale: 1.02 }}
      className={`
        relative p-6 rounded-2xl overflow-hidden
        bg-gradient-to-br ${config.bgGradient}
        border ${config.borderColor}
        ${className}
      `}
    >
      {/* Glow effect */}
      <div className={`
        absolute inset-0 opacity-30 blur-2xl
        bg-gradient-to-br ${config.gradient}
      `} />
      
      <div className="relative z-10">
        <div className={`
          w-12 h-12 rounded-xl mb-4
          bg-gradient-to-br ${config.gradient}
          flex items-center justify-center
        `}>
          <IconComponent className="w-6 h-6 text-white" />
        </div>
        
        <h3 className="text-xl font-bold text-white mb-1">
          {config.name}
          {config.subtitle && (
            <span className="ml-2 text-sm font-normal text-white/60">
              {config.subtitle}
            </span>
          )}
        </h3>
        
        <p className="text-gray-400">
          {config.description}
        </p>
        
        <div className="mt-4 flex items-center gap-2">
          <span className="px-2 py-1 text-xs rounded-full bg-white/10 text-white/80">
            BKD Labs
          </span>
          <span className="px-2 py-1 text-xs rounded-full bg-white/10 text-white/80">
            In-house AI
          </span>
        </div>
      </div>
    </motion.div>
  );
};

// Inline AI mention component
export const PoweredByAI = ({ size = 'sm', className = '' }) => {
  const sizes = {
    xs: 'text-[10px] gap-1',
    sm: 'text-xs gap-1.5',
    md: 'text-sm gap-2',
  };

  return (
    <span className={`inline-flex items-center ${sizes[size]} text-gray-500 ${className}`}>
      <Sparkles className={size === 'xs' ? 'w-3 h-3' : 'w-4 h-4'} />
      <span>Powered by <span className="text-cyan-400">Suru</span> & <span className="text-violet-400">Savi</span></span>
    </span>
  );
};

export default AIModelBadge;
