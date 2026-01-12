// ScrollProgress.jsx
// Scroll progress indicator bar that shows how far user has scrolled
// Inspired by Palo Alto's scroll-based visual feedback

import React from 'react';
import { motion, useScroll, useSpring, useTransform } from 'framer-motion';
import { useReducedMotion } from '../../hooks/useReducedMotion';

/**
 * Horizontal progress bar fixed to top of viewport.
 * Shows scroll progress as a growing bar.
 * 
 * @param {Object} props
 * @param {string} props.color - Bar color. Default: 'bg-gradient-to-r from-cyan-500 via-violet-500 to-rose-500'
 * @param {number} props.height - Bar height in pixels. Default: 3
 * @param {string} props.position - 'top' or 'bottom'. Default: 'top'
 * @param {boolean} props.glow - Add glow effect. Default: true
 */
export const ScrollProgressBar = ({ 
  color = 'bg-gradient-to-r from-cyan-500 via-violet-500 to-rose-500',
  height = 3,
  position = 'top',
  glow = true
}) => {
  const prefersReducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  
  const scaleX = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  if (prefersReducedMotion) {
    return null;
  }

  return (
    <motion.div
      className={`
        fixed left-0 right-0 z-50 origin-left
        ${color}
        ${position === 'top' ? 'top-0' : 'bottom-0'}
        ${glow ? 'shadow-lg shadow-cyan-500/50' : ''}
      `}
      style={{ 
        scaleX,
        height: `${height}px`,
        transformOrigin: '0%'
      }}
    />
  );
};

/**
 * Circular scroll progress indicator.
 * Can be placed in corners or as a fixed element.
 * 
 * @param {Object} props
 * @param {number} props.size - Circle size in pixels. Default: 48
 * @param {number} props.strokeWidth - Stroke width. Default: 3
 * @param {string} props.strokeColor - Stroke color. Default: '#06b6d4'
 * @param {string} props.bgColor - Background stroke color. Default: 'rgba(255,255,255,0.1)'
 * @param {boolean} props.showPercentage - Show percentage text. Default: false
 * @param {string} props.position - Fixed position: 'bottom-right', 'bottom-left', 'top-right', 'top-left', or 'none'. Default: 'bottom-right'
 */
export const ScrollProgressCircle = ({ 
  size = 48,
  strokeWidth = 3,
  strokeColor = '#06b6d4',
  bgColor = 'rgba(255,255,255,0.1)',
  showPercentage = false,
  position = 'bottom-right'
}) => {
  const prefersReducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  
  const pathLength = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  const percentage = useTransform(scrollYProgress, [0, 1], [0, 100]);

  const positionClasses = {
    'bottom-right': 'fixed bottom-6 right-6 z-50',
    'bottom-left': 'fixed bottom-6 left-6 z-50',
    'top-right': 'fixed top-20 right-6 z-50',
    'top-left': 'fixed top-20 left-6 z-50',
    'none': ''
  };

  if (prefersReducedMotion) {
    return null;
  }

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className={positionClasses[position]}>
      <motion.div
        className="relative"
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.5 }}
      >
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          className="transform -rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={bgColor}
            strokeWidth={strokeWidth}
          />
          
          {/* Progress circle */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            style={{
              pathLength,
              strokeDasharray: circumference,
              strokeDashoffset: 0
            }}
          />
        </svg>
        
        {/* Percentage text */}
        {showPercentage && (
          <motion.span 
            className="absolute inset-0 flex items-center justify-center text-xs font-medium text-cyan-400"
          >
            <motion.span>{percentage}</motion.span>%
          </motion.span>
        )}
      </motion.div>
    </div>
  );
};

/**
 * Scroll indicator arrow that bounces to encourage scrolling.
 * Fades out as user starts scrolling.
 */
export const ScrollIndicator = ({ 
  text = 'Scroll to explore',
  className = ''
}) => {
  const prefersReducedMotion = useReducedMotion();
  const { scrollY } = useScroll();
  
  const opacity = useTransform(scrollY, [0, 100], [1, 0]);

  if (prefersReducedMotion) {
    return null;
  }

  return (
    <motion.div 
      className={`flex flex-col items-center gap-2 ${className}`}
      style={{ opacity }}
    >
      <span className="text-sm text-gray-400">{text}</span>
      <motion.div
        animate={{ y: [0, 8, 0] }}
        transition={{ 
          duration: 1.5, 
          repeat: Infinity, 
          ease: 'easeInOut' 
        }}
      >
        <svg 
          className="w-6 h-6 text-cyan-400" 
          fill="none" 
          viewBox="0 0 24 24" 
          stroke="currentColor"
        >
          <path 
            strokeLinecap="round" 
            strokeLinejoin="round" 
            strokeWidth={2} 
            d="M19 14l-7 7m0 0l-7-7m7 7V3" 
          />
        </svg>
      </motion.div>
    </motion.div>
  );
};

export default ScrollProgressBar;
