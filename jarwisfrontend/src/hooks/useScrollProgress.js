// useScrollProgress.js
// Hook for tracking scroll progress across the entire page or specific containers
// Useful for progress bars, scroll indicators, and scroll-based animations

import { useScroll, useSpring, useTransform } from 'framer-motion';
import { useReducedMotion } from './useReducedMotion';

/**
 * Tracks scroll progress of the entire page.
 * 
 * Usage:
 *   const { progress, progressSpring } = useScrollProgress();
 *   return <motion.div style={{ scaleX: progressSpring }} />
 * 
 * @param {Object} options
 * @param {boolean} options.smooth - Apply spring smoothing. Default: true
 * @returns {{ progress: MotionValue, progressSpring: MotionValue, progressPercent: MotionValue }}
 */
export const useScrollProgress = ({ smooth = true } = {}) => {
  const { scrollYProgress } = useScroll();
  
  const progressSpring = useSpring(scrollYProgress, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  const progressPercent = useTransform(scrollYProgress, [0, 1], [0, 100]);

  return {
    progress: scrollYProgress,
    progressSpring: smooth ? progressSpring : scrollYProgress,
    progressPercent
  };
};

/**
 * Tracks scroll progress within a specific container element.
 * 
 * @param {React.RefObject} containerRef - Reference to the container element
 * @returns {{ progress: MotionValue, isInView: boolean }}
 */
export const useContainerScrollProgress = (containerRef) => {
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start end', 'end start']
  });

  return { progress: scrollYProgress };
};

/**
 * Creates a scroll-based color transition.
 * 
 * @param {string[]} colors - Array of colors to transition through
 * @returns {{ color: MotionValue }}
 */
export const useScrollColor = (colors = ['#06b6d4', '#8b5cf6', '#f43f5e']) => {
  const { scrollYProgress } = useScroll();
  const prefersReducedMotion = useReducedMotion();

  const color = useTransform(
    scrollYProgress,
    colors.map((_, i) => i / (colors.length - 1)),
    colors
  );

  return { color: prefersReducedMotion ? colors[0] : color };
};

export default useScrollProgress;
