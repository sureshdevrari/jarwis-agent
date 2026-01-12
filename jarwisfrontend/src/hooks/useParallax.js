// useParallax.js
// Hook for creating parallax scroll effects using Framer Motion
// Returns motion values that can be applied to element's style.y or style.x

import { useScroll, useTransform, useSpring } from 'framer-motion';
import { useRef } from 'react';
import { useReducedMotion } from './useReducedMotion';

/**
 * Creates a parallax effect based on scroll position.
 * 
 * Usage:
 *   const { ref, y } = useParallax({ speed: 0.5 });
 *   return <motion.div ref={ref} style={{ y }}>...</motion.div>
 * 
 * @param {Object} options
 * @param {number} options.speed - Parallax speed multiplier (0.1 = slow, 1 = fast). Default: 0.5
 * @param {string} options.direction - 'up' or 'down'. Default: 'up'
 * @param {boolean} options.smooth - Whether to apply spring smoothing. Default: true
 * @returns {{ ref: React.RefObject, y: MotionValue, progress: MotionValue }}
 */
export const useParallax = ({ 
  speed = 0.5, 
  direction = 'up',
  smooth = true 
} = {}) => {
  const ref = useRef(null);
  const prefersReducedMotion = useReducedMotion();

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'end start']
  });

  // Calculate parallax offset based on speed and direction
  const multiplier = direction === 'up' ? -1 : 1;
  const yValue = useTransform(
    scrollYProgress, 
    [0, 1], 
    [100 * speed * multiplier, -100 * speed * multiplier]
  );

  // Apply spring smoothing for more natural movement
  const ySpring = useSpring(yValue, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  // Return 0 if user prefers reduced motion
  const y = prefersReducedMotion ? 0 : (smooth ? ySpring : yValue);

  return { ref, y, progress: scrollYProgress };
};

/**
 * Creates a horizontal parallax effect.
 * 
 * @param {Object} options
 * @param {number} options.speed - Parallax speed multiplier. Default: 0.3
 * @param {string} options.direction - 'left' or 'right'. Default: 'left'
 * @returns {{ ref: React.RefObject, x: MotionValue }}
 */
export const useParallaxX = ({ 
  speed = 0.3, 
  direction = 'left' 
} = {}) => {
  const ref = useRef(null);
  const prefersReducedMotion = useReducedMotion();

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'end start']
  });

  const multiplier = direction === 'left' ? -1 : 1;
  const xValue = useTransform(
    scrollYProgress, 
    [0, 1], 
    [50 * speed * multiplier, -50 * speed * multiplier]
  );

  const xSpring = useSpring(xValue, {
    stiffness: 100,
    damping: 30,
    restDelta: 0.001
  });

  const x = prefersReducedMotion ? 0 : xSpring;

  return { ref, x };
};

/**
 * Creates a scale effect based on scroll position.
 * Element scales from startScale to endScale as it enters the viewport.
 * 
 * @param {Object} options
 * @param {number} options.startScale - Scale at start. Default: 0.8
 * @param {number} options.endScale - Scale at end. Default: 1
 * @returns {{ ref: React.RefObject, scale: MotionValue }}
 */
export const useScrollScale = ({ 
  startScale = 0.8, 
  endScale = 1 
} = {}) => {
  const ref = useRef(null);
  const prefersReducedMotion = useReducedMotion();

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'center center']
  });

  const scaleValue = useTransform(scrollYProgress, [0, 1], [startScale, endScale]);
  
  const scale = prefersReducedMotion ? 1 : scaleValue;

  return { ref, scale };
};

/**
 * Creates an opacity fade effect based on scroll position.
 * 
 * @param {Object} options
 * @param {number} options.startOpacity - Opacity at start. Default: 0
 * @param {number} options.endOpacity - Opacity at end. Default: 1
 * @returns {{ ref: React.RefObject, opacity: MotionValue }}
 */
export const useScrollOpacity = ({ 
  startOpacity = 0, 
  endOpacity = 1 
} = {}) => {
  const ref = useRef(null);
  const prefersReducedMotion = useReducedMotion();

  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'center center']
  });

  const opacityValue = useTransform(scrollYProgress, [0, 0.5], [startOpacity, endOpacity]);
  
  const opacity = prefersReducedMotion ? 1 : opacityValue;

  return { ref, opacity };
};

export default useParallax;
