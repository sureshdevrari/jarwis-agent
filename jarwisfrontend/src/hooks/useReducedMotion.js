// useReducedMotion.js
// Hook to detect and respect user's prefers-reduced-motion preference
// Returns true if user prefers reduced motion, false otherwise

import { useState, useEffect } from 'react';

/**
 * Detects if user has enabled reduced motion preference in their OS settings.
 * 
 * Usage:
 *   const prefersReducedMotion = useReducedMotion();
 *   
 *   if (prefersReducedMotion) {
 *     // Skip animations or use simpler transitions
 *   }
 * 
 * @returns {boolean} True if user prefers reduced motion
 */
export const useReducedMotion = () => {
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    // Check if window is available (SSR safety)
    if (typeof window === 'undefined') return;

    // Create media query
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    
    // Set initial value
    setPrefersReducedMotion(mediaQuery.matches);

    // Listen for changes (user might change preference while on page)
    const handleChange = (event) => {
      setPrefersReducedMotion(event.matches);
    };

    // Modern browsers
    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handleChange);
    } else {
      // Legacy Safari
      mediaQuery.addListener(handleChange);
    }

    // Cleanup
    return () => {
      if (mediaQuery.removeEventListener) {
        mediaQuery.removeEventListener('change', handleChange);
      } else {
        mediaQuery.removeListener(handleChange);
      }
    };
  }, []);

  return prefersReducedMotion;
};

/**
 * Returns animation configuration based on reduced motion preference.
 * Useful for Framer Motion or other animation libraries.
 * 
 * Usage:
 *   const { shouldAnimate, duration, transition } = useAnimationConfig();
 *   
 *   <motion.div
 *     animate={shouldAnimate ? { opacity: 1 } : false}
 *     transition={transition}
 *   />
 * 
 * @param {Object} options - Configuration options
 * @param {number} options.defaultDuration - Default animation duration in seconds
 * @returns {Object} Animation configuration
 */
export const useAnimationConfig = (options = {}) => {
  const { defaultDuration = 0.3 } = options;
  const prefersReducedMotion = useReducedMotion();

  return {
    shouldAnimate: !prefersReducedMotion,
    prefersReducedMotion,
    duration: prefersReducedMotion ? 0 : defaultDuration,
    transition: prefersReducedMotion 
      ? { duration: 0 } 
      : { duration: defaultDuration, ease: 'easeOut' },
    // Framer Motion variants helper
    variants: {
      hidden: { opacity: 0, y: prefersReducedMotion ? 0 : 20 },
      visible: { 
        opacity: 1, 
        y: 0,
        transition: prefersReducedMotion ? { duration: 0 } : { duration: defaultDuration }
      }
    }
  };
};

/**
 * CSS class helper for reduced motion
 * 
 * Usage:
 *   <div className={motionClass('animate-bounce', 'opacity-100')}>
 *     Bounces on normal, static on reduced motion
 *   </div>
 */
export const useMotionClass = () => {
  const prefersReducedMotion = useReducedMotion();
  
  return (animatedClass, fallbackClass = '') => {
    return prefersReducedMotion ? fallbackClass : animatedClass;
  };
};

export default useReducedMotion;
