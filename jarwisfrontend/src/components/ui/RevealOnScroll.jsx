// RevealOnScroll.jsx
// Simple wrapper component that reveals content when scrolled into view
// Inspired by Palo Alto's scroll-triggered content reveals

import React from 'react';
import { motion } from 'framer-motion';
import { useReducedMotion } from '../../hooks/useReducedMotion';

// Animation presets
const animationPresets = {
  fadeUp: {
    hidden: { opacity: 0, y: 60 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15, duration: 0.6 }
    }
  },
  fadeDown: {
    hidden: { opacity: 0, y: -60 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15, duration: 0.6 }
    }
  },
  fadeLeft: {
    hidden: { opacity: 0, x: -80 },
    visible: { 
      opacity: 1, 
      x: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15, duration: 0.6 }
    }
  },
  fadeRight: {
    hidden: { opacity: 0, x: 80 },
    visible: { 
      opacity: 1, 
      x: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15, duration: 0.6 }
    }
  },
  zoomIn: {
    hidden: { opacity: 0, scale: 0.8 },
    visible: { 
      opacity: 1, 
      scale: 1,
      transition: { type: 'spring', stiffness: 100, damping: 15, duration: 0.6 }
    }
  },
  zoomOut: {
    hidden: { opacity: 0, scale: 1.2 },
    visible: { 
      opacity: 1, 
      scale: 1,
      transition: { type: 'spring', stiffness: 100, damping: 20, duration: 0.6 }
    }
  },
  flip: {
    hidden: { opacity: 0, rotateX: 90 },
    visible: { 
      opacity: 1, 
      rotateX: 0,
      transition: { type: 'spring', stiffness: 100, damping: 20, duration: 0.8 }
    }
  },
  fade: {
    hidden: { opacity: 0 },
    visible: { 
      opacity: 1,
      transition: { duration: 0.6 }
    }
  },
  blur: {
    hidden: { opacity: 0, filter: 'blur(10px)' },
    visible: { 
      opacity: 1, 
      filter: 'blur(0px)',
      transition: { duration: 0.6 }
    }
  },
  spring: {
    hidden: { opacity: 0, y: 100, scale: 0.9 },
    visible: { 
      opacity: 1, 
      y: 0,
      scale: 1,
      transition: { type: 'spring', stiffness: 80, damping: 12 }
    }
  }
};

/**
 * Wrapper component that reveals content with animation when scrolled into view.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - Content to reveal
 * @param {string} props.animation - Animation preset: 'fadeUp', 'fadeDown', 'fadeLeft', 'fadeRight', 'zoomIn', 'zoomOut', 'flip', 'fade', 'blur', 'spring'. Default: 'fadeUp'
 * @param {number} props.delay - Animation delay in seconds. Default: 0
 * @param {number} props.duration - Animation duration override. Default: uses preset
 * @param {boolean} props.once - Only animate once. Default: true
 * @param {string} props.viewportMargin - Viewport margin for trigger. Default: '-100px'
 * @param {number} props.viewportAmount - Amount of element that must be visible (0-1). Default: 0.2
 * @param {string} props.className - Additional CSS classes
 * @param {string} props.as - HTML element type. Default: 'div'
 * @param {Object} props.custom - Custom animation variants (overrides preset)
 */
export const RevealOnScroll = ({ 
  children, 
  animation = 'fadeUp',
  delay = 0,
  duration,
  once = true,
  viewportMargin = '-100px',
  viewportAmount = 0.2,
  className = '',
  as = 'div',
  custom,
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const MotionComponent = motion[as] || motion.div;

  // Get animation preset or use custom
  let variants = custom || animationPresets[animation] || animationPresets.fadeUp;

  // Apply delay and duration overrides
  if (delay || duration) {
    variants = {
      ...variants,
      visible: {
        ...variants.visible,
        transition: {
          ...variants.visible.transition,
          ...(delay && { delay }),
          ...(duration && { duration })
        }
      }
    };
  }

  // Reduced motion fallback
  if (prefersReducedMotion) {
    const Component = as;
    return <Component className={className} {...props}>{children}</Component>;
  }

  return (
    <MotionComponent
      className={className}
      variants={variants}
      initial="hidden"
      whileInView="visible"
      viewport={{ 
        once, 
        margin: viewportMargin,
        amount: viewportAmount
      }}
      {...props}
    >
      {children}
    </MotionComponent>
  );
};

/**
 * Animated text reveal with word-by-word or letter-by-letter animation.
 * 
 * @param {Object} props
 * @param {string} props.text - Text to animate
 * @param {string} props.mode - 'words' or 'letters'. Default: 'words'
 * @param {string} props.className - Text classes
 * @param {string} props.as - HTML element ('h1', 'h2', 'p', etc). Default: 'p'
 */
export const TextReveal = ({ 
  text, 
  mode = 'words',
  className = '',
  as = 'p',
  staggerDelay = 0.05,
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const MotionComponent = motion[as] || motion.p;

  const items = mode === 'letters' ? text.split('') : text.split(' ');

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: staggerDelay,
        delayChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { type: 'spring', stiffness: 100, damping: 12 }
    }
  };

  if (prefersReducedMotion) {
    const Component = as;
    return <Component className={className} {...props}>{text}</Component>;
  }

  return (
    <MotionComponent
      className={className}
      variants={containerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once: true, margin: '-50px' }}
      {...props}
    >
      {items.map((item, index) => (
        <motion.span
          key={index}
          variants={itemVariants}
          className="inline-block"
          style={{ marginRight: mode === 'words' ? '0.25em' : '0' }}
        >
          {item === ' ' ? '\u00A0' : item}
        </motion.span>
      ))}
    </MotionComponent>
  );
};

/**
 * Animated counter that counts up when scrolled into view.
 * 
 * @param {Object} props
 * @param {number} props.value - Target number value
 * @param {string} props.suffix - Text after number (e.g., '+', '%', 'K'). Default: ''
 * @param {string} props.prefix - Text before number (e.g., '$'). Default: ''
 * @param {number} props.duration - Animation duration in ms. Default: 2000
 * @param {string} props.className - Additional CSS classes
 */
export const AnimatedCounter = ({ 
  value, 
  suffix = '', 
  prefix = '',
  duration = 2000,
  className = ''
}) => {
  const prefersReducedMotion = useReducedMotion();
  const [count, setCount] = React.useState(0);
  const [hasAnimated, setHasAnimated] = React.useState(false);
  const ref = React.useRef(null);

  React.useEffect(() => {
    if (prefersReducedMotion) {
      setCount(value);
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && !hasAnimated) {
          setHasAnimated(true);
          
          let start = 0;
          const step = value / (duration / 16);
          const timer = setInterval(() => {
            start += step;
            if (start >= value) {
              setCount(value);
              clearInterval(timer);
            } else {
              setCount(Math.floor(start));
            }
          }, 16);
        }
      },
      { threshold: 0.5 }
    );

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => observer.disconnect();
  }, [value, duration, hasAnimated, prefersReducedMotion]);

  return (
    <span ref={ref} className={className}>
      {prefix}{count.toLocaleString()}{suffix}
    </span>
  );
};

export default RevealOnScroll;
