// StaggerContainer.jsx
// Animated container that reveals children with staggered cascade effect
// Perfect for lists, grids, and sequential content reveals like Palo Alto's design

import React from 'react';
import { motion } from 'framer-motion';
import { useReducedMotion } from '../../hooks/useReducedMotion';

// Container animation variants
const containerVariants = {
  hidden: { 
    opacity: 0 
  },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.1,
      delayChildren: 0.1,
      when: 'beforeChildren'
    }
  }
};

// Individual item animation variants
const itemVariants = {
  hidden: { 
    opacity: 0, 
    y: 40,
    scale: 0.95
  },
  visible: { 
    opacity: 1, 
    y: 0,
    scale: 1,
    transition: { 
      type: 'spring',
      stiffness: 100,
      damping: 15,
      duration: 0.6 
    }
  }
};

// Alternative slide-in variants
const slideVariants = {
  left: {
    hidden: { opacity: 0, x: -60 },
    visible: { 
      opacity: 1, 
      x: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15 }
    }
  },
  right: {
    hidden: { opacity: 0, x: 60 },
    visible: { 
      opacity: 1, 
      x: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15 }
    }
  },
  up: {
    hidden: { opacity: 0, y: 60 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15 }
    }
  },
  down: {
    hidden: { opacity: 0, y: -60 },
    visible: { 
      opacity: 1, 
      y: 0,
      transition: { type: 'spring', stiffness: 100, damping: 15 }
    }
  },
  scale: {
    hidden: { opacity: 0, scale: 0.8 },
    visible: { 
      opacity: 1, 
      scale: 1,
      transition: { type: 'spring', stiffness: 100, damping: 15 }
    }
  },
  fade: {
    hidden: { opacity: 0 },
    visible: { 
      opacity: 1,
      transition: { duration: 0.5 }
    }
  }
};

/**
 * Container that animates children with staggered reveal effect when in view.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - Child elements (should be StaggerItem components)
 * @param {string} props.className - Additional CSS classes
 * @param {number} props.staggerDelay - Delay between each child animation. Default: 0.1
 * @param {number} props.initialDelay - Delay before animation starts. Default: 0.1
 * @param {boolean} props.once - Only animate once. Default: true
 * @param {string} props.viewportMargin - Viewport margin for triggering. Default: "-100px"
 * @param {string} props.as - HTML element type. Default: 'div'
 */
export const StaggerContainer = ({ 
  children, 
  className = '',
  staggerDelay = 0.1,
  initialDelay = 0.1,
  once = true,
  viewportMargin = '-100px',
  as = 'div',
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const MotionComponent = motion[as] || motion.div;

  const customContainerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: prefersReducedMotion ? 0 : staggerDelay,
        delayChildren: prefersReducedMotion ? 0 : initialDelay,
        when: 'beforeChildren'
      }
    }
  };

  if (prefersReducedMotion) {
    const Component = as;
    return <Component className={className} {...props}>{children}</Component>;
  }

  return (
    <MotionComponent
      className={className}
      variants={customContainerVariants}
      initial="hidden"
      whileInView="visible"
      viewport={{ once, margin: viewportMargin }}
      {...props}
    >
      {children}
    </MotionComponent>
  );
};

/**
 * Individual item within a StaggerContainer.
 * Automatically inherits animation from parent StaggerContainer.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - Child content
 * @param {string} props.className - Additional CSS classes
 * @param {string} props.direction - Animation direction: 'up', 'down', 'left', 'right', 'scale', 'fade'. Default: 'up'
 * @param {string} props.as - HTML element type. Default: 'div'
 */
export const StaggerItem = ({ 
  children, 
  className = '',
  direction = 'up',
  as = 'div',
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const MotionComponent = motion[as] || motion.div;
  
  const variants = slideVariants[direction] || itemVariants;

  if (prefersReducedMotion) {
    const Component = as;
    return <Component className={className} {...props}>{children}</Component>;
  }

  return (
    <MotionComponent
      className={className}
      variants={variants}
      {...props}
    >
      {children}
    </MotionComponent>
  );
};

/**
 * Pre-built stagger grid for card layouts.
 * Combines StaggerContainer with grid styling.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - Grid items
 * @param {string} props.columns - Grid columns class. Default: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3'
 * @param {string} props.gap - Gap class. Default: 'gap-6'
 */
export const StaggerGrid = ({ 
  children, 
  columns = 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
  gap = 'gap-6',
  className = '',
  ...props 
}) => {
  return (
    <StaggerContainer 
      className={`grid ${columns} ${gap} ${className}`}
      {...props}
    >
      {children}
    </StaggerContainer>
  );
};

/**
 * Pre-built stagger list for vertical content.
 */
export const StaggerList = ({ 
  children, 
  className = '',
  ...props 
}) => {
  return (
    <StaggerContainer 
      className={`flex flex-col space-y-4 ${className}`}
      {...props}
    >
      {children}
    </StaggerContainer>
  );
};

export default StaggerContainer;
