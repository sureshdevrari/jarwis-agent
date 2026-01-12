// ParallaxSection.jsx
// Parallax background section with depth layers
// Creates Palo Alto-style floating orb and background effects

import React from 'react';
import { motion, useScroll, useTransform, useSpring } from 'framer-motion';
import { useReducedMotion } from '../../hooks/useReducedMotion';

/**
 * Section with parallax scrolling background layers.
 * Great for hero sections and visually rich content areas.
 * 
 * @param {Object} props
 * @param {React.ReactNode} props.children - Section content
 * @param {string} props.className - Additional CSS classes
 * @param {boolean} props.showOrbs - Show floating gradient orbs. Default: true
 * @param {string} props.orbColor1 - First orb color. Default: 'rgba(6, 182, 212, 0.3)'
 * @param {string} props.orbColor2 - Second orb color. Default: 'rgba(139, 92, 246, 0.2)'
 */
export const ParallaxSection = ({ 
  children, 
  className = '',
  showOrbs = true,
  orbColor1 = 'rgba(6, 182, 212, 0.3)',
  orbColor2 = 'rgba(139, 92, 246, 0.2)',
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const ref = React.useRef(null);
  
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start end', 'end start']
  });

  // Different parallax speeds for depth layers
  const y1 = useTransform(scrollYProgress, [0, 1], [0, -150]);
  const y2 = useTransform(scrollYProgress, [0, 1], [0, -80]);
  const y3 = useTransform(scrollYProgress, [0, 1], [0, -200]);
  
  const ySpring1 = useSpring(y1, { stiffness: 100, damping: 30 });
  const ySpring2 = useSpring(y2, { stiffness: 100, damping: 30 });
  const ySpring3 = useSpring(y3, { stiffness: 100, damping: 30 });

  const rotate1 = useTransform(scrollYProgress, [0, 1], [0, 45]);
  const rotate2 = useTransform(scrollYProgress, [0, 1], [0, -30]);

  return (
    <section 
      ref={ref} 
      className={`relative overflow-hidden ${className}`}
      {...props}
    >
      {/* Parallax Background Layers */}
      {showOrbs && !prefersReducedMotion && (
        <>
          {/* Large gradient orb - slow parallax */}
          <motion.div
            className="absolute -top-40 -right-40 w-96 h-96 rounded-full blur-3xl pointer-events-none"
            style={{ 
              background: `radial-gradient(circle, ${orbColor1} 0%, transparent 70%)`,
              y: ySpring1,
              rotate: rotate1
            }}
          />
          
          {/* Medium orb - medium parallax */}
          <motion.div
            className="absolute top-1/2 -left-32 w-72 h-72 rounded-full blur-3xl pointer-events-none"
            style={{ 
              background: `radial-gradient(circle, ${orbColor2} 0%, transparent 70%)`,
              y: ySpring2,
              rotate: rotate2
            }}
          />
          
          {/* Small accent orb - fast parallax */}
          <motion.div
            className="absolute bottom-20 right-1/4 w-48 h-48 rounded-full blur-2xl pointer-events-none opacity-50"
            style={{ 
              background: `radial-gradient(circle, ${orbColor1} 0%, transparent 70%)`,
              y: ySpring3
            }}
          />
        </>
      )}

      {/* Static orbs for reduced motion */}
      {showOrbs && prefersReducedMotion && (
        <>
          <div
            className="absolute -top-40 -right-40 w-96 h-96 rounded-full blur-3xl pointer-events-none"
            style={{ background: `radial-gradient(circle, ${orbColor1} 0%, transparent 70%)` }}
          />
          <div
            className="absolute top-1/2 -left-32 w-72 h-72 rounded-full blur-3xl pointer-events-none"
            style={{ background: `radial-gradient(circle, ${orbColor2} 0%, transparent 70%)` }}
          />
        </>
      )}
      
      {/* Content */}
      <div className="relative z-10">
        {children}
      </div>
    </section>
  );
};

/**
 * Floating element with hover and scroll-based animation.
 * Use for decorative cards, icons, or badges.
 */
export const FloatingElement = ({ 
  children, 
  className = '',
  floatIntensity = 10,
  rotateOnHover = true,
  glowColor = 'rgba(6, 182, 212, 0.5)',
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();

  if (prefersReducedMotion) {
    return <div className={className} {...props}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      animate={{
        y: [0, -floatIntensity, 0],
      }}
      transition={{
        duration: 4,
        repeat: Infinity,
        ease: 'easeInOut'
      }}
      whileHover={rotateOnHover ? {
        scale: 1.05,
        rotate: [0, -2, 2, 0],
        boxShadow: `0 20px 40px ${glowColor}`,
        transition: { duration: 0.3 }
      } : { scale: 1.05 }}
      {...props}
    >
      {children}
    </motion.div>
  );
};

/**
 * Animated gradient background that shifts colors on scroll.
 */
export const AnimatedGradientBg = ({ 
  children,
  className = '',
  colors = ['#0a0e17', '#0d1321', '#0a0e17'],
  ...props 
}) => {
  const prefersReducedMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  
  const backgroundPosition = useTransform(
    scrollYProgress, 
    [0, 1], 
    ['0% 0%', '100% 100%']
  );

  if (prefersReducedMotion) {
    return (
      <div 
        className={className}
        style={{ background: colors[0] }}
        {...props}
      >
        {children}
      </div>
    );
  }

  return (
    <motion.div
      className={className}
      style={{
        background: `linear-gradient(135deg, ${colors.join(', ')})`,
        backgroundSize: '400% 400%',
        backgroundPosition
      }}
      {...props}
    >
      {children}
    </motion.div>
  );
};

export default ParallaxSection;
