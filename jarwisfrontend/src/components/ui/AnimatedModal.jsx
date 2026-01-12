// AnimatedModal.jsx
// Beautiful animated modal/popup with backdrop blur and spring animations
// Inspired by Palo Alto's dynamic popup overlays

import React, { useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X } from 'lucide-react';
import { useReducedMotion } from '../../hooks/useReducedMotion';

// Overlay backdrop animation
const overlayVariants = {
  hidden: { 
    opacity: 0,
    backdropFilter: 'blur(0px)'
  },
  visible: { 
    opacity: 1,
    backdropFilter: 'blur(8px)',
    transition: { duration: 0.3 }
  },
  exit: {
    opacity: 0,
    backdropFilter: 'blur(0px)',
    transition: { duration: 0.2 }
  }
};

// Modal content animation
const modalVariants = {
  hidden: { 
    opacity: 0, 
    scale: 0.9, 
    y: 30
  },
  visible: { 
    opacity: 1, 
    scale: 1, 
    y: 0,
    transition: { 
      type: 'spring', 
      damping: 25, 
      stiffness: 300,
      duration: 0.4
    }
  },
  exit: { 
    opacity: 0, 
    scale: 0.95, 
    y: 20,
    transition: { duration: 0.2, ease: 'easeOut' }
  }
};

// Slide-up variant (alternative style)
const slideUpVariants = {
  hidden: { 
    opacity: 0, 
    y: '100%'
  },
  visible: { 
    opacity: 1, 
    y: 0,
    transition: { 
      type: 'spring', 
      damping: 30, 
      stiffness: 300
    }
  },
  exit: { 
    opacity: 0, 
    y: '100%',
    transition: { duration: 0.2 }
  }
};

/**
 * Animated modal with backdrop blur and spring animations.
 * 
 * @param {Object} props
 * @param {boolean} props.isOpen - Whether modal is open
 * @param {Function} props.onClose - Close handler
 * @param {React.ReactNode} props.children - Modal content
 * @param {string} props.title - Optional modal title
 * @param {string} props.size - Modal size: 'sm', 'md', 'lg', 'xl', 'full'. Default: 'md'
 * @param {string} props.variant - Animation variant: 'default', 'slideUp'. Default: 'default'
 * @param {boolean} props.showCloseButton - Show close button. Default: true
 * @param {boolean} props.closeOnBackdrop - Close on backdrop click. Default: true
 * @param {boolean} props.closeOnEscape - Close on Escape key. Default: true
 */
export const AnimatedModal = ({ 
  isOpen, 
  onClose, 
  children,
  title,
  size = 'md',
  variant = 'default',
  showCloseButton = true,
  closeOnBackdrop = true,
  closeOnEscape = true,
  className = ''
}) => {
  const prefersReducedMotion = useReducedMotion();

  // Size classes
  const sizeClasses = {
    sm: 'max-w-sm',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-[95vw] max-h-[95vh]'
  };

  // Handle escape key
  const handleKeyDown = useCallback((e) => {
    if (e.key === 'Escape' && closeOnEscape) {
      onClose();
    }
  }, [closeOnEscape, onClose]);

  useEffect(() => {
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, handleKeyDown]);

  const contentVariants = variant === 'slideUp' ? slideUpVariants : modalVariants;

  // Reduced motion: simple fade
  const reducedVariants = {
    hidden: { opacity: 0 },
    visible: { opacity: 1 },
    exit: { opacity: 0 }
  };

  return (
    <AnimatePresence mode="wait">
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop */}
          <motion.div
            className="absolute inset-0 bg-black/60"
            variants={prefersReducedMotion ? reducedVariants : overlayVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            onClick={closeOnBackdrop ? onClose : undefined}
            style={{ 
              WebkitBackdropFilter: 'blur(8px)',
              backdropFilter: 'blur(8px)'
            }}
          />
          
          {/* Modal Content */}
          <motion.div
            className={`
              relative z-10 w-full ${sizeClasses[size]}
              bg-gradient-to-b from-gray-900/95 to-gray-950/95
              border border-white/10
              rounded-2xl
              shadow-2xl shadow-cyan-500/10
              overflow-hidden
              ${className}
            `}
            variants={prefersReducedMotion ? reducedVariants : contentVariants}
            initial="hidden"
            animate="visible"
            exit="exit"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            {(title || showCloseButton) && (
              <div className="flex items-center justify-between p-4 border-b border-white/10">
                {title && (
                  <h2 className="text-lg font-semibold text-white">{title}</h2>
                )}
                {showCloseButton && (
                  <motion.button
                    onClick={onClose}
                    className="p-2 rounded-lg bg-white/5 hover:bg-white/10 text-gray-400 hover:text-white transition-colors"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    aria-label="Close modal"
                  >
                    <X className="w-5 h-5" />
                  </motion.button>
                )}
              </div>
            )}
            
            {/* Body */}
            <div className="p-6">
              {children}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

/**
 * Animated popup card that appears on hover or click.
 * Useful for tooltips, dropdowns, and context menus.
 */
export const AnimatedPopup = ({ 
  isOpen, 
  children,
  position = 'bottom',
  className = ''
}) => {
  const prefersReducedMotion = useReducedMotion();

  const positionClasses = {
    top: 'bottom-full mb-2',
    bottom: 'top-full mt-2',
    left: 'right-full mr-2',
    right: 'left-full ml-2'
  };

  const popupVariants = {
    hidden: { 
      opacity: 0, 
      scale: 0.95,
      y: position === 'top' ? 10 : position === 'bottom' ? -10 : 0,
      x: position === 'left' ? 10 : position === 'right' ? -10 : 0
    },
    visible: { 
      opacity: 1, 
      scale: 1,
      y: 0,
      x: 0,
      transition: { type: 'spring', damping: 20, stiffness: 300 }
    },
    exit: { 
      opacity: 0, 
      scale: 0.95,
      transition: { duration: 0.15 }
    }
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className={`
            absolute ${positionClasses[position]}
            bg-gray-900/95 border border-white/10
            rounded-xl shadow-xl shadow-black/20
            backdrop-blur-xl
            z-50
            ${className}
          `}
          variants={prefersReducedMotion ? { hidden: { opacity: 0 }, visible: { opacity: 1 }, exit: { opacity: 0 } } : popupVariants}
          initial="hidden"
          animate="visible"
          exit="exit"
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default AnimatedModal;
