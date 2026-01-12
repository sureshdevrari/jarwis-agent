// tailwind.config.js
module.exports = {
    content: [
      "./src/**/*.{js,jsx,ts,tsx}",
      "./public/index.html",
    ],
    theme: {
      // Define custom breakpoints for all device sizes
      screens: {
        'xs': '375px',      // Small phones
        'sm': '640px',      // Large phones / Tablets portrait
        'md': '768px',      // Tablets
        'lg': '1024px',     // Laptops / Tablets landscape
        'xl': '1280px',     // Desktops
        '2xl': '1536px',    // Large desktops
        '3xl': '1920px',    // Ultra-wide
        // Touch device detection
        'touch': { 'raw': '(hover: none)' },
        'hover': { 'raw': '(hover: hover)' },
        // Orientation
        'portrait': { 'raw': '(orientation: portrait)' },
        'landscape': { 'raw': '(orientation: landscape)' },
        // Reduced motion preference
        'motion-safe': { 'raw': '(prefers-reduced-motion: no-preference)' },
        'motion-reduce': { 'raw': '(prefers-reduced-motion: reduce)' },
      },
      extend: {
        fontFamily: {
          sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
        },
        // Responsive font sizes using clamp
        fontSize: {
          'fluid-xs': 'clamp(0.65rem, 1.5vw, 0.75rem)',
          'fluid-sm': 'clamp(0.75rem, 1.8vw, 0.875rem)',
          'fluid-base': 'clamp(0.875rem, 2vw, 1rem)',
          'fluid-lg': 'clamp(1rem, 2.2vw, 1.125rem)',
          'fluid-xl': 'clamp(1.125rem, 2.5vw, 1.25rem)',
          'fluid-2xl': 'clamp(1.25rem, 3vw, 1.5rem)',
          'fluid-3xl': 'clamp(1.5rem, 4vw, 1.875rem)',
          'fluid-4xl': 'clamp(1.875rem, 5vw, 2.25rem)',
          'fluid-5xl': 'clamp(2.25rem, 6vw, 3rem)',
          'fluid-6xl': 'clamp(2.75rem, 7vw, 3.75rem)',
          'fluid-7xl': 'clamp(3rem, 8vw, 4.5rem)',
        },
        // Responsive spacing
        spacing: {
          'safe-top': 'env(safe-area-inset-top)',
          'safe-bottom': 'env(safe-area-inset-bottom)',
          'safe-left': 'env(safe-area-inset-left)',
          'safe-right': 'env(safe-area-inset-right)',
          '18': '4.5rem',
          '88': '22rem',
          '104': '26rem',
          '112': '28rem',
          '128': '32rem',
        },
        // Min/Max heights for mobile
        minHeight: {
          'screen-small': '100svh',
          'screen-dynamic': '100dvh',
          'touch': '44px',
          'touch-lg': '48px',
        },
        minWidth: {
          'touch': '44px',
          'touch-lg': '48px',
        },
        // Max widths for containers
        maxWidth: {
          'readable': '65ch',
          '8xl': '88rem',
          '9xl': '96rem',
        },
        animation: {
          'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
          'glow': 'glow 2s ease-in-out infinite alternate',
          'float': 'float 6s ease-in-out infinite',
          'shimmer': 'shimmer 2s linear infinite',
          'scan-line': 'scanLine 8s linear infinite',
          'border-glow': 'borderGlow 3s ease-in-out infinite',
          'fade-in': 'fadeIn 0.6s ease-out both',
          'fade-in-up': 'fadeInUp 0.6s ease-out both',
          'slide-in-right': 'slideInRight 0.3s ease-out',
          'slide-in-left': 'slideInLeft 0.3s ease-out',
          'slide-in-up': 'slideInUp 0.3s ease-out',
          'slide-in-down': 'slideInDown 0.3s ease-out',
          'scale-in': 'scaleIn 0.2s ease-out',
          'bounce-subtle': 'bounceSubtle 0.6s ease-out',
          // New Palo Alto-style animations
          'reveal-up': 'revealUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          'reveal-down': 'revealDown 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          'reveal-left': 'revealLeft 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          'reveal-right': 'revealRight 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          'reveal-scale': 'revealScale 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards',
          'blur-in': 'blurIn 0.6s ease-out forwards',
          'float-slow': 'float 8s ease-in-out infinite',
          'float-delayed': 'float 6s ease-in-out 2s infinite',
          'spin-slow': 'spin 20s linear infinite',
          'gradient-shift': 'gradientShift 8s ease infinite',
          'pulse-glow': 'pulseGlow 3s ease-in-out infinite',
          'marquee': 'marquee 30s linear infinite',
          'marquee-reverse': 'marquee 30s linear infinite reverse',
        },
        keyframes: {
          glow: {
            '0%': { boxShadow: '0 0 5px rgba(6, 182, 212, 0.5), 0 0 10px rgba(6, 182, 212, 0.3)' },
            '100%': { boxShadow: '0 0 20px rgba(6, 182, 212, 0.8), 0 0 30px rgba(6, 182, 212, 0.5)' },
          },
          float: {
            '0%, 100%': { transform: 'translateY(0px)' },
            '50%': { transform: 'translateY(-10px)' },
          },
          shimmer: {
            '0%': { backgroundPosition: '-200% 0' },
            '100%': { backgroundPosition: '200% 0' },
          },
          scanLine: {
            '0%': { transform: 'translateY(-100%)' },
            '100%': { transform: 'translateY(100vh)' },
          },
          borderGlow: {
            '0%, 100%': { borderColor: 'rgba(6, 182, 212, 0.3)' },
            '50%': { borderColor: 'rgba(6, 182, 212, 0.8)' },
          },
          fadeIn: {
            '0%': { opacity: '0', transform: 'translateY(20px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          fadeInUp: {
            '0%': { opacity: '0', transform: 'translateY(30px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          slideInRight: {
            '0%': { opacity: '0', transform: 'translateX(20px)' },
            '100%': { opacity: '1', transform: 'translateX(0)' },
          },
          slideInLeft: {
            '0%': { opacity: '0', transform: 'translateX(-20px)' },
            '100%': { opacity: '1', transform: 'translateX(0)' },
          },
          slideInUp: {
            '0%': { opacity: '0', transform: 'translateY(20px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          slideInDown: {
            '0%': { opacity: '0', transform: 'translateY(-20px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          scaleIn: {
            '0%': { opacity: '0', transform: 'scale(0.95)' },
            '100%': { opacity: '1', transform: 'scale(1)' },
          },
          bounceSubtle: {
            '0%, 100%': { transform: 'translateY(0)' },
            '50%': { transform: 'translateY(-5px)' },
          },
          // New Palo Alto-style keyframes
          revealUp: {
            '0%': { opacity: '0', transform: 'translateY(60px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          revealDown: {
            '0%': { opacity: '0', transform: 'translateY(-60px)' },
            '100%': { opacity: '1', transform: 'translateY(0)' },
          },
          revealLeft: {
            '0%': { opacity: '0', transform: 'translateX(-60px)' },
            '100%': { opacity: '1', transform: 'translateX(0)' },
          },
          revealRight: {
            '0%': { opacity: '0', transform: 'translateX(60px)' },
            '100%': { opacity: '1', transform: 'translateX(0)' },
          },
          revealScale: {
            '0%': { opacity: '0', transform: 'scale(0.9)' },
            '100%': { opacity: '1', transform: 'scale(1)' },
          },
          blurIn: {
            '0%': { opacity: '0', filter: 'blur(10px)' },
            '100%': { opacity: '1', filter: 'blur(0)' },
          },
          gradientShift: {
            '0%, 100%': { backgroundPosition: '0% 50%' },
            '50%': { backgroundPosition: '100% 50%' },
          },
          pulseGlow: {
            '0%, 100%': { 
              boxShadow: '0 0 20px rgba(6, 182, 212, 0.3), 0 0 40px rgba(6, 182, 212, 0.1)',
              borderColor: 'rgba(6, 182, 212, 0.3)'
            },
            '50%': { 
              boxShadow: '0 0 30px rgba(6, 182, 212, 0.5), 0 0 60px rgba(6, 182, 212, 0.2)',
              borderColor: 'rgba(6, 182, 212, 0.6)'
            },
          },
          marquee: {
            '0%': { transform: 'translateX(0%)' },
            '100%': { transform: 'translateX(-50%)' },
          },
        },
        colors: {
          cyber: {
            50: '#ecfeff',
            100: '#cffafe',
            200: '#a5f3fc',
            300: '#67e8f9',
            400: '#22d3ee',
            500: '#06b6d4',
            600: '#0891b2',
            700: '#0e7490',
            800: '#155e75',
            900: '#164e63',
            950: '#083344',
          },
          matrix: {
            50: '#f0fdf4',
            100: '#dcfce7',
            200: '#bbf7d0',
            300: '#86efac',
            400: '#4ade80',
            500: '#22c55e',
            600: '#16a34a',
            700: '#15803d',
            800: '#166534',
            900: '#14532d',
          },
        },
        backgroundImage: {
          'cyber-grid': `
            linear-gradient(rgba(6, 182, 212, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(6, 182, 212, 0.03) 1px, transparent 1px)
          `,
          'cyber-gradient': 'linear-gradient(135deg, #0a0e17 0%, #0d1321 50%, #0a0e17 100%)',
          'glow-gradient': 'radial-gradient(ellipse at center, rgba(6, 182, 212, 0.15) 0%, transparent 70%)',
        },
        boxShadow: {
          'cyber': '0 0 20px rgba(6, 182, 212, 0.3)',
          'cyber-lg': '0 0 40px rgba(6, 182, 212, 0.4)',
          'neon-cyan': '0 0 5px #06b6d4, 0 0 20px #06b6d4, 0 0 40px #06b6d4',
          'neon-violet': '0 0 5px #8b5cf6, 0 0 20px #8b5cf6, 0 0 40px #8b5cf6',
          'neon-rose': '0 0 5px #f43f5e, 0 0 20px #f43f5e, 0 0 40px #f43f5e',
          // Premium glow effects for cards
          'glow-cyan': '0 0 20px rgba(6, 182, 212, 0.25), 0 0 40px rgba(6, 182, 212, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-violet': '0 0 20px rgba(139, 92, 246, 0.25), 0 0 40px rgba(139, 92, 246, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-blue': '0 0 20px rgba(59, 130, 246, 0.25), 0 0 40px rgba(59, 130, 246, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-emerald': '0 0 20px rgba(16, 185, 129, 0.25), 0 0 40px rgba(16, 185, 129, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-amber': '0 0 20px rgba(245, 158, 11, 0.25), 0 0 40px rgba(245, 158, 11, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-red': '0 0 20px rgba(239, 68, 68, 0.25), 0 0 40px rgba(239, 68, 68, 0.1), 0 4px 20px rgba(0, 0, 0, 0.3)',
          'glow-gradient': '0 0 30px rgba(6, 182, 212, 0.2), 0 10px 40px rgba(139, 92, 246, 0.15), 0 4px 20px rgba(0, 0, 0, 0.25)',
          // Elevated card shadows
          'card-elevated': '0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 10px 20px -5px rgba(0, 0, 0, 0.4)',
          'card-hover': '0 10px 30px -5px rgba(0, 0, 0, 0.4), 0 20px 40px -10px rgba(0, 0, 0, 0.3)',
        },
      },
    },
    plugins: [],
  }
  