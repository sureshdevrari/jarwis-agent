// src/components/EscapingButton.jsx
// Ultra-responsive escaping button - IMPOSSIBLE to catch without filling form!

import { useState, useRef, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";

const EscapingButton = ({ 
  isFormValid, 
  onClick, 
  loading, 
  children,
  loadingText = "Processing...",
  className = ""
}) => {
  const [position, setPosition] = useState({ x: 0, y: 0 });
  const [escapeCount, setEscapeCount] = useState(0);
  const [showMessage, setShowMessage] = useState(false);
  const [currentMessage, setCurrentMessage] = useState("");
  const buttonRef = useRef(null);
  const positionRef = useRef({ x: 0, y: 0 });
  const mouseRef = useRef({ x: 0, y: 0, vx: 0, vy: 0 });
  const lastMousePos = useRef({ x: 0, y: 0 });
  const animationFrameRef = useRef(null);
  const messageTimeoutRef = useRef(null);

  // Funny messages
  const escapeMessages = useMemo(() => [
    "Nice try! ", "Fill the form! [NOTE]", "Can't catch me! ‍", 
    "Nope! ", "Too slow! [!]", "Fill details! ", "I'm fast! [LAUNCH]",
    "Missing fields? ", "Complete form! [TARGET]", "Not today! "
  ], []);

  useEffect(() => {
    if (isFormValid || loading) {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      return;
    }

    let isRunning = true;

    // Track mouse position and velocity
    const handleMouseMove = (e) => {
      const dx = e.clientX - lastMousePos.current.x;
      const dy = e.clientY - lastMousePos.current.y;
      
      mouseRef.current = {
        x: e.clientX,
        y: e.clientY,
        vx: dx * 2, // Velocity with amplification
        vy: dy * 2
      };
      
      lastMousePos.current = { x: e.clientX, y: e.clientY };
    };

    // Main escape loop - runs every frame
    const escapeLoop = () => {
      if (!isRunning || isFormValid) return;

      const button = buttonRef.current;
      if (!button) {
        animationFrameRef.current = requestAnimationFrame(escapeLoop);
        return;
      }

      const rect = button.getBoundingClientRect();
      const btnCenterX = rect.left + rect.width / 2;
      const btnCenterY = rect.top + rect.height / 2;
      
      // Predict where mouse will be
      const predictedX = mouseRef.current.x + mouseRef.current.vx * 3;
      const predictedY = mouseRef.current.y + mouseRef.current.vy * 3;
      
      // Check distance to both current and predicted mouse position
      const distToCurrent = Math.hypot(btnCenterX - mouseRef.current.x, btnCenterY - mouseRef.current.y);
      const distToPredicted = Math.hypot(btnCenterX - predictedX, btnCenterY - predictedY);
      
      const triggerDistance = 200; // Large detection zone
      
      if (distToCurrent < triggerDistance || distToPredicted < triggerDistance) {
        // Calculate escape direction (away from both current and predicted mouse)
        const awayFromCurrentX = btnCenterX - mouseRef.current.x;
        const awayFromCurrentY = btnCenterY - mouseRef.current.y;
        const awayFromPredictedX = btnCenterX - predictedX;
        const awayFromPredictedY = btnCenterY - predictedY;
        
        // Combine both escape vectors
        let escapeX = awayFromCurrentX + awayFromPredictedX * 0.5;
        let escapeY = awayFromCurrentY + awayFromPredictedY * 0.5;
        
        // Normalize and scale
        const escapeMag = Math.hypot(escapeX, escapeY) || 1;
        const escapeSpeed = 180 + Math.random() * 100; // Fast escape!
        
        escapeX = (escapeX / escapeMag) * escapeSpeed;
        escapeY = (escapeY / escapeMag) * escapeSpeed;
        
        // Add randomness for unpredictability
        const randomAngle = (Math.random() - 0.5) * 1.2;
        const cos = Math.cos(randomAngle);
        const sin = Math.sin(randomAngle);
        const newEscapeX = escapeX * cos - escapeY * sin;
        const newEscapeY = escapeX * sin + escapeY * cos;
        
        let newX = positionRef.current.x + newEscapeX;
        let newY = positionRef.current.y + newEscapeY;
        
        // Viewport bounds
        const vw = window.innerWidth;
        const vh = window.innerHeight;
        const pad = 50;
        
        const baseX = rect.left - positionRef.current.x;
        const baseY = rect.top - positionRef.current.y;
        
        const minX = pad - baseX;
        const maxX = vw - rect.width - pad - baseX;
        const minY = pad - baseY;
        const maxY = vh - rect.height - pad - baseY;
        
        // Clamp to bounds
        newX = Math.max(minX, Math.min(maxX, newX));
        newY = Math.max(minY, Math.min(maxY, newY));
        
        // If stuck, teleport!
        const movedEnough = Math.hypot(newX - positionRef.current.x, newY - positionRef.current.y) > 30;
        if (!movedEnough) {
          // Teleport to random position away from mouse
          const randomAngle = Math.random() * Math.PI * 2;
          const teleportDist = Math.min(vw, vh) * 0.3;
          newX = (Math.cos(randomAngle) * teleportDist);
          newY = (Math.sin(randomAngle) * teleportDist);
          newX = Math.max(minX, Math.min(maxX, newX));
          newY = Math.max(minY, Math.min(maxY, newY));
        }
        
        positionRef.current = { x: newX, y: newY };
        setPosition({ x: newX, y: newY });
        
        // Update escape count and message (throttled)
        if (!messageTimeoutRef.current) {
          setEscapeCount(c => c + 1);
          setCurrentMessage(escapeMessages[Math.floor(Math.random() * escapeMessages.length)]);
          setShowMessage(true);
          
          messageTimeoutRef.current = setTimeout(() => {
            setShowMessage(false);
            messageTimeoutRef.current = null;
          }, 600);
        }
      }
      
      animationFrameRef.current = requestAnimationFrame(escapeLoop);
    };

    document.addEventListener('mousemove', handleMouseMove, { passive: true });
    animationFrameRef.current = requestAnimationFrame(escapeLoop);
    
    return () => {
      isRunning = false;
      document.removeEventListener('mousemove', handleMouseMove);
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current);
      }
      if (messageTimeoutRef.current) {
        clearTimeout(messageTimeoutRef.current);
      }
    };
  }, [isFormValid, loading, escapeMessages]);

  // Reset when form becomes valid
  useEffect(() => {
    if (isFormValid) {
      positionRef.current = { x: 0, y: 0 };
      setPosition({ x: 0, y: 0 });
      setShowMessage(false);
    }
  }, [isFormValid]);

  return (
    <div className="relative w-full h-20 flex items-center justify-center" style={{ overflow: "visible" }}>
      {/* The escaping button */}
      <motion.button
        ref={buttonRef}
        type="submit"
        disabled={loading}
        onClick={isFormValid ? onClick : (e) => e.preventDefault()}
        animate={{
          x: position.x,
          y: position.y,
        }}
        whileHover={isFormValid ? { scale: 1.05 } : undefined}
        whileTap={isFormValid ? { scale: 0.95 } : undefined}
        transition={isFormValid ? {
          type: "spring",
          stiffness: 300,
          damping: 20,
        } : {
          type: "tween",
          duration: 0.15,
          ease: "easeOut",
        }}
        className={`
          relative px-8 py-3 rounded-2xl font-bold text-white
          cursor-pointer select-none
          disabled:opacity-50 disabled:cursor-not-allowed
          ${isFormValid 
            ? "bg-gradient-to-r from-blue-500 to-cyan-400 hover:from-cyan-400 hover:to-blue-500 shadow-lg shadow-cyan-500/30" 
            : "bg-gradient-to-r from-purple-600 to-pink-500 shadow-lg shadow-purple-500/30 animate-pulse"
          }
          ${className}
        `}
        style={{
          minWidth: "200px",
          zIndex: isFormValid ? 1 : 9999,
          position: "relative",
        }}
      >
        {/* Button content */}
        <span className="relative z-10 flex items-center justify-center gap-2">
          {loading ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
                className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full"
              />
              {loadingText}
            </>
          ) : (
            <>
              {!isFormValid && <span>[LOCK]</span>}
              {isFormValid && <span>[OK]</span>}
              {children}
            </>
          )}
        </span>

        {/* Glow effect when valid */}
        {isFormValid && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="absolute inset-0 rounded-2xl bg-gradient-to-r from-cyan-400 to-blue-500 blur-xl opacity-50 -z-10"
          />
        )}
      </motion.button>

      {/* Hint text - positioned below button */}
      <AnimatePresence>
        {!isFormValid && (
          <motion.p
            initial={{ opacity: 0, y: -5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="w-full text-center mt-3 text-xs text-gray-500"
          >
            [IDEA] Hint: Fill in both email and password!
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
};

export default EscapingButton;