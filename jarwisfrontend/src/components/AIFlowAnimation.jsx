// src/components/AIFlowAnimation.jsx
// Human-like AI intelligence flow animation with CSS

import { useEffect, useState } from "react";

const AIFlowAnimation = () => {
  const [activeNode, setActiveNode] = useState(0);
  
  // Rotate through nodes to simulate thinking
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveNode((prev) => (prev + 1) % 6);
    }, 800);
    return () => clearInterval(interval);
  }, []);

  const nodes = [
    { id: 1, label: "Analyze", x: 50, y: 15 },
    { id: 2, label: "Reason", x: 85, y: 35 },
    { id: 3, label: "Plan", x: 85, y: 65 },
    { id: 4, label: "Execute", x: 50, y: 85 },
    { id: 5, label: "Learn", x: 15, y: 65 },
    { id: 6, label: "Adapt", x: 15, y: 35 },
  ];

  return (
    <div className="relative w-full max-w-md aspect-square mx-auto">
      {/* Outer glow ring */}
      <div className="absolute inset-0 rounded-full bg-gradient-to-r from-cyan-500/20 via-blue-500/20 to-violet-500/20 blur-xl animate-pulse" />
      
      {/* Main container */}
      <div className="relative w-full h-full">
        {/* Central brain/core */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-24 h-24 sm:w-32 sm:h-32">
          {/* Rotating rings */}
          <div className="absolute inset-0 rounded-full border-2 border-cyan-500/30 animate-[spin_8s_linear_infinite]" />
          <div className="absolute inset-2 rounded-full border-2 border-blue-500/40 animate-[spin_6s_linear_infinite_reverse]" />
          <div className="absolute inset-4 rounded-full border-2 border-violet-500/50 animate-[spin_4s_linear_infinite]" />
          
          {/* Core */}
          <div className="absolute inset-6 rounded-full bg-gradient-to-br from-cyan-500 via-blue-600 to-violet-600 flex items-center justify-center shadow-lg shadow-cyan-500/30">
            <span className="text-white font-bold text-xs sm:text-sm">AGI</span>
          </div>
        </div>

        {/* Neural nodes */}
        {nodes.map((node, index) => (
          <div
            key={node.id}
            className="absolute transform -translate-x-1/2 -translate-y-1/2 transition-all duration-500"
            style={{ left: `${node.x}%`, top: `${node.y}%` }}
          >
            {/* Connection line to center */}
            <svg
              className="absolute w-32 h-32 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
              style={{ left: '50%', top: '50%' }}
            >
              <line
                x1="50%"
                y1="50%"
                x2={node.x < 50 ? '100%' : node.x > 50 ? '0%' : '50%'}
                y2={node.y < 50 ? '100%' : node.y > 50 ? '0%' : '50%'}
                className={`transition-all duration-300 ${
                  activeNode === index ? 'stroke-cyan-400' : 'stroke-gray-600'
                }`}
                strokeWidth="2"
                strokeDasharray={activeNode === index ? "0" : "4 4"}
              />
            </svg>
            
            {/* Node circle */}
            <div
              className={`relative w-14 h-14 sm:w-16 sm:h-16 rounded-full flex items-center justify-center transition-all duration-300 ${
                activeNode === index
                  ? 'bg-gradient-to-br from-cyan-500 to-blue-600 scale-110 shadow-lg shadow-cyan-500/50'
                  : 'bg-gray-800/80 border border-gray-600 hover:border-cyan-500/50'
              }`}
            >
              <span className={`text-xs sm:text-sm font-medium transition-colors duration-300 ${
                activeNode === index ? 'text-white' : 'text-gray-400'
              }`}>
                {node.label}
              </span>
            </div>

            {/* Pulse effect for active node */}
            {activeNode === index && (
              <div className="absolute inset-0 w-14 h-14 sm:w-16 sm:h-16 rounded-full bg-cyan-500/30 animate-ping" />
            )}
          </div>
        ))}

        {/* Floating particles */}
        <div className="absolute inset-0 overflow-hidden rounded-full">
          {[...Array(8)].map((_, i) => (
            <div
              key={i}
              className="absolute w-1 h-1 bg-cyan-400 rounded-full animate-ai-float"
              style={{
                left: `${20 + Math.random() * 60}%`,
                top: `${20 + Math.random() * 60}%`,
                animationDelay: `${i * 0.5}s`,
                animationDuration: `${3 + Math.random() * 2}s`,
              }}
            />
          ))}
        </div>

        {/* Data flow lines */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-30">
          {/* Hexagon connecting nodes */}
          <polygon
            points="50,15 85,35 85,65 50,85 15,65 15,35"
            fill="none"
            stroke="url(#flowGradient)"
            strokeWidth="1"
            className="animate-[dash_3s_linear_infinite]"
            strokeDasharray="10 5"
            transform="scale(0.9) translate(5.5%, 5.5%)"
          />
          <defs>
            <linearGradient id="flowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="50%" stopColor="#3b82f6" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>
        </svg>
      </div>

      {/* Bottom label */}
      <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 text-center">
        <p className="text-sm text-gray-400">
          <span className="text-cyan-400 font-semibold">Continuous</span> Learning Cycle
        </p>
      </div>
    </div>
  );
};

export default AIFlowAnimation;
