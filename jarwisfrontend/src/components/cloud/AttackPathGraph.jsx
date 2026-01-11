// src/components/cloud/AttackPathGraph.jsx - D3.js Attack Path Visualization
import { useEffect, useRef, useState } from "react";
import { useTheme } from "../../context/ThemeContext";

/**
 * Attack Path Graph Component
 * Visualizes cloud attack paths as a directed graph using SVG
 * No D3.js dependency - pure React/SVG implementation
 */
const AttackPathGraph = ({ attackPaths, resources, onNodeClick }) => {
  const { isDarkMode } = useTheme();
  const containerRef = useRef(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 400 });
  const [selectedPath, setSelectedPath] = useState(null);
  const [hoveredNode, setHoveredNode] = useState(null);

  // Update dimensions on resize
  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: Math.max(400, containerRef.current.clientWidth * 0.5),
        });
      }
    };

    updateDimensions();
    window.addEventListener("resize", updateDimensions);
    return () => window.removeEventListener("resize", updateDimensions);
  }, []);

  // Build graph from attack paths
  const buildGraph = () => {
    const nodes = new Map();
    const edges = [];

    attackPaths?.forEach((path, pathIndex) => {
      const pathNodes = path.path || [];
      
      pathNodes.forEach((nodeId, idx) => {
        if (!nodes.has(nodeId)) {
          // Find resource details
          const resource = resources?.find((r) => r.id === nodeId || r.name === nodeId);
          
          nodes.set(nodeId, {
            id: nodeId,
            label: nodeId.length > 20 ? nodeId.substring(0, 20) + "..." : nodeId,
            type: resource?.type || "unknown",
            pathIndex,
            isSource: idx === 0,
            isTarget: idx === pathNodes.length - 1,
          });
        }

        // Add edge to next node
        if (idx < pathNodes.length - 1) {
          edges.push({
            source: nodeId,
            target: pathNodes[idx + 1],
            pathIndex,
            severity: path.severity || "medium",
          });
        }
      });
    });

    return { nodes: Array.from(nodes.values()), edges };
  };

  const { nodes, edges } = buildGraph();

  // Calculate node positions (simple force-directed layout simulation)
  const calculatePositions = () => {
    const { width, height } = dimensions;
    const positions = {};
    
    // Group nodes by their position in paths
    const levels = {};
    attackPaths?.forEach((path) => {
      path.path?.forEach((nodeId, level) => {
        if (!levels[nodeId] || levels[nodeId] > level) {
          levels[nodeId] = level;
        }
      });
    });

    // Calculate max level
    const maxLevel = Math.max(...Object.values(levels), 0);
    
    // Position nodes by level
    const levelNodes = {};
    Object.entries(levels).forEach(([nodeId, level]) => {
      if (!levelNodes[level]) levelNodes[level] = [];
      levelNodes[level].push(nodeId);
    });

    // Assign positions
    const padding = 80;
    const levelWidth = (width - padding * 2) / (maxLevel + 1);
    
    Object.entries(levelNodes).forEach(([level, nodeIds]) => {
      const levelHeight = (height - padding * 2) / (nodeIds.length + 1);
      nodeIds.forEach((nodeId, idx) => {
        positions[nodeId] = {
          x: padding + parseInt(level) * levelWidth + levelWidth / 2,
          y: padding + (idx + 1) * levelHeight,
        };
      });
    });

    return positions;
  };

  const positions = calculatePositions();

  // Get node colors based on type
  const getNodeColor = (node) => {
    if (node.isSource) return "#ef4444"; // Red for entry point
    if (node.isTarget) return "#f97316"; // Orange for target
    
    const typeColors = {
      s3_bucket: "#f59e0b",
      ec2_instance: "#3b82f6",
      iam_role: "#8b5cf6",
      lambda_function: "#10b981",
      rds_instance: "#ec4899",
      storage_account: "#0ea5e9",
      virtual_machine: "#6366f1",
      sql_server: "#14b8a6",
      gcs_bucket: "#eab308",
      compute_instance: "#7c3aed",
      default: "#6b7280",
    };
    
    return typeColors[node.type] || typeColors.default;
  };

  // Get edge color based on severity
  const getEdgeColor = (edge) => {
    const colors = {
      critical: "#ef4444",
      high: "#f97316",
      medium: "#eab308",
      low: "#3b82f6",
    };
    return colors[edge.severity] || colors.medium;
  };

  // Render nothing if no paths
  if (!attackPaths || attackPaths.length === 0) {
    return (
      <div
        ref={containerRef}
        className={`flex items-center justify-center h-64 rounded-lg ${
          isDarkMode ? "bg-gray-800" : "bg-gray-100"
        }`}
      >
        <p className={isDarkMode ? "text-gray-500" : "text-gray-400"}>
          No attack paths detected
        </p>
      </div>
    );
  }

  return (
    <div ref={containerRef} className="relative w-full">
      {/* Legend */}
      <div className={`absolute top-2 left-2 p-2 rounded-lg text-xs z-10 ${
        isDarkMode ? "bg-gray-800/90" : "bg-white/90"
      } shadow`}>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-3 h-3 rounded-full bg-red-500" />
          <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Entry Point</span>
        </div>
        <div className="flex items-center gap-2 mb-1">
          <span className="w-3 h-3 rounded-full bg-orange-500" />
          <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Target Resource</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-blue-500" />
          <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>Cloud Resource</span>
        </div>
      </div>

      {/* Path selector */}
      {attackPaths.length > 1 && (
        <div className={`absolute top-2 right-2 p-2 rounded-lg z-10 ${
          isDarkMode ? "bg-gray-800/90" : "bg-white/90"
        } shadow`}>
          <select
            value={selectedPath ?? ""}
            onChange={(e) => setSelectedPath(e.target.value === "" ? null : parseInt(e.target.value))}
            className={`text-sm rounded px-2 py-1 ${
              isDarkMode ? "bg-gray-700 text-white" : "bg-gray-100 text-gray-900"
            }`}
          >
            <option value="">All Paths</option>
            {attackPaths.map((path, idx) => (
              <option key={idx} value={idx}>
                Path {idx + 1} (Blast: {path.blast_radius})
              </option>
            ))}
          </select>
        </div>
      )}

      {/* SVG Graph */}
      <svg
        width={dimensions.width}
        height={dimensions.height}
        className={`rounded-lg ${isDarkMode ? "bg-gray-900" : "bg-gray-50"}`}
      >
        {/* Gradient definitions */}
        <defs>
          <marker
            id="arrowhead"
            markerWidth="10"
            markerHeight="7"
            refX="10"
            refY="3.5"
            orient="auto"
          >
            <polygon
              points="0 0, 10 3.5, 0 7"
              fill={isDarkMode ? "#6b7280" : "#9ca3af"}
            />
          </marker>
          <marker
            id="arrowhead-critical"
            markerWidth="10"
            markerHeight="7"
            refX="10"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#ef4444" />
          </marker>
          <marker
            id="arrowhead-high"
            markerWidth="10"
            markerHeight="7"
            refX="10"
            refY="3.5"
            orient="auto"
          >
            <polygon points="0 0, 10 3.5, 0 7" fill="#f97316" />
          </marker>
        </defs>

        {/* Render edges */}
        <g>
          {edges
            .filter((e) => selectedPath === null || e.pathIndex === selectedPath)
            .map((edge, idx) => {
              const sourcePos = positions[edge.source];
              const targetPos = positions[edge.target];
              
              if (!sourcePos || !targetPos) return null;

              // Calculate control point for curved path
              const midX = (sourcePos.x + targetPos.x) / 2;
              const midY = (sourcePos.y + targetPos.y) / 2;
              const dx = targetPos.x - sourcePos.x;
              const dy = targetPos.y - sourcePos.y;
              const offset = 20;
              const controlX = midX - dy * offset / Math.sqrt(dx * dx + dy * dy || 1);
              const controlY = midY + dx * offset / Math.sqrt(dx * dx + dy * dy || 1);

              return (
                <path
                  key={`edge-${idx}`}
                  d={`M ${sourcePos.x} ${sourcePos.y} Q ${controlX} ${controlY} ${targetPos.x} ${targetPos.y}`}
                  fill="none"
                  stroke={getEdgeColor(edge)}
                  strokeWidth={selectedPath === edge.pathIndex ? 3 : 2}
                  strokeOpacity={selectedPath === null || selectedPath === edge.pathIndex ? 0.8 : 0.3}
                  markerEnd={`url(#arrowhead-${edge.severity === "critical" ? "critical" : edge.severity === "high" ? "high" : ""})`}
                  className="transition-all duration-300"
                />
              );
            })}
        </g>

        {/* Render nodes */}
        <g>
          {nodes
            .filter((n) => selectedPath === null || n.pathIndex === selectedPath)
            .map((node) => {
              const pos = positions[node.id];
              if (!pos) return null;

              const isHovered = hoveredNode === node.id;
              const radius = isHovered ? 30 : 25;

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={() => onNodeClick?.(node)}
                  onMouseEnter={() => setHoveredNode(node.id)}
                  onMouseLeave={() => setHoveredNode(null)}
                  className="cursor-pointer"
                >
                  {/* Node circle */}
                  <circle
                    r={radius}
                    fill={getNodeColor(node)}
                    stroke={isDarkMode ? "#1f2937" : "#ffffff"}
                    strokeWidth={3}
                    className="transition-all duration-200"
                    opacity={selectedPath === null || node.pathIndex === selectedPath ? 1 : 0.4}
                  />
                  
                  {/* Node icon based on type */}
                  <text
                    textAnchor="middle"
                    dominantBaseline="central"
                    fill="white"
                    fontSize={isHovered ? 14 : 12}
                    fontWeight="bold"
                  >
                    {node.isSource ? "⚡" : node.isTarget ? "🎯" : "☁️"}
                  </text>

                  {/* Node label */}
                  <text
                    y={radius + 15}
                    textAnchor="middle"
                    fill={isDarkMode ? "#d1d5db" : "#374151"}
                    fontSize={11}
                    className="pointer-events-none"
                  >
                    {node.label}
                  </text>
                </g>
              );
            })}
        </g>
      </svg>

      {/* Hover tooltip */}
      {hoveredNode && positions[hoveredNode] && (
        <div
          className={`absolute pointer-events-none z-20 px-3 py-2 rounded-lg shadow-lg text-sm ${
            isDarkMode ? "bg-gray-700 text-white" : "bg-white text-gray-900"
          }`}
          style={{
            left: positions[hoveredNode].x + 40,
            top: positions[hoveredNode].y - 20,
          }}
        >
          <p className="font-medium">{hoveredNode}</p>
          <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
            Click for details
          </p>
        </div>
      )}
    </div>
  );
};

export default AttackPathGraph;
