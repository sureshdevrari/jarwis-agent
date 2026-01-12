// Security-specific icon components and utilities
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert,
  Lock,
  Bug,
  AlertTriangle,
  AlertCircle,
  XCircle,
  CheckCircle,
  Globe,
  Smartphone,
  Server,
  Cloud,
  Code,
  Database,
  Network,
  Wifi,
  Key,
  FileCode,
  Terminal,
  Eye,
  Fingerprint,
} from 'lucide-react';

// Vulnerability severity icons
export const VulnerabilityIcon = ({ severity, size = 'w-5 h-5', className = '' }) => {
  const config = {
    critical: { icon: XCircle, color: 'text-red-500', bg: 'bg-red-500/20' },
    high: { icon: AlertCircle, color: 'text-orange-500', bg: 'bg-orange-500/20' },
    medium: { icon: AlertTriangle, color: 'text-amber-500', bg: 'bg-amber-500/20' },
    low: { icon: ShieldAlert, color: 'text-yellow-500', bg: 'bg-yellow-500/20' },
    info: { icon: Shield, color: 'text-blue-500', bg: 'bg-blue-500/20' },
  };

  const { icon: Icon, color, bg } = config[severity?.toLowerCase()] || config.info;

  return (
    <div className={`${bg} ${color} p-1.5 rounded-lg inline-flex ${className}`}>
      <Icon className={size} />
    </div>
  );
};

// Scan type icons
export const ScanTypeIcon = ({ type, size = 'w-5 h-5', className = '' }) => {
  const icons = {
    web: Globe,
    mobile: Smartphone,
    network: Network,
    cloud: Cloud,
    sast: FileCode,
    api: Server,
    infrastructure: Database,
    authentication: Key,
    code: Code,
    terminal: Terminal,
    reconnaissance: Eye,
    identity: Fingerprint,
  };

  const Icon = icons[type?.toLowerCase()] || Shield;

  return <Icon className={`${size} ${className}`} />;
};

// Security status icons
export const SecurityIcons = {
  // Status indicators
  Secure: (props) => <ShieldCheck className="text-emerald-400" {...props} />,
  Warning: (props) => <ShieldAlert className="text-amber-400" {...props} />,
  Critical: (props) => <XCircle className="text-red-400" {...props} />,
  Protected: (props) => <Lock className="text-cyan-400" {...props} />,
  
  // Scan types
  WebScan: (props) => <Globe className="text-blue-400" {...props} />,
  MobileScan: (props) => <Smartphone className="text-violet-400" {...props} />,
  NetworkScan: (props) => <Wifi className="text-cyan-400" {...props} />,
  CloudScan: (props) => <Cloud className="text-sky-400" {...props} />,
  CodeScan: (props) => <Code className="text-emerald-400" {...props} />,
  
  // Vulnerability types
  Vulnerability: (props) => <Bug className="text-red-400" {...props} />,
  Fixed: (props) => <CheckCircle className="text-emerald-400" {...props} />,
};

// Security badge component
export const SecurityBadge = ({ 
  status = 'secure', 
  label, 
  size = 'sm',
  className = '' 
}) => {
  const config = {
    secure: { 
      icon: ShieldCheck, 
      color: 'text-emerald-400', 
      bg: 'bg-emerald-500/10', 
      border: 'border-emerald-500/30',
      defaultLabel: 'Secure'
    },
    warning: { 
      icon: ShieldAlert, 
      color: 'text-amber-400', 
      bg: 'bg-amber-500/10', 
      border: 'border-amber-500/30',
      defaultLabel: 'Warning'
    },
    critical: { 
      icon: XCircle, 
      color: 'text-red-400', 
      bg: 'bg-red-500/10', 
      border: 'border-red-500/30',
      defaultLabel: 'Critical'
    },
    scanning: { 
      icon: Shield, 
      color: 'text-cyan-400', 
      bg: 'bg-cyan-500/10', 
      border: 'border-cyan-500/30',
      defaultLabel: 'Scanning'
    },
  };

  const { icon: Icon, color, bg, border, defaultLabel } = config[status] || config.secure;

  const sizes = {
    xs: 'px-2 py-0.5 text-xs gap-1',
    sm: 'px-2.5 py-1 text-sm gap-1.5',
    md: 'px-3 py-1.5 text-base gap-2',
  };

  const iconSizes = {
    xs: 'w-3 h-3',
    sm: 'w-4 h-4',
    md: 'w-5 h-5',
  };

  return (
    <span className={`
      inline-flex items-center ${sizes[size]}
      ${bg} ${border} border rounded-full
      font-medium ${color}
      ${className}
    `}>
      <Icon className={iconSizes[size]} />
      {label || defaultLabel}
    </span>
  );
};

export default SecurityIcons;
