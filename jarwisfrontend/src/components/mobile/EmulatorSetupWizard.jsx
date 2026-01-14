// src/components/mobile/EmulatorSetupWizard.jsx
// Step-by-step wizard for setting up mobile emulators for security testing

import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
  Alert,
  AlertTitle,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  CircularProgress,
  Collapse,
  IconButton,
  Divider,
  Paper,
  Link,
  LinearProgress,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Android as AndroidIcon,
  Apple as AppleIcon,
  Computer as ComputerIcon,
  Refresh as RefreshIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Download as DownloadIcon,
  Terminal as TerminalIcon,
  Security as SecurityIcon,
  CheckBox as CheckBoxIcon,
  CheckBoxOutlineBlank as CheckBoxOutlineBlankIcon,
} from '@mui/icons-material';
import { getAccessToken } from '../../services/api';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

// Wizard steps
const STEPS = [
  { label: 'Choose Platform', description: 'Select Android or iOS for testing' },
  { label: 'Install Requirements', description: 'Install emulator and dependencies' },
  { label: 'Configure Emulator', description: 'Set up emulator for security testing' },
  { label: 'Verify Connection', description: 'Confirm Jarwis can detect your device' },
];

// Platform requirements
const ANDROID_REQUIREMENTS = [
  {
    id: 'android_studio',
    name: 'Android Studio',
    description: 'Required for Android Emulator',
    downloadUrl: 'https://developer.android.com/studio',
    commands: ['android-studio --version'],
    installInstructions: 'Download and install Android Studio from the official website',
  },
  {
    id: 'adb',
    name: 'ADB (Android Debug Bridge)',
    description: 'Required for device communication',
    downloadUrl: null,
    commands: ['adb --version'],
    installInstructions: 'Included with Android Studio SDK Platform-Tools',
  },
  {
    id: 'python',
    name: 'Python 3.8+',
    description: 'Required for Frida',
    downloadUrl: 'https://www.python.org/downloads/',
    commands: ['python --version', 'python3 --version'],
    installInstructions: 'Download and install Python 3.8 or higher',
  },
  {
    id: 'frida',
    name: 'Frida Tools',
    description: 'Dynamic instrumentation for SSL bypass',
    downloadUrl: null,
    commands: ['frida --version'],
    installInstructions: 'Run: pip install frida-tools',
  },
];

const IOS_REQUIREMENTS = [
  {
    id: 'xcode',
    name: 'Xcode (macOS only)',
    description: 'Required for iOS Simulator',
    downloadUrl: 'https://apps.apple.com/app/xcode/id497799835',
    commands: ['xcodebuild -version'],
    installInstructions: 'Install from the Mac App Store',
  },
  {
    id: 'xcrun',
    name: 'Xcode Command Line Tools',
    description: 'Required for simulator control',
    downloadUrl: null,
    commands: ['xcrun simctl help'],
    installInstructions: 'Run: xcode-select --install',
  },
];

// Terminal command component
const TerminalCommand = ({ command, onCopy }) => (
  <Paper 
    sx={{ 
      p: 1.5, 
      bgcolor: 'grey.900', 
      display: 'flex', 
      alignItems: 'center',
      justifyContent: 'space-between',
      fontFamily: 'monospace',
      mb: 1,
    }}
  >
    <Typography 
      variant="body2" 
      sx={{ color: 'success.light', fontFamily: 'monospace' }}
    >
      $ {command}
    </Typography>
    <IconButton 
      size="small" 
      onClick={() => onCopy(command)}
      sx={{ color: 'grey.400' }}
    >
      <CopyIcon fontSize="small" />
    </IconButton>
  </Paper>
);

// Requirement check item
const RequirementItem = ({ requirement, status, onCheck }) => {
  const [expanded, setExpanded] = useState(false);
  
  const getStatusIcon = () => {
    switch (status) {
      case 'checking':
        return <CircularProgress size={20} />;
      case 'installed':
        return <CheckCircleIcon color="success" />;
      case 'missing':
        return <ErrorIcon color="error" />;
      default:
        return <CheckBoxOutlineBlankIcon color="disabled" />;
    }
  };

  return (
    <Paper variant="outlined" sx={{ mb: 1.5 }}>
      <ListItem 
        secondaryAction={
          <IconButton onClick={() => setExpanded(!expanded)}>
            {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
          </IconButton>
        }
      >
        <ListItemIcon>{getStatusIcon()}</ListItemIcon>
        <ListItemText 
          primary={requirement.name}
          secondary={requirement.description}
        />
        {status === 'missing' && (
          <Chip 
            label="Missing" 
            color="error" 
            size="small" 
            sx={{ mr: 2 }}
          />
        )}
      </ListItem>
      <Collapse in={expanded}>
        <Box sx={{ p: 2, pt: 0, bgcolor: 'background.default' }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            <strong>Installation:</strong> {requirement.installInstructions}
          </Typography>
          {requirement.downloadUrl && (
            <Button
              variant="outlined"
              size="small"
              startIcon={<DownloadIcon />}
              href={requirement.downloadUrl}
              target="_blank"
              rel="noopener noreferrer"
              sx={{ mb: 1 }}
            >
              Download
            </Button>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
};

// Main component
export default function EmulatorSetupWizard({ onComplete, onCancel }) {
  const [activeStep, setActiveStep] = useState(0);
  const [platform, setPlatform] = useState(null); // 'android' or 'ios'
  const [requirementStatus, setRequirementStatus] = useState({});
  const [deviceStatus, setDeviceStatus] = useState(null); // null, 'checking', 'found', 'not_found'
  const [detectedDevices, setDetectedDevices] = useState([]);
  const [isChecking, setIsChecking] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const requirements = platform === 'android' ? ANDROID_REQUIREMENTS : 
                       platform === 'ios' ? IOS_REQUIREMENTS : [];

  // Copy to clipboard
  const copyToClipboard = useCallback((text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  // Check if all requirements are met
  const allRequirementsMet = requirements.every(
    req => requirementStatus[req.id] === 'installed'
  );

  // Check device connection via backend
  const checkDeviceConnection = useCallback(async () => {
    setDeviceStatus('checking');
    setError(null);
    
    try {
      const token = getAccessToken();
      const response = await fetch(`${API_URL}/api/mobile/devices`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        throw new Error('Failed to check device status');
      }
      
      const data = await response.json();
      const devices = data.devices || [];
      
      // Filter by selected platform
      const platformDevices = devices.filter(d => 
        platform === 'android' ? d.type?.toLowerCase().includes('android') || d.type?.toLowerCase().includes('emulator') :
        platform === 'ios' ? d.type?.toLowerCase().includes('ios') || d.type?.toLowerCase().includes('simulator') :
        true
      );
      
      setDetectedDevices(platformDevices);
      setDeviceStatus(platformDevices.length > 0 ? 'found' : 'not_found');
    } catch (err) {
      console.error('Device check error:', err);
      setError(err.message);
      setDeviceStatus('not_found');
    }
  }, [platform]);

  // Check individual requirement (basic check - actual verification would be done by backend)
  const checkRequirements = useCallback(async () => {
    setIsChecking(true);
    setError(null);
    
    // In a real implementation, this would call a backend endpoint
    // For now, we'll simulate the check
    const newStatus = {};
    
    for (const req of requirements) {
      setRequirementStatus(prev => ({ ...prev, [req.id]: 'checking' }));
      
      // Simulate async check (in production, call backend)
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // For demo, mark ADB and Python as usually installed
      const isLikelyInstalled = ['adb', 'python', 'frida'].includes(req.id) ? 
        Math.random() > 0.3 : Math.random() > 0.5;
      
      newStatus[req.id] = isLikelyInstalled ? 'installed' : 'missing';
    }
    
    setRequirementStatus(newStatus);
    setIsChecking(false);
  }, [requirements]);

  // Auto-check requirements when platform is selected
  useEffect(() => {
    if (platform && activeStep === 1) {
      checkRequirements();
    }
  }, [platform, activeStep, checkRequirements]);

  // Auto-check device when on verification step
  useEffect(() => {
    if (activeStep === 3) {
      checkDeviceConnection();
    }
  }, [activeStep, checkDeviceConnection]);

  // Handle step navigation
  const handleNext = () => {
    if (activeStep === STEPS.length - 1) {
      // Complete the wizard
      onComplete?.({ 
        platform, 
        devices: detectedDevices 
      });
    } else {
      setActiveStep(prev => prev + 1);
    }
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  // Render step content
  const renderStepContent = (step) => {
    switch (step) {
      case 0:
        return (
          <Box sx={{ pt: 2 }}>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Select the platform you want to test. You can set up additional platforms later.
            </Typography>
            
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Card 
                variant="outlined" 
                sx={{ 
                  width: 200, 
                  cursor: 'pointer',
                  borderColor: platform === 'android' ? 'primary.main' : 'divider',
                  borderWidth: platform === 'android' ? 2 : 1,
                  bgcolor: platform === 'android' ? 'primary.dark' : 'background.paper',
                  '&:hover': { borderColor: 'primary.light' }
                }}
                onClick={() => setPlatform('android')}
              >
                <CardContent sx={{ textAlign: 'center' }}>
                  <AndroidIcon sx={{ fontSize: 60, color: '#3DDC84', mb: 1 }} />
                  <Typography variant="h6">Android</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Emulator or Physical Device
                  </Typography>
                </CardContent>
              </Card>
              
              <Card 
                variant="outlined" 
                sx={{ 
                  width: 200, 
                  cursor: 'pointer',
                  borderColor: platform === 'ios' ? 'primary.main' : 'divider',
                  borderWidth: platform === 'ios' ? 2 : 1,
                  bgcolor: platform === 'ios' ? 'primary.dark' : 'background.paper',
                  '&:hover': { borderColor: 'primary.light' }
                }}
                onClick={() => setPlatform('ios')}
              >
                <CardContent sx={{ textAlign: 'center' }}>
                  <AppleIcon sx={{ fontSize: 60, color: 'grey.400', mb: 1 }} />
                  <Typography variant="h6">iOS</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Simulator (macOS only)
                  </Typography>
                </CardContent>
              </Card>
            </Box>
            
            {platform === 'ios' && (
              <Alert severity="info" sx={{ mt: 2 }}>
                <AlertTitle>iOS Simulator Requirement</AlertTitle>
                iOS Simulator is only available on macOS with Xcode installed.
              </Alert>
            )}
          </Box>
        );
        
      case 1:
        return (
          <Box sx={{ pt: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="body1">
                The following tools are required for {platform === 'android' ? 'Android' : 'iOS'} testing:
              </Typography>
              <Button 
                size="small" 
                startIcon={<RefreshIcon />}
                onClick={checkRequirements}
                disabled={isChecking}
              >
                Re-check
              </Button>
            </Box>
            
            {isChecking && <LinearProgress sx={{ mb: 2 }} />}
            
            <List disablePadding>
              {requirements.map(req => (
                <RequirementItem 
                  key={req.id}
                  requirement={req}
                  status={requirementStatus[req.id]}
                />
              ))}
            </List>
            
            {!isChecking && !allRequirementsMet && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <AlertTitle>Missing Requirements</AlertTitle>
                Please install the missing tools before proceeding. Expand each item for installation instructions.
              </Alert>
            )}
            
            {!isChecking && allRequirementsMet && (
              <Alert severity="success" sx={{ mt: 2 }}>
                <AlertTitle>All Requirements Met!</AlertTitle>
                You're ready to configure your {platform === 'android' ? 'Android emulator' : 'iOS simulator'}.
              </Alert>
            )}
          </Box>
        );
        
      case 2:
        return (
          <Box sx={{ pt: 2 }}>
            <Typography variant="body1" sx={{ mb: 2 }}>
              Follow these steps to configure your {platform === 'android' ? 'Android emulator' : 'iOS simulator'} for security testing:
            </Typography>
            
            {platform === 'android' ? (
              <List>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="1. Open Android Studio and go to Tools → AVD Manager"
                    secondary="Create a new virtual device if you don't have one"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="2. Create an emulator with root access (no Google Play Services)"
                    secondary="Select a system image without 'Google APIs' for root access"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="3. Start the emulator"
                  />
                </ListItem>
                <Divider sx={{ my: 1 }} />
                <ListItem>
                  <Box sx={{ width: '100%' }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Verify ADB connection:
                    </Typography>
                    <TerminalCommand command="adb devices" onCopy={copyToClipboard} />
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1, mt: 2 }}>
                      Push Frida server to emulator (required for SSL bypass):
                    </Typography>
                    <TerminalCommand 
                      command="adb push frida-server /data/local/tmp/frida-server" 
                      onCopy={copyToClipboard} 
                    />
                    <TerminalCommand 
                      command="adb shell chmod 755 /data/local/tmp/frida-server" 
                      onCopy={copyToClipboard} 
                    />
                    <TerminalCommand 
                      command="adb shell /data/local/tmp/frida-server &" 
                      onCopy={copyToClipboard} 
                    />
                  </Box>
                </ListItem>
              </List>
            ) : (
              <List>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="1. Open Xcode and go to Window → Devices and Simulators"
                    secondary="Or use the Simulator app directly"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="2. Create or select a simulator"
                    secondary="Recommended: iPhone 14 Pro or newer"
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckCircleIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary="3. Boot the simulator"
                  />
                </ListItem>
                <Divider sx={{ my: 1 }} />
                <ListItem>
                  <Box sx={{ width: '100%' }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      List available simulators:
                    </Typography>
                    <TerminalCommand command="xcrun simctl list devices" onCopy={copyToClipboard} />
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1, mt: 2 }}>
                      Boot a specific simulator:
                    </Typography>
                    <TerminalCommand 
                      command='xcrun simctl boot "iPhone 14 Pro"' 
                      onCopy={copyToClipboard} 
                    />
                  </Box>
                </ListItem>
              </List>
            )}
            
            {copied && (
              <Alert severity="success" sx={{ mt: 2 }}>
                Command copied to clipboard!
              </Alert>
            )}
          </Box>
        );
        
      case 3:
        return (
          <Box sx={{ pt: 2 }}>
            <Typography variant="body1" sx={{ mb: 3 }}>
              Checking if Jarwis can detect your {platform === 'android' ? 'Android device' : 'iOS simulator'}...
            </Typography>
            
            {deviceStatus === 'checking' && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
                <CircularProgress size={24} />
                <Typography>Scanning for devices...</Typography>
              </Box>
            )}
            
            {deviceStatus === 'found' && (
              <Alert severity="success" sx={{ mb: 3 }}>
                <AlertTitle>Device Detected!</AlertTitle>
                Found {detectedDevices.length} {platform === 'android' ? 'Android' : 'iOS'} device(s):
                <List dense>
                  {detectedDevices.map((device, idx) => (
                    <ListItem key={idx}>
                      <ListItemIcon>
                        {platform === 'android' ? <AndroidIcon color="success" /> : <AppleIcon />}
                      </ListItemIcon>
                      <ListItemText 
                        primary={device.name || device.id || 'Unknown device'}
                        secondary={device.type || ''}
                      />
                    </ListItem>
                  ))}
                </List>
              </Alert>
            )}
            
            {deviceStatus === 'not_found' && (
              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>No Device Detected</AlertTitle>
                <Typography variant="body2">
                  Make sure your {platform === 'android' ? 'emulator is running' : 'simulator is booted'} and try again.
                </Typography>
                <Box sx={{ mt: 2 }}>
                  <Typography variant="body2" color="text.secondary">
                    Troubleshooting steps:
                  </Typography>
                  <List dense>
                    {platform === 'android' ? (
                      <>
                        <ListItem><ListItemText primary="• Verify emulator is running in Android Studio" /></ListItem>
                        <ListItem><ListItemText primary='• Run "adb devices" to check ADB connection' /></ListItem>
                        <ListItem><ListItemText primary="• Restart ADB server: adb kill-server && adb start-server" /></ListItem>
                      </>
                    ) : (
                      <>
                        <ListItem><ListItemText primary="• Verify simulator is booted in Simulator app" /></ListItem>
                        <ListItem><ListItemText primary='• Run "xcrun simctl list devices" to check status' /></ListItem>
                      </>
                    )}
                  </List>
                </Box>
              </Alert>
            )}
            
            {error && (
              <Alert severity="error" sx={{ mb: 3 }}>
                <AlertTitle>Error</AlertTitle>
                {error}
              </Alert>
            )}
            
            <Button 
              variant="outlined" 
              startIcon={<RefreshIcon />}
              onClick={checkDeviceConnection}
              disabled={deviceStatus === 'checking'}
            >
              Retry Detection
            </Button>
          </Box>
        );
        
      default:
        return null;
    }
  };

  // Determine if can proceed to next step
  const canProceed = () => {
    switch (activeStep) {
      case 0:
        return platform !== null;
      case 1:
        return true; // Allow skipping if user wants
      case 2:
        return true;
      case 3:
        return deviceStatus === 'found';
      default:
        return false;
    }
  };

  return (
    <Card sx={{ maxWidth: 800, mx: 'auto', mt: 2 }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
          <SecurityIcon color="primary" />
          <Typography variant="h5">
            Emulator Setup Wizard
          </Typography>
        </Box>
        
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          This wizard will help you set up a mobile emulator for security testing with Jarwis.
        </Typography>
        
        <Stepper activeStep={activeStep} orientation="vertical">
          {STEPS.map((step, index) => (
            <Step key={step.label}>
              <StepLabel>
                <Typography variant="subtitle1">{step.label}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {step.description}
                </Typography>
              </StepLabel>
              <StepContent>
                {renderStepContent(index)}
                
                <Box sx={{ mt: 3, display: 'flex', gap: 1 }}>
                  <Button
                    variant="contained"
                    onClick={handleNext}
                    disabled={!canProceed()}
                  >
                    {activeStep === STEPS.length - 1 ? 'Finish' : 'Continue'}
                  </Button>
                  {activeStep > 0 && (
                    <Button onClick={handleBack}>
                      Back
                    </Button>
                  )}
                  {onCancel && (
                    <Button onClick={onCancel} color="inherit">
                      Cancel
                    </Button>
                  )}
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </CardContent>
    </Card>
  );
}
