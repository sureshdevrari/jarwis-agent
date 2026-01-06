import React, { useState, useEffect, useRef } from 'react';
import './OTPModal.css';

const OTPModal = ({ 
  isOpen, 
  onSubmit, 
  onCancel, 
  onResend,
  phoneNumber = '',
  timeoutSeconds = 60,
  otpLength = 6,
  canResend = true,
  resendCooldown = 30 
}) => {
  const [otp, setOtp] = useState(new Array(otpLength).fill(''));
  const [timeLeft, setTimeLeft] = useState(timeoutSeconds);
  const [resendTimer, setResendTimer] = useState(0);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState('');
  const inputRefs = useRef([]);

  // Timer countdown
  useEffect(() => {
    if (!isOpen) return;
    
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [timeLeft, isOpen]);

  // Resend cooldown timer
  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      setOtp(new Array(otpLength).fill(''));
      setTimeLeft(timeoutSeconds);
      setResendTimer(0);
      setIsVerifying(false);
      setError('');
      // Focus first input
      setTimeout(() => inputRefs.current[0]?.focus(), 100);
    }
  }, [isOpen, otpLength, timeoutSeconds]);

  const handleChange = (element, index) => {
    if (isNaN(element.value)) return;

    const newOtp = [...otp];
    newOtp[index] = element.value;
    setOtp(newOtp);
    setError('');

    // Auto-focus next input
    if (element.value && index < otpLength - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (e, index) => {
    // Handle backspace
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    // Handle paste
    if (e.key === 'v' && (e.ctrlKey || e.metaKey)) {
      e.preventDefault();
      handlePaste(e);
    }
  };

  const handlePaste = async (e) => {
    const pastedData = e.clipboardData?.getData('text') || 
                       await navigator.clipboard?.readText();
    
    if (pastedData) {
      const digits = pastedData.replace(/\D/g, '').slice(0, otpLength);
      if (digits.length > 0) {
        const newOtp = [...otp];
        digits.split('').forEach((digit, i) => {
          if (i < otpLength) newOtp[i] = digit;
        });
        setOtp(newOtp);
        setError('');
        // Focus last filled input or next empty
        const lastIndex = Math.min(digits.length - 1, otpLength - 1);
        inputRefs.current[lastIndex]?.focus();
      }
    }
  };

  const handleSubmit = async () => {
    const otpValue = otp.join('');
    
    if (otpValue.length !== otpLength) {
      setError('Please enter the complete OTP');
      return;
    }

    setIsVerifying(true);
    setError('');

    try {
      await onSubmit(otpValue);
    } catch (err) {
      setError(err.message || 'OTP verification failed. Please try again.');
      setOtp(new Array(otpLength).fill(''));
      inputRefs.current[0]?.focus();
    } finally {
      setIsVerifying(false);
    }
  };

  const handleResend = async () => {
    if (resendTimer > 0 || !canResend) return;
    
    setResendTimer(resendCooldown);
    setTimeLeft(timeoutSeconds);
    setOtp(new Array(otpLength).fill(''));
    setError('');
    
    try {
      await onResend();
    } catch (err) {
      setError('Failed to resend OTP. Please try again.');
    }
  };

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const maskedPhone = phoneNumber 
    ? phoneNumber.replace(/(\d{3})\d+(\d{2})/, '$1****$2')
    : '';

  if (!isOpen) return null;

  return (
    <div className="otp-modal-overlay" onClick={onCancel}>
      <div className="otp-modal" onClick={(e) => e.stopPropagation()}>
        <div className="otp-modal-header">
          <div className="otp-lock-icon">🔐</div>
          <h2>Secure Authentication Required</h2>
          <button className="otp-close-btn" onClick={onCancel}>✕</button>
        </div>

        <div className="otp-modal-body">
          <p className="otp-instruction">
            To continue testing, please enter the OTP sent to your registered mobile number
            {maskedPhone && <span className="otp-phone"> ({maskedPhone})</span>}.
          </p>

          <div className="otp-input-container">
            {otp.map((digit, index) => (
              <input
                key={index}
                type="text"
                maxLength="1"
                className={`otp-input ${digit ? 'filled' : ''} ${error ? 'error' : ''}`}
                value={digit}
                onChange={(e) => handleChange(e.target, index)}
                onKeyDown={(e) => handleKeyDown(e, index)}
                onPaste={handlePaste}
                ref={(el) => (inputRefs.current[index] = el)}
                disabled={isVerifying || timeLeft === 0}
                inputMode="numeric"
                autoComplete="one-time-code"
              />
            ))}
          </div>

          {error && <div className="otp-error">{error}</div>}

          <div className="otp-timer">
            {timeLeft > 0 ? (
              <>
                <span className="timer-icon">⏱️</span>
                <span>OTP expires in <strong>{formatTime(timeLeft)}</strong></span>
              </>
            ) : (
              <span className="timer-expired">⚠️ OTP has expired</span>
            )}
          </div>

          <div className="otp-security-notice">
            <span className="lock-icon">🔒</span>
            <span>Your OTP is encrypted in transit and never stored.</span>
          </div>
        </div>

        <div className="otp-modal-footer">
          <div className="otp-resend">
            {canResend && (
              resendTimer > 0 ? (
                <span className="resend-cooldown">Resend OTP in {resendTimer}s</span>
              ) : (
                <button 
                  className="resend-btn" 
                  onClick={handleResend}
                  disabled={isVerifying}
                >
                  Didn't receive OTP? Resend
                </button>
              )
            )}
          </div>

          <div className="otp-actions">
            <button 
              className="otp-cancel-btn" 
              onClick={onCancel}
              disabled={isVerifying}
            >
              Cancel
            </button>
            <button 
              className="otp-submit-btn" 
              onClick={handleSubmit}
              disabled={isVerifying || otp.join('').length !== otpLength || timeLeft === 0}
            >
              {isVerifying ? (
                <>
                  <span className="spinner"></span>
                  Verifying...
                </>
              ) : (
                'Verify & Start Testing'
              )}
            </button>
          </div>
        </div>

        <div className="otp-disclaimer">
          <p>
            Jarwis does not store, log, or reuse your OTP. The OTP is used only once 
            to authenticate and begin security testing. Your privacy and data security 
            are our top priority.
          </p>
        </div>
      </div>
    </div>
  );
};

export default OTPModal;
