// src/services/paymentService.js
// Razorpay payment integration service

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

// Load Razorpay script dynamically
export const loadRazorpayScript = () => {
  return new Promise((resolve) => {
    if (window.Razorpay) {
      resolve(true);
      return;
    }
    
    const script = document.createElement("script");
    script.src = "https://checkout.razorpay.com/v1/checkout.js";
    script.onload = () => resolve(true);
    script.onerror = () => resolve(false);
    document.body.appendChild(script);
  });
};

// Get user's location/country
export const getUserCountry = async () => {
  try {
    // Use a free IP geolocation API
    const response = await fetch("https://ipapi.co/json/");
    if (response.ok) {
      const data = await response.json();
      return data.country_code || "IN";
    }
  } catch (error) {
    console.warn("Failed to get user location:", error);
  }
  return "IN"; // Default to India
};

// Get currency info based on country
export const getCurrencyInfo = async (countryCode) => {
  try {
    const response = await fetch(
      `${API_URL}/api/payments/currency-info?country_code=${countryCode}`
    );
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.error("Failed to get currency info:", error);
  }
  // Default fallback
  return {
    currency: "INR",
    symbol: "Rs.",
    plans: {
      individual: { amount: 100, display: "Rs.1" },
      professional: { amount: 200, display: "Rs.2" },
    },
  };
};

// Get payment configuration
export const getPaymentConfig = async () => {
  try {
    const response = await fetch(`${API_URL}/api/payments/config`);
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.error("Failed to get payment config:", error);
  }
  return null;
};

// Create Razorpay order
export const createPaymentOrder = async (plan, currency, token = null, email = null) => {
  try {
    const headers = {
      "Content-Type": "application/json",
    };
    
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${API_URL}/api/payments/create-order`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        plan,
        currency,
        email,
      }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Failed to create order");
    }
    
    return await response.json();
  } catch (error) {
    console.error("Create order error:", error);
    throw error;
  }
};

// Verify payment after completion
export const verifyPayment = async (paymentData, token = null) => {
  try {
    const headers = {
      "Content-Type": "application/json",
    };
    
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    
    const response = await fetch(`${API_URL}/api/payments/verify`, {
      method: "POST",
      headers,
      body: JSON.stringify(paymentData),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || "Payment verification failed");
    }
    
    return await response.json();
  } catch (error) {
    console.error("Verify payment error:", error);
    throw error;
  }
};

// Open Razorpay checkout
export const openRazorpayCheckout = async ({
  orderId,
  amount,
  currency,
  keyId,
  plan,
  userEmail,
  userName,
  onSuccess,
  onError,
  onClose,
}) => {
  const scriptLoaded = await loadRazorpayScript();
  if (!scriptLoaded) {
    onError?.(new Error("Failed to load Razorpay SDK"));
    return;
  }
  
  const options = {
    key: keyId,
    amount: amount,
    currency: currency,
    name: "Jarwis AGI Security",
    description: `${plan.charAt(0).toUpperCase() + plan.slice(1)} Plan Subscription`,
    image: "/jarwis-logo.png", // Update with actual logo path
    order_id: orderId,
    prefill: {
      email: userEmail || "",
      name: userName || "",
    },
    notes: {
      plan: plan,
    },
    theme: {
      color: "#0ea5e9", // Cyan color to match Jarwis branding
      backdrop_color: "rgba(0, 0, 0, 0.8)",
    },
    handler: function (response) {
      // Payment successful
      onSuccess?.({
        razorpay_order_id: response.razorpay_order_id,
        razorpay_payment_id: response.razorpay_payment_id,
        razorpay_signature: response.razorpay_signature,
        plan: plan,
      });
    },
    modal: {
      ondismiss: function () {
        onClose?.();
      },
      escape: true,
      animation: true,
    },
  };
  
  const razorpay = new window.Razorpay(options);
  
  razorpay.on("payment.failed", function (response) {
    onError?.(new Error(response.error.description || "Payment failed"));
  });
  
  razorpay.open();
};

// Full payment flow
export const initiatePayment = async ({
  plan,
  currency,
  token,
  email,
  userName,
  onSuccess,
  onError,
  onClose,
}) => {
  try {
    // Create order
    const order = await createPaymentOrder(plan, currency, token, email);
    
    // Open checkout
    await openRazorpayCheckout({
      orderId: order.order_id,
      amount: order.amount,
      currency: order.currency,
      keyId: order.key_id,
      plan: order.plan,
      userEmail: order.user_email || email,
      userName,
      onSuccess: async (paymentResponse) => {
        try {
          // Verify payment
          const verification = await verifyPayment(
            {
              ...paymentResponse,
              email,
            },
            token
          );
          
          onSuccess?.(verification);
        } catch (error) {
          onError?.(error);
        }
      },
      onError,
      onClose,
    });
  } catch (error) {
    onError?.(error);
  }
};

export default {
  loadRazorpayScript,
  getUserCountry,
  getCurrencyInfo,
  getPaymentConfig,
  createPaymentOrder,
  verifyPayment,
  openRazorpayCheckout,
  initiatePayment,
};
