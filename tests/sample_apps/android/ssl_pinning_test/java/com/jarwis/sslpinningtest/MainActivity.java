package com.jarwis.sslpinningtest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.jarwis.sslpinningtest.network.SecureApiClient;
import com.jarwis.sslpinningtest.security.RootDetector;

/**
 * Main Activity for SSL Pinning Test App
 * Demonstrates various security implementations for Jarwis testing
 */
public class MainActivity extends Activity {
    
    private static final String TAG = "JarwisSSLTest";
    
    // SECURITY ISSUE: Hardcoded API key - should be detected
    private static final String API_KEY = "sk_live_1234567890abcdef";
    private static final String SECRET_KEY = "super_secret_key_123";
    
    private SecureApiClient apiClient;
    private TextView statusTextView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        statusTextView = findViewById(R.id.statusText);
        
        // Initialize secure API client with certificate pinning
        apiClient = new SecureApiClient(this);
        
        // Check for root/emulator
        if (RootDetector.isDeviceRooted()) {
            Log.w(TAG, "Device appears to be rooted!");
            // In a real app, might want to restrict functionality
        }
        
        // Make a secure API call
        makeSecureRequest();
    }
    
    private void makeSecureRequest() {
        // SECURITY ISSUE: Logging sensitive data
        Log.d(TAG, "Using API key: " + API_KEY);
        
        apiClient.fetchSecureData(new SecureApiClient.ApiCallback() {
            @Override
            public void onSuccess(String response) {
                runOnUiThread(() -> {
                    statusTextView.setText("Connected securely!");
                });
            }
            
            @Override
            public void onError(Exception e) {
                Log.e(TAG, "API Error: " + e.getMessage());
                runOnUiThread(() -> {
                    statusTextView.setText("Connection failed: " + e.getMessage());
                });
            }
        });
    }
    
    // SECURITY ISSUE: Deep link handling without validation
    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        
        if (intent != null && intent.getData() != null) {
            String uri = intent.getData().toString();
            // No validation of deep link - potential injection
            handleDeepLink(uri);
        }
    }
    
    private void handleDeepLink(String uri) {
        // SECURITY ISSUE: No input validation
        Log.d(TAG, "Handling deep link: " + uri);
        
        // Potential for injection attacks
        if (uri.contains("redirect=")) {
            String redirect = uri.substring(uri.indexOf("redirect=") + 9);
            // Directly using untrusted input
            loadUrl(redirect);
        }
    }
    
    private void loadUrl(String url) {
        // WebView could be injected here
        Log.d(TAG, "Loading URL: " + url);
    }
}
