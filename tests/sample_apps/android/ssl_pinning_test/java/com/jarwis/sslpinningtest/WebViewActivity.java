package com.jarwis.sslpinningtest;

import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.JavascriptInterface;
import android.util.Log;
import android.content.Intent;

/**
 * WebView Activity with multiple security vulnerabilities
 * This class is intentionally vulnerable for Jarwis testing
 */
public class WebViewActivity extends Activity {
    
    private static final String TAG = "WebViewActivity";
    private WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        webView = new WebView(this);
        setContentView(webView);
        
        // Configure WebView with INSECURE settings
        configureWebView();
        
        // Load URL from intent (potentially malicious)
        Intent intent = getIntent();
        if (intent != null && intent.getData() != null) {
            // SECURITY ISSUE: Loading untrusted URL
            String url = intent.getData().toString();
            webView.loadUrl(url);
        } else {
            webView.loadUrl("https://jarwis.ai");
        }
    }
    
    /**
     * INSECURE WebView configuration
     * Multiple security vulnerabilities intentionally introduced
     */
    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        
        // SECURITY ISSUE: JavaScript enabled without proper controls
        settings.setJavaScriptEnabled(true);
        
        // SECURITY ISSUE: Allows file access from WebView
        settings.setAllowFileAccess(true);
        
        // SECURITY ISSUE: Allows file access from file URLs (critical!)
        settings.setAllowFileAccessFromFileURLs(true);
        
        // SECURITY ISSUE: Allows universal access from file URLs (critical!)
        settings.setAllowUniversalAccessFromFileURLs(true);
        
        // SECURITY ISSUE: Enables DOM storage which can be abused
        settings.setDomStorageEnabled(true);
        
        // SECURITY ISSUE: Allows content access
        settings.setAllowContentAccess(true);
        
        // SECURITY ISSUE: Enables mixed content (HTTP in HTTPS pages)
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        
        // SECURITY ISSUE: WebView debugging in production
        WebView.setWebContentsDebuggingEnabled(true);
        
        // SECURITY ISSUE: Adding JavaScript interface (RCE on old Android)
        webView.addJavascriptInterface(new WebAppInterface(), "AndroidBridge");
        
        // SECURITY ISSUE: Insecure WebViewClient
        webView.setWebViewClient(new InsecureWebViewClient());
    }
    
    /**
     * JavaScript Interface - potential for abuse
     * Exposes native Android functionality to JavaScript
     */
    public class WebAppInterface {
        
        @JavascriptInterface
        public String getDeviceId() {
            // SECURITY ISSUE: Exposing device ID to JavaScript
            return android.provider.Settings.Secure.getString(
                getContentResolver(),
                android.provider.Settings.Secure.ANDROID_ID
            );
        }
        
        @JavascriptInterface
        public String getAuthToken() {
            // SECURITY ISSUE: Exposing auth token to JavaScript
            return getSharedPreferences("auth", MODE_PRIVATE)
                .getString("token", "");
        }
        
        @JavascriptInterface
        public void executeCommand(String command) {
            // SECURITY ISSUE: Arbitrary command execution!
            try {
                Runtime.getRuntime().exec(command);
                Log.d(TAG, "Executed command: " + command);
            } catch (Exception e) {
                Log.e(TAG, "Command failed: " + e.getMessage());
            }
        }
        
        @JavascriptInterface
        public String readFile(String path) {
            // SECURITY ISSUE: Arbitrary file read!
            try {
                java.io.File file = new java.io.File(path);
                java.util.Scanner scanner = new java.util.Scanner(file);
                StringBuilder content = new StringBuilder();
                while (scanner.hasNextLine()) {
                    content.append(scanner.nextLine()).append("\n");
                }
                scanner.close();
                return content.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
        
        @JavascriptInterface
        public void sendSMS(String number, String message) {
            // SECURITY ISSUE: Sending SMS without permission check
            try {
                android.telephony.SmsManager sms = android.telephony.SmsManager.getDefault();
                sms.sendTextMessage(number, null, message, null, null);
            } catch (Exception e) {
                Log.e(TAG, "SMS failed: " + e.getMessage());
            }
        }
    }
    
    /**
     * Insecure WebViewClient that accepts all certificates
     */
    private class InsecureWebViewClient extends WebViewClient {
        
        @Override
        public void onReceivedSslError(WebView view, android.webkit.SslErrorHandler handler,
                                       android.net.http.SslError error) {
            // SECURITY ISSUE: Ignoring SSL errors!
            // This completely defeats the purpose of HTTPS
            handler.proceed();
            Log.w(TAG, "Ignoring SSL error: " + error.toString());
        }
        
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            // SECURITY ISSUE: No URL validation
            // Allows navigation to any URL including malicious ones
            Log.d(TAG, "Loading URL: " + url);
            view.loadUrl(url);
            return true;
        }
    }
    
    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
