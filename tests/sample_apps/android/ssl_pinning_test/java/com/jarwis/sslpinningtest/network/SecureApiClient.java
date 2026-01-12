package com.jarwis.sslpinningtest.network;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Callback;
import okhttp3.Call;

/**
 * Secure API Client with SSL Certificate Pinning
 * Uses OkHttp CertificatePinner for enhanced security
 */
public class SecureApiClient {
    
    private static final String TAG = "SecureApiClient";
    private static final String BASE_URL = "https://api.jarwis.ai";
    
    // Certificate pins for api.jarwis.ai
    private static final String API_HOST = "api.jarwis.ai";
    private static final String PIN_SHA256_1 = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    private static final String PIN_SHA256_2 = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    
    private final OkHttpClient client;
    private final Context context;

    public SecureApiClient(Context context) {
        this.context = context;
        this.client = createSecureClient();
    }
    
    /**
     * Creates OkHttpClient with certificate pinning enabled
     */
    private OkHttpClient createSecureClient() {
        // Certificate Pinner - main security feature
        CertificatePinner certificatePinner = new CertificatePinner.Builder()
            .add(API_HOST, PIN_SHA256_1)
            .add(API_HOST, PIN_SHA256_2)
            // Backup pins for certificate rotation
            .add("secure.jarwis.ai", PIN_SHA256_1)
            .add("*.jarwis.ai", PIN_SHA256_2)
            .build();
        
        return new OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            // SECURITY: Disable redirects to prevent MITM redirects
            .followRedirects(false)
            .followSslRedirects(false)
            .build();
    }
    
    /**
     * Fetch data from secure API endpoint
     */
    public void fetchSecureData(final ApiCallback callback) {
        Request request = new Request.Builder()
            .url(BASE_URL + "/api/v1/data")
            .addHeader("Accept", "application/json")
            .addHeader("X-App-Version", "1.0.0")
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Request failed: " + e.getMessage());
                
                // Check if it's a certificate pinning failure
                if (e.getMessage() != null && 
                    e.getMessage().contains("Certificate pinning failure")) {
                    Log.w(TAG, "SSL Pinning validation failed - possible MITM attack!");
                }
                
                callback.onError(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    String body = response.body().string();
                    callback.onSuccess(body);
                } else {
                    callback.onError(new IOException("HTTP " + response.code()));
                }
            }
        });
    }
    
    /**
     * Post sensitive data securely
     * SECURITY ISSUE: Stores auth token in SharedPreferences without encryption
     */
    public void login(String username, String password, final ApiCallback callback) {
        // SECURITY ISSUE: Building credentials in memory
        String credentials = username + ":" + password;
        
        // SECURITY ISSUE: Logging credentials
        Log.d(TAG, "Attempting login for: " + username);
        
        Request request = new Request.Builder()
            .url(BASE_URL + "/api/v1/auth/login")
            .addHeader("Authorization", "Basic " + android.util.Base64.encodeToString(
                credentials.getBytes(), android.util.Base64.NO_WRAP))
            .post(okhttp3.RequestBody.create(null, new byte[0]))
            .build();
        
        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                callback.onError(e);
            }
            
            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    String token = response.header("X-Auth-Token");
                    // SECURITY ISSUE: Storing token insecurely
                    context.getSharedPreferences("auth", Context.MODE_PRIVATE)
                        .edit()
                        .putString("token", token)
                        .apply();
                    callback.onSuccess(token);
                } else {
                    callback.onError(new IOException("Login failed"));
                }
            }
        });
    }
    
    public interface ApiCallback {
        void onSuccess(String response);
        void onError(Exception e);
    }
}
