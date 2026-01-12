package com.jarwis.sslpinningtest.data;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * User Data Manager - demonstrates both secure and insecure patterns
 * Jarwis should detect the security issues in this class
 */
public class UserDataManager {
    
    private static final String TAG = "UserDataManager";
    
    // SECURITY ISSUE: Hardcoded encryption key
    private static final String ENCRYPTION_KEY = "MySecretKey12345";
    private static final String DATABASE_PASSWORD = "db_pass_123";
    
    // SECURITY ISSUE: Hardcoded API credentials
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
    private static final String AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String GOOGLE_API_KEY = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    
    private final Context context;
    private final SharedPreferences prefs;
    private final DatabaseHelper dbHelper;
    
    public UserDataManager(Context context) {
        this.context = context;
        
        // SECURITY ISSUE: MODE_WORLD_READABLE is deprecated and insecure
        // but still used in some legacy apps
        this.prefs = context.getSharedPreferences("user_data", Context.MODE_PRIVATE);
        this.dbHelper = new DatabaseHelper(context);
    }
    
    /**
     * Save user credentials - INSECURE
     */
    public void saveCredentials(String username, String password) {
        // SECURITY ISSUE: Storing password in plain text
        prefs.edit()
            .putString("username", username)
            .putString("password", password)  // NEVER do this!
            .putString("token", generateToken(username, password))
            .apply();
        
        // SECURITY ISSUE: Logging sensitive data
        Log.d(TAG, "Saved credentials for user: " + username);
        Log.d(TAG, "Password hash: " + password.hashCode());
    }
    
    /**
     * Save auth token - also insecure
     */
    public void saveAuthToken(String token) {
        // SECURITY ISSUE: Token stored without encryption
        prefs.edit()
            .putString("auth_token", token)
            .putLong("token_timestamp", System.currentTimeMillis())
            .apply();
    }
    
    /**
     * Store sensitive data in database - INSECURE
     */
    public void storeSensitiveData(String ssn, String creditCard, String cvv) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        
        // SECURITY ISSUE: Storing sensitive data without encryption
        db.execSQL("INSERT INTO user_data (ssn, credit_card, cvv) VALUES (?, ?, ?)",
            new Object[]{ssn, creditCard, cvv});
        
        // SECURITY ISSUE: Logging sensitive data
        Log.d(TAG, "Stored SSN: " + ssn);
        Log.d(TAG, "Stored CC: " + creditCard.substring(0, 4) + "****");
    }
    
    private String generateToken(String username, String password) {
        // SECURITY ISSUE: Weak token generation
        return android.util.Base64.encodeToString(
            (username + ":" + password + ":" + System.currentTimeMillis()).getBytes(),
            android.util.Base64.NO_WRAP
        );
    }
    
    /**
     * SECURITY ISSUE: SQL Injection vulnerability
     */
    public void searchUsers(String searchTerm) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        
        // VULNERABLE: Direct string concatenation in SQL
        String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'";
        db.rawQuery(query, null);
    }
    
    /**
     * Export data to external storage - INSECURE
     */
    public void exportDataToFile() {
        try {
            // SECURITY ISSUE: Writing sensitive data to external storage
            java.io.File exportFile = new java.io.File(
                android.os.Environment.getExternalStorageDirectory(),
                "jarwis_export.json"
            );
            
            java.io.FileWriter writer = new java.io.FileWriter(exportFile);
            writer.write("{\"username\": \"" + prefs.getString("username", "") + "\",");
            writer.write("\"token\": \"" + prefs.getString("auth_token", "") + "\"}");
            writer.close();
            
            Log.d(TAG, "Exported to: " + exportFile.getAbsolutePath());
            
        } catch (Exception e) {
            Log.e(TAG, "Export failed: " + e.getMessage());
        }
    }
    
    /**
     * Database Helper with insecure patterns
     */
    private static class DatabaseHelper extends SQLiteOpenHelper {
        
        private static final String DATABASE_NAME = "jarwis_user.db";
        private static final int DATABASE_VERSION = 1;
        
        public DatabaseHelper(Context context) {
            super(context, DATABASE_NAME, null, DATABASE_VERSION);
        }
        
        @Override
        public void onCreate(SQLiteDatabase db) {
            // SECURITY ISSUE: Storing sensitive data in plaintext
            db.execSQL("CREATE TABLE user_data (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "ssn TEXT," +           // Should be encrypted
                "credit_card TEXT," +   // Should be encrypted
                "cvv TEXT," +           // Should never be stored!
                "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
            
            db.execSQL("CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "name TEXT," +
                "email TEXT," +
                "password TEXT)");  // Should use proper hashing
        }
        
        @Override
        public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
            db.execSQL("DROP TABLE IF EXISTS user_data");
            db.execSQL("DROP TABLE IF EXISTS users");
            onCreate(db);
        }
    }
}
