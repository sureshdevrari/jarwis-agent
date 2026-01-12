package com.jarwis.sslpinningtest.security;

import android.os.Build;
import java.io.File;

/**
 * Root Detection Utility
 * Detects if the device is rooted or running in an emulator
 * 
 * Note: These checks can be bypassed with Frida/Xposed
 * Jarwis should be able to detect and bypass these
 */
public class RootDetector {
    
    // Known root binary paths
    private static final String[] ROOT_PATHS = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
    };
    
    // Known root packages
    private static final String[] ROOT_PACKAGES = {
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot"
    };
    
    /**
     * Check if device is rooted
     */
    public static boolean isDeviceRooted() {
        return checkRootBinaries() || 
               checkRootPackages() || 
               checkBuildTags() ||
               checkSuCommand();
    }
    
    /**
     * Check for root binary files
     */
    private static boolean checkRootBinaries() {
        for (String path : ROOT_PATHS) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check for root management packages
     */
    private static boolean checkRootPackages() {
        // In real implementation, would check package manager
        return false;
    }
    
    /**
     * Check build tags for test-keys
     */
    private static boolean checkBuildTags() {
        String buildTags = Build.TAGS;
        return buildTags != null && buildTags.contains("test-keys");
    }
    
    /**
     * Try to execute su command
     */
    private static boolean checkSuCommand() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            int exitCode = process.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check if running in emulator
     */
    public static boolean isEmulator() {
        return Build.FINGERPRINT.contains("generic") ||
               Build.FINGERPRINT.contains("unknown") ||
               Build.MODEL.contains("google_sdk") ||
               Build.MODEL.contains("Emulator") ||
               Build.MODEL.contains("Android SDK built for x86") ||
               Build.MANUFACTURER.contains("Genymotion") ||
               Build.BRAND.startsWith("generic") ||
               Build.DEVICE.startsWith("generic") ||
               Build.PRODUCT.contains("sdk") ||
               Build.PRODUCT.contains("emulator") ||
               Build.HARDWARE.contains("goldfish") ||
               Build.HARDWARE.contains("ranchu");
    }
    
    /**
     * Check for Frida injection
     */
    public static boolean isFridaDetected() {
        // Check for Frida server running
        try {
            // Check common Frida ports
            java.net.Socket socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", 27042), 100);
            socket.close();
            return true;
        } catch (Exception e) {
            // Port not open, might not have Frida
        }
        
        // Check for Frida in /proc/maps
        try {
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.FileReader("/proc/self/maps"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("frida") || line.contains("gadget")) {
                    reader.close();
                    return true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // Cannot read maps
        }
        
        return false;
    }
    
    /**
     * Check for Xposed framework
     */
    public static boolean isXposedDetected() {
        // Check for Xposed installer
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            return true;
        } catch (ClassNotFoundException e) {
            // Xposed not loaded
        }
        
        // Check stack trace for Xposed
        try {
            throw new Exception("Detection");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                if (element.getClassName().contains("xposed")) {
                    return true;
                }
            }
        }
        
        return false;
    }
}
