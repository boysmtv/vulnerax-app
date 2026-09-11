package com.vulnerax.modules.scan.analyzers;

import java.util.*;

public class MobileAnalyzer {

    public static List<Map<String,Object>> analyze(String target, String configJson) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (target == null) return out;
        String fileName = target.toLowerCase();

        if (fileName.endsWith(".apk")) {
            analyzeApk(out, configJson);
        } else if (fileName.endsWith(".ipa")) {
            analyzeIpa(out, configJson);
        } else if (fileName.endsWith(".aab")) {
            analyzeAab(out, configJson);
        } else {
            out.add(mk("Not a Mobile Artifact", "CWE-0", "INFO",
                "Target " + target + " is not a recognized mobile file (.apk/.ipa/.aab)",
                target, 0, "Provide APK/IPA/AAB file for analysis"));
        }
        return out;
    }

    private static void analyzeApk(List<Map<String,Object>> out, String configJson) {
        String cfg = configJson != null ? configJson : "";

        // 1. Backup allowed
        if (cfg.contains("allowBackup=true") || !cfg.contains("allowBackup")) {
            out.add(mk("APK: allowBackup Enabled", "CWE-921", "HIGH",
                "Android backup enabled — attacker can extract app data via ADB",
                "AndroidManifest.xml", 0, "Set android:allowBackup=\"false\""));
        }

        // 2. Debuggable
        if (cfg.contains("debuggable=true")) {
            out.add(mk("APK: Debuggable", "CWE-489", "CRITICAL",
                "App is debuggable — attach debugger, bypass security checks",
                "AndroidManifest.xml", 0, "Set android:debuggable=\"false\""));
        }

        // 3. Network security — cleartext traffic
        if (cfg.contains("usesCleartextTraffic=true") || !cfg.contains("networkSecurityConfig")) {
            out.add(mk("APK: Cleartext Traffic Allowed", "CWE-319", "HIGH",
                "App allows HTTP traffic — MITM possible",
                "AndroidManifest.xml", 0, "Set usesCleartextTraffic=\"false\", use network-security-config"));
        }

        // 4. Exported components
        if (cfg.contains("exported=true")) {
            out.add(mk("APK: Exported Component", "CWE-284", "HIGH",
                "Component exported — accessible by other apps",
                "AndroidManifest.xml", 0, "Set exported=\"false\" or add permission"));
        }

        // 5. Insecure WebView
        if (cfg.contains("setJavaScriptEnabled(true)") || cfg.contains("setJavaScriptEnabled( true )")) {
            out.add(mk("APK: JavaScript in WebView", "CWE-79", "HIGH",
                "WebView with JavaScript enabled — XSS risk",
                "WebView config", 0, "Validate URL origin, use shouldOverrideUrlLoading"));
        }
        if (cfg.contains("setAllowFileAccess(true)") || cfg.contains("setAllowUniversalAccessFromFileURLs(true)")) {
            out.add(mk("APK: File Access in WebView", "CWE-22", "CRITICAL",
                "WebView allows file access — local file theft possible",
                "WebView config", 0, "Disable file access in WebView"));
        }

        // 6. Deep link validation
        if (cfg.contains("intent-filter") && cfg.contains("VIEW")) {
            if (!cfg.contains("android:autoVerify")) {
                out.add(mk("APK: Deep Link without Verification", "CWE-601", "MEDIUM",
                    "Deep link intent-filter without autoVerify — URL hijacking risk",
                    "AndroidManifest.xml", 0, "Add android:autoVerify=\"true\""));
            }
        }

        // 7. Hardcoded secrets
        String[] secrets = {"api_key", "apikey", "secret", "password", "token", "AWS"};
        for (String s : secrets) {
            if (cfg.toLowerCase().contains(s)) {
                out.add(mk("APK: Hardcoded " + s, "CWE-798", "CRITICAL",
                    "Secret " + s + " found in APK config — extractable via decompilation",
                    "APK resources", 0, "Use Android Keystore / encrypted SharedPreferences"));
            }
        }

        // 8. Insecure storage
        if (cfg.contains("getExternalFilesDir") || cfg.contains("Environment.getExternalStorage")) {
            out.add(mk("APK: External Storage Usage", "CWE-922", "MEDIUM",
                "App uses external storage — data readable by other apps",
                "Storage", 0, "Use internal storage for sensitive data"));
        }

        // 9. Weak crypto
        if (cfg.contains("AES/ECB") || cfg.contains("DES/") || cfg.contains("MD5") || cfg.contains("SHA-1")) {
            out.add(mk("APK: Weak Crypto Algorithm", "CWE-327", "HIGH",
                "Weak algorithm detected (ECB/DES/MD5/SHA1) in mobile app",
                "Crypto", 0, "Use AES-GCM, SHA-256+"));
        }

        // 10. Root detection missing
        if (!cfg.contains("isRooted") && !cfg.contains("SafetyNet") && !cfg.contains("Play Integrity")) {
            out.add(mk("APK: No Root Detection", "CWE-693", "MEDIUM",
                "No root/jailbreak detection found — app may run on compromised devices",
                "Security", 0, "Implement root detection + SafetyNet/Play Integrity"));
        }

        // 11. Logcat logging
        if (cfg.contains("Log.d(") || cfg.contains("Log.v(") || cfg.contains("Log.i(")) {
            out.add(mk("APK: Debug Logging in Production", "CWE-532", "MEDIUM",
                "Debug/verbose logging found — info leakage via logcat",
                "Code", 0, "Remove debug logs in production builds"));
        }

        if (out.isEmpty()) {
            out.add(mk("APK Scan Complete", "CWE-693", "INFO",
                "No critical mobile security issue found in APK",
                "APK", 0, "Perform manual MASVS review"));
        }
    }

    private static void analyzeIpa(List<Map<String,Object>> out, String configJson) {
        String cfg = configJson != null ? configJson : "";

        // iOS-specific checks
        if (cfg.contains("NSAppTransportSecurity") && cfg.contains("NSAllowsArbitraryLoads=YES")) {
            out.add(mk("iOS: ATS Disabled", "CWE-319", "HIGH",
                "App Transport Security disabled — HTTP allowed",
                "Info.plist", 0, "Remove NSAllowsArbitraryLoads or set NO"));
        }
        if (cfg.contains("UIFileSharingEnabled=YES")) {
            out.add(mk("iOS: File Sharing Enabled", "CWE-922", "MEDIUM",
                "iTunes file sharing enabled — data exposed via iTunes",
                "Info.plist", 0, "Set UIFileSharingEnabled to NO"));
        }
        if (cfg.contains("NSPhotoLibraryUsageDescription")) {
            out.add(mk("iOS: Photo Library Access", "CWE-200", "INFO",
                "App requests photo library access — verify necessity",
                "Info.plist", 0, "Minimize data access scope"));
        }
        if (cfg.contains("keychain") || cfg.contains("kSecAttrAccessible")) {
            // good — keychain usage
        } else {
            out.add(mk("iOS: No Keychain Usage Detected", "CWE-922", "MEDIUM",
                "No Keychain storage detected — secrets may be in UserDefaults/plist",
                "iOS Storage", 0, "Use Keychain for sensitive data"));
        }

        if (out.isEmpty()) {
            out.add(mk("IPA Scan Complete", "CWE-693", "INFO",
                "No critical iOS security issue found",
                "IPA", 0, "Perform manual OWASP MASVS review"));
        }
    }

    private static void analyzeAab(List<Map<String,Object>> out, String configJson) {
        out.add(mk("AAB Format Detected", "CWE-0", "INFO",
            "Android App Bundle — analyze as APK after extraction from Play Store",
            "AAB", 0, "Download from Play Store, extract APK for analysis"));
        analyzeApk(out, configJson);
    }

    private static Map<String,Object> mk(String title, String cwe, String severity, String desc, String file, int line, String rec) {
        Map<String,Object> m = new HashMap<>();
        m.put("title", title); m.put("rule", title); m.put("cwe", cwe);
        m.put("severity", severity); m.put("file", file); m.put("line", line);
        m.put("snippet", desc); m.put("recommendation", rec); m.put("match", title);
        return m;
    }
}
