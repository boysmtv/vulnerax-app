package com.vulnerax.modules.compliance;

import java.util.Map;

public class OwaspMapper {

    private static final Map<String, String> CWE_TO_OWASP = Map.ofEntries(
            Map.entry("CWE-79", "A03:2021-Injection"),
            Map.entry("CWE-89", "A03:2021-Injection"),
            Map.entry("CWE-22", "A01:2021-Broken Access Control"),
            Map.entry("CWE-287", "A07:2021-Identification and Authentication Failures"),
            Map.entry("CWE-200", "A01:2021-Broken Access Control"),
            Map.entry("CWE-319", "A02:2021-Cryptographic Failures"),
            Map.entry("CWE-352", "A01:2021-Broken Access Control"),
            Map.entry("CWE-502", "A08:2021-Software and Data Integrity Failures"),
            Map.entry("CWE-538", "A01:2021-Broken Access Control"),
            Map.entry("CWE-601", "A01:2021-Broken Access Control"),
            Map.entry("CWE-611", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-614", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-693", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-732", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-770", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-798", "A07:2021-Identification and Authentication Failures"),
            Map.entry("CWE-862", "A01:2021-Broken Access Control"),
            Map.entry("CWE-918", "A10:2021-Server-Side Request Forgery"),
            Map.entry("CWE-942", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-1004", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-1021", "A05:2021-Security Misconfiguration"),
            Map.entry("CWE-1104", "A06:2021-Vulnerable and Outdated Components")
    );

    private static final Map<String, String> CWE_TO_ASVS = Map.ofEntries(
            Map.entry("CWE-79", "v5.0.0-5.3-Req-1"),
            Map.entry("CWE-89", "v5.0.0-5.5-Req-1"),
            Map.entry("CWE-22", "v5.0.0-5.1-Req-1"),
            Map.entry("CWE-287", "v5.0.0-2.1-Req-1"),
            Map.entry("CWE-352", "v5.0.0-4.1-Req-1"),
            Map.entry("CWE-611", "v5.0.0-5.3-Req-5"),
            Map.entry("CWE-862", "v5.0.0-4.2-Req-1"),
            Map.entry("CWE-918", "v5.0.0-7.4-Req-1")
    );

    private static final Map<String, String> CWE_TO_WSTG = Map.ofEntries(
            Map.entry("CWE-79", "WSTG-SESS-xx"),
            Map.entry("CWE-89", "WSTG-SESS-xx"),
            Map.entry("CWE-22", "WSTG-ATHZ-xx"),
            Map.entry("CWE-287", "WSTG-ATHN-xx"),
            Map.entry("CWE-352", "WSTG-CSRF-xx"),
            Map.entry("CWE-862", "WSTG-ATHZ-xx"),
            Map.entry("CWE-918", "WSTG-SRNR-xx")
    );

    public static String getOwasp(String cwe) {
        if (cwe == null) return null;
        return CWE_TO_OWASP.getOrDefault(cwe, "See OWASP Top 10 2021 mapping");
    }

    public static String getAsvs(String cwe) {
        if (cwe == null) return null;
        return CWE_TO_ASVS.get(cwe);
    }

    public static String getWstg(String cwe) {
        if (cwe == null) return null;
        return CWE_TO_WSTG.get(cwe);
    }
}
