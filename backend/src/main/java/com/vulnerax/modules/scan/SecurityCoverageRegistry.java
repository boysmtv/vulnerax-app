package com.vulnerax.modules.scan;

import org.springframework.stereotype.Component;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SecurityCoverageRegistry {
    private final Map<String, TestDefinition> tests = new ConcurrentHashMap<>();
    private final Map<String, String> targetHints = new ConcurrentHashMap<>();
    private final Map<String, String> owaspAsvsMap = new ConcurrentHashMap<>();

    public SecurityCoverageRegistry() {
        // WSTG tests
        registerTest(new TestDefinition("WSTG-INFO-01", "HTTP Methods", "ORIGIN_SERVER", List.of("or", "origin"), "Check allowed HTTP methods", List.of("TRACE", "OPTIONS")));
        registerTest(new TestDefinition("WSTG-INFO-02", "Fingerprint Web Server", "ORIGIN_SERVER", List.of("or", "origin"), "Identify web server software", List.of("Server header", "X-Powered-By")));
        registerTest(new TestDefinition("WSTG-INFO-06", "Enumerate Web Apps", "ORIGIN_SERVER", List.of("or", "origin"), "Discover web applications", List.of("robots.txt", "sitemap.xml")));
        registerTest(new TestDefinition("WSTG-INPV-01", "Reflected XSS", "ORIGIN_SERVER", List.of("or", "xss"), "Cross-site scripting reflection", List.of("parameter reflection", "script tag injection")));
        registerTest(new TestDefinition("WSTG-INPV-02", "Stored XSS", "ORIGIN_SERVER", List.of("or", "xss"), "Persistent cross-site scripting", List.of("database storage", "DOM manipulation")));
        registerTest(new TestDefinition("WSTG-INPV-03", "HTTP Verb Tampering", "ORIGIN_SERVER", List.of("or", "origin"), "Test HTTP method access controls", List.of("PUT", "DELETE", "PATCH")));
        registerTest(new TestDefinition("WSTG-INPV-04", "Local File Inclusion", "ORIGIN_SERVER", List.of("or", "lfi"), "Path traversal to read local files", List.of("/etc/passwd")));
        registerTest(new TestDefinition("WSTG-INPV-05", "Remote File Inclusion", "ORIGIN_SERVER", List.of("or", "lfi", "rfi"), "Include remote files via URL", List.of("http://evil.com/shell.txt")));
        registerTest(new TestDefinition("WSTG-INPV-06", "SSRF", "ORIGIN_SERVER", List.of("or", "ssrf"), "Server-Side Request Forgery", List.of("http://169.254.169.254")));
        registerTest(new TestDefinition("WSTG-INPV-07", "SQL Injection", "ORIGIN_SERVER", List.of("or", "sqli"), "SQL injection in parameters", List.of("UNION SELECT", "OR 1=1")));
        registerTest(new TestDefinition("WSTG-INPV-08", "SQL Injection Blind", "ORIGIN_SERVER", List.of("or", "sqli"), "Blind SQL injection", List.of("SLEEP", "BENCHMARK")));
        registerTest(new TestDefinition("WSTG-ATHN-01", "Credential Filling", "ORIGIN_SERVER", List.of("or", "auth"), "Test credential stuffing resistance", List.of("rate limiting", "CAPTCHA")));
        registerTest(new TestDefinition("WSTG-ATHZ-01", "Directory Browsing", "ORIGIN_SERVER", List.of("or", "auth"), "Test for directory listing", List.of("Directory listing")));
        registerTest(new TestDefinition("WSTG-ATHZ-02", "Bypass Authorization", "ORIGIN_SERVER", List.of("or", "auth"), "Test IDOR and authorization bypass", List.of("/api/admin")));
        registerTest(new TestDefinition("WSTG-SESS-01", "Session Mgmt", "ORIGIN_SERVER", List.of("or", "session"), "Test session management", List.of("Cookie flags", "Session fixation")));
        registerTest(new TestDefinition("WSTG-SESS-02", "Cookie Attributes", "ORIGIN_SERVER", List.of("or", "session"), "Check cookie security flags", List.of("HttpOnly", "Secure", "SameSite")));
        registerTest(new TestDefinition("WSTG-SESS-04", "CSRF", "ORIGIN_SERVER", List.of("or", "csrf"), "Cross-Site Request Forgery", List.of("missing CSRF token")));
        registerTest(new TestDefinition("WSTG-CRYP-01", "Weak TLS", "ORIGIN_SERVER", List.of("or", "tls"), "Check TLS configuration", List.of("TLS 1.0", "RC4", "DES")));
        registerTest(new TestDefinition("WSTG-CRYP-02", "Weak Ciphers", "ORIGIN_SERVER", List.of("or", "tls"), "Check for weak cipher suites", List.of("3DES", "NULL", "EXPORT")));
        registerTest(new TestDefinition("WSTG-CONF-01", "Security Headers", "ORIGIN_SERVER", List.of("or", "headers"), "Check security headers", List.of("CSP", "X-Frame-Options")));
        registerTest(new TestDefinition("WSTG-INPV-11", "Business Logic", "ORIGIN_SERVER", List.of("or", "logic"), "Business logic bypass", List.of("negative quantities", "privilege escalation")));
        registerTest(new TestDefinition("WSTG-INPV-12", "Input Validation", "ORIGIN_SERVER", List.of("or", "xss", "sqli"), "Input validation bypass", List.of("unicode bypass", "encoding tricks")));

        // SAST-specific tests
        registerTest(new TestDefinition("SAST-INJECT-01", "SQL Injection (SAST)", "CODE", List.of("sast", "sqli"), "Pattern-based SQL injection detection", List.of("Statement concatenation", "createQuery")));
        registerTest(new TestDefinition("SAST-INJECT-02", "Command Injection (SAST)", "CODE", List.of("sast", "cmdi"), "Runtime.exec / ProcessBuilder detection", List.of("Runtime.exec", "ProcessBuilder")));
        registerTest(new TestDefinition("SAST-INJECT-03", "XSS (SAST)", "CODE", List.of("sast", "xss"), "DOM manipulation patterns", List.of("innerHTML", "document.write")));
        registerTest(new TestDefinition("SAST-CRYPTO-01", "Weak Crypto (SAST)", "CODE", List.of("sast", "crypto"), "MD5/SHA1/DES usage", List.of("MD5", "SHA-1", "DES")));
        registerTest(new TestDefinition("SAST-AUTH-01", "Hardcoded Secrets (SAST)", "CODE", List.of("sast", "secret"), "Hardcoded credentials/keys", List.of("password=", "secret=", "apikey=")));

        // SCA-specific tests
        registerTest(new TestDefinition("SCA-VULN-01", "Known CVE", "DEPENDENCY", List.of("sca", "cve"), "Dependency with known CVE", List.of("CVE-", "GHSA-")));
        registerTest(new TestDefinition("SCA-LICENSE-01", "License Risk", "DEPENDENCY", List.of("sca", "license"), "Copyleft or risky licenses", List.of("GPL", "AGPL")));

        // Secret-specific tests
        registerTest(new TestDefinition("SECRET-01", "API Key", "CODE", List.of("secret", "apikey"), "API key patterns", List.of("AKIA", "api_key")));
        registerTest(new TestDefinition("SECRET-02", "Private Key", "CODE", List.of("secret", "privatekey"), "PEM private key", List.of("BEGIN RSA", "BEGIN PRIVATE")));

        registerTargetHint("or", "Check HTTP methods, headers, cookies, SQL injection, XSS, path traversal");
        registerTargetHint("ip", "Port scan, service detection, OS fingerprinting");
        registerTargetHint("domain", "Subdomain enumeration, DNS analysis, certificate transparency");
        registerTargetHint("url", "Full web application testing, API endpoints, form handling");
        registerTargetHint("mobile", "API endpoint analysis, certificate pinning, data storage");

        // OWASP ASVS mappings
        initAsvsMap();
    }

    private void initAsvsMap() {
        owaspAsvsMap.put("WSTG-INPV-01", "ASVS 5.1.1 - Input Validation");
        owaspAsvsMap.put("WSTG-INPV-02", "ASVS 5.1.1 - Input Validation");
        owaspAsvsMap.put("WSTG-INPV-07", "ASVS 5.1.3 - SQL Injection Prevention");
        owaspAsvsMap.put("WSTG-INPV-08", "ASVS 5.1.3 - SQL Injection Prevention");
        owaspAsvsMap.put("WSTG-INPV-06", "ASVS 5.3.7 - SSRF Prevention");
        owaspAsvsMap.put("WSTG-INPV-04", "ASVS 5.3.1 - File Path Traversal");
        owaspAsvsMap.put("WSTG-ATHN-01", "ASVS 2.1.1 - Password Security");
        owaspAsvsMap.put("WSTG-ATHZ-01", "ASVS 4.1.1 - Access Control");
        owaspAsvsMap.put("WSTG-ATHZ-02", "ASVS 4.1.3 - Access Control");
        owaspAsvsMap.put("WSTG-SESS-01", "ASVS 3.1.1 - Session Management");
        owaspAsvsMap.put("WSTG-SESS-02", "ASVS 3.4.1 - Cookie Security");
        owaspAsvsMap.put("WSTG-SESS-04", "ASVS 3.5.1 - CSRF Protection");
        owaspAsvsMap.put("WSTG-CRYP-01", "ASVS 9.1.1 - TLS Configuration");
        owaspAsvsMap.put("WSTG-CRYP-02", "ASVS 9.1.2 - Cipher Suites");
        owaspAsvsMap.put("WSTG-CONF-01", "ASVS 14.1.4 - Security Headers");
        owaspAsvsMap.put("WSTG-INPV-11", "ASVS 12.1.1 - Business Logic");
        owaspAsvsMap.put("SAST-INJECT-01", "ASVS 5.1.3 - SQL Injection Prevention");
        owaspAsvsMap.put("SAST-INJECT-02", "ASVS 5.1.5 - OS Command Injection");
        owaspAsvsMap.put("SAST-INJECT-03", "ASVS 5.1.2 - XSS Prevention");
        owaspAsvsMap.put("SAST-CRYPTO-01", "ASVS 9.2.1 - Cryptographic Modules");
        owaspAsvsMap.put("SAST-AUTH-01", "ASVS 6.5.1 - Credential Storage");
        owaspAsvsMap.put("SCA-VULN-01", "ASVS 14.2.1 - Dependency Management");
        owaspAsvsMap.put("SECRET-01", "ASVS 6.5.1 - Credential Storage");
        owaspAsvsMap.put("SECRET-02", "ASVS 6.5.1 - Credential Storage");
    }

    public void registerTest(TestDefinition test) {
        tests.put(test.id(), test);
    }

    public void registerTargetHint(String type, String hint) {
        targetHints.put(type, hint);
    }

    public List<TestDefinition> getTestsForTarget(String targetType) {
        return tests.values().stream()
                .filter(t -> t.tags().contains(targetType) || t.tags().contains("*"))
                .toList();
    }

    public Map<String, Object> planCoverage(String targetType, String url) {
        List<TestDefinition> applicableTests = getTestsForTarget(targetType);
        List<String> allTags = applicableTests.stream().flatMap(t -> t.tags().stream()).distinct().toList();
        List<String> recommended = allTags.stream().filter(t -> !t.equals("*")).toList();
        return Map.of(
                "target", url,
                "targetType", targetType,
                "totalTests", applicableTests.size(),
                "recommendedTags", recommended,
                "hint", targetHints.getOrDefault(targetType, "No specific hints"),
                "tests", applicableTests.stream().map(TestDefinition::id).toList()
        );
    }

    public Map<String, Object> calculateCoverage(UUID projectId) {
        // Return all test definitions and their coverage status
        List<Map<String, Object>> tested = new ArrayList<>();
        List<Map<String, Object>> untested = new ArrayList<>();

        for (TestDefinition t : tests.values()) {
            Map<String, Object> testInfo = new LinkedHashMap<>();
            testInfo.put("id", t.id());
            testInfo.put("name", t.name());
            testInfo.put("phase", t.phase());
            testInfo.put("tags", t.tags());
            String asvs = owaspAsvsMap.get(t.id());
            if (asvs != null) testInfo.put("asvs", asvs);
            // For now, mark all as untested (caller should override with actual data)
            untested.add(testInfo);
        }

        double percentage = tests.isEmpty() ? 0.0 : (tested.size() * 100.0 / tests.size());

        return Map.of(
                "overallPercentage", Math.round(percentage * 10.0) / 10.0,
                "tested", tested,
                "untested", untested,
                "totalTests", tests.size(),
                "testedCount", tested.size()
        );
    }

    public Map<String, Object> calculateCoverageWithFinds(Set<String> findingTypes, Set<String> cwesFound) {
        List<Map<String, Object>> matched = new ArrayList<>();
        List<Map<String, Object>> unmatched = new ArrayList<>();

        for (TestDefinition t : tests.values()) {
            Map<String, Object> testInfo = new LinkedHashMap<>();
            testInfo.put("id", t.id());
            testInfo.put("name", t.name());
            testInfo.put("asvs", owaspAsvsMap.getOrDefault(t.id(), "N/A"));

            boolean isMatched = t.tags().stream().anyMatch(findingTypes::contains) ||
                    t.indicators().stream().anyMatch(ind ->
                            cwesFound.stream().anyMatch(cwe -> ind.toLowerCase().contains(cwe.toLowerCase())));
            if (isMatched) matched.add(testInfo);
            else unmatched.add(testInfo);
        }

        double percentage = tests.isEmpty() ? 0.0 : (matched.size() * 100.0 / tests.size());
        return Map.of(
                "overallPercentage", Math.round(percentage * 10.0) / 10.0,
                "matched", matched,
                "unmatched", unmatched,
                "totalTests", tests.size(),
                "matchedCount", matched.size()
        );
    }

    public double calculateCoverage(Set<String> foundTags) {
        if (tests.isEmpty()) return 0.0;
        long matched = tests.values().stream()
                .filter(t -> foundTags.stream().anyMatch(t.tags()::contains))
                .count();
        return matched * 100.0 / tests.size();
    }

    public record TestDefinition(String id, String name, String phase, List<String> tags, String description, List<String> indicators) {}
}
