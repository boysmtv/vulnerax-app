package com.vulnerax.modules.scan;

import org.springframework.stereotype.Component;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SecurityCoverageRegistry {
    private final Map<String, TestDefinition> tests = new ConcurrentHashMap<>();
    private final Map<String, String> targetHints = new ConcurrentHashMap<>();

    public SecurityCoverageRegistry() {
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

        registerTargetHint("or", "Check HTTP methods, headers, cookies, SQL injection, XSS, path traversal");
        registerTargetHint("ip", "Port scan, service detection, OS fingerprinting");
        registerTargetHint("domain", "Subdomain enumeration, DNS analysis, certificate transparency");
        registerTargetHint("url", "Full web application testing, API endpoints, form handling");
        registerTargetHint("mobile", "API endpoint analysis, certificate pinning, data storage");
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

    public double calculateCoverage(Set<String> foundTags) {
        if (tests.isEmpty()) return 0.0;
        long matched = tests.values().stream()
                .filter(t -> foundTags.stream().anyMatch(t.tags()::contains))
                .count();
        return matched * 100.0 / tests.size();
    }

    public record TestDefinition(String id, String name, String phase, List<String> tags, String description, List<String> indicators) {}
}
