package com.vulnerax.modules.classification;

import com.vulnerax.modules.finding.Finding;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ClassificationEngine {

    public enum FindingClass {
        VULNERABILITY,
        MISCONFIGURATION,
        EXPOSURE,
        SCAN_ISSUE,
        COVERAGE_GAP,
        INFORMATIONAL
    }

    public enum FindingSubtype {
        // Vulnerability subtypes
        SQL_INJECTION, XSS, SSRF, XXE, COMMAND_INJECTION, PATH_TRAVERSAL,
        AUTHORIZATION_BYPASS, AUTHENTICATION_BYPASS, INSECURE_DESERIALIZATION,
        OPEN_REDIRECT, FILE_INCLUSION, HARDcoded_SECRET, VULNERABLE_DEPENDENCY,
        // Misconfiguration subtypes
        MISSING_HEADER, WEAK_TLS, CORS_MISCONFIG, COOKIE_MISCONFIG,
        DEBUG_ENDPOINT, VERSION_DISCLOSURE, DEFAULT_CREDENTIALS,
        // Exposure subtypes
        SENSITIVE_FILE, ADMIN_ENDPOINT, PUBLIC_API, INTERNET_EXPOSED_SERVICE,
        // Scan issue subtypes
        TARGET_UNREACHABLE, AUTH_FAILED, RATE_LIMITED, WAF_BLOCKED,
        SCAN_TIMEOUT, DNS_FAILURE, CERTIFICATE_ERROR,
        // Coverage gap subtypes
        UNCRAWLED_ENDPOINT, UNTESTED_AUTH, UNTESTED_INPUT,
        // Informational
        SCAN_COMPLETED, CLEAN_SCAN, INFO_DISCLOSURE
    }

    public Classification classify(Map<String, Object> rawObservation) {
        String title = (String) rawObservation.getOrDefault("title", "");
        String cwe = (String) rawObservation.get("cwe");
        String severity = (String) rawObservation.get("severity");
        String findingType = (String) rawObservation.get("findingType");
        Boolean confirmed = (Boolean) rawObservation.get("vulnerabilityConfirmed");
        Boolean secVuln = (Boolean) rawObservation.get("securityVulnerability");
        String subtype = (String) rawObservation.get("scanSubtype");

        // Step 1: Classify
        FindingClass findingClass = determineClass(findingType, confirmed, secVuln, cwe, title);

        // Step 2: Determine subtype
        FindingSubtype findingSubtype = determineSubtype(findingClass, subtype, title);

        // Step 3: Validate CWE assignment
        String validatedCwe = validateCwe(findingClass, cwe, confirmed);

        // Step 4: Determine evidence strength
        String evidenceStrength = determineEvidenceStrength(findingClass, confirmed, rawObservation);

        // Step 5: Calculate confidence levels
        Map<String, Double> confidence = calculateConfidence(findingClass, confirmed, rawObservation);

        // Step 6: Determine if CWE/CVSS should be null
        boolean assignCwe = findingClass == FindingClass.VULNERABILITY && Boolean.TRUE.equals(confirmed);
        boolean assignCvss = assignCwe && validatedCwe != null;

        return new Classification(
                findingClass,
                findingSubtype,
                assignCwe ? validatedCwe : null,
                assignCvss,
                evidenceStrength,
                confidence
        );
    }

    private FindingClass determineClass(String findingType, Boolean confirmed, Boolean secVuln, String cwe, String title) {
        // Explicit SCAN_ERROR from analyzer
        if ("SCAN_ERROR".equals(findingType)) return FindingClass.SCAN_ISSUE;

        // If analyzer says not a vulnerability
        if (Boolean.FALSE.equals(secVuln)) {
            if (title.contains("Unreachable") || title.contains("Error") || title.contains("Timeout")) {
                return FindingClass.SCAN_ISSUE;
            }
            return FindingClass.INFORMATIONAL;
        }

        // If vulnerability is confirmed
        if (Boolean.TRUE.equals(confirmed) && cwe != null) {
            return FindingClass.VULNERABILITY;
        }

        // Header/config issues
        if (title.startsWith("Missing Header:") || title.contains("Cookie Missing")) {
            return FindingClass.MISCONFIGURATION;
        }
        if (title.contains("CORS") || title.contains("Cleartext HTTP")) {
            return FindingClass.MISCONFIGURATION;
        }

        // Exposure findings
        if (title.contains("Exposed") || title.contains("Disclosure") || title.contains("Admin Endpoint")) {
            return FindingClass.EXPOSURE;
        }

        // Default: if we have a CWE and it's not confirmed, treat as informational
        if (cwe != null && confirmed == null) {
            return FindingClass.INFORMATIONAL;
        }

        return FindingClass.INFORMATIONAL;
    }

    private FindingSubtype determineSubtype(FindingClass findingClass, String explicitSubtype, String title) {
        if (explicitSubtype != null) {
            try {
                return FindingSubtype.valueOf(explicitSubtype);
            } catch (IllegalArgumentException ignored) {}
        }

        String lower = title.toLowerCase();
        return switch (findingClass) {
            case VULNERABILITY -> {
                if (lower.contains("sql injection")) yield FindingSubtype.SQL_INJECTION;
                if (lower.contains("xss") || lower.contains("cross-site scripting")) yield FindingSubtype.XSS;
                if (lower.contains("ssrf")) yield FindingSubtype.SSRF;
                if (lower.contains("xxe")) yield FindingSubtype.XXE;
                if (lower.contains("command injection")) yield FindingSubtype.COMMAND_INJECTION;
                if (lower.contains("path traversal")) yield FindingSubtype.PATH_TRAVERSAL;
                if (lower.contains("authorization") || lower.contains("idor") || lower.contains("bola")) yield FindingSubtype.AUTHORIZATION_BYPASS;
                if (lower.contains("redirect")) yield FindingSubtype.OPEN_REDIRECT;
                if (lower.contains("secret") || lower.contains("credential")) yield FindingSubtype.HARDcoded_SECRET;
                if (lower.contains("dependency") || lower.contains("cve")) yield FindingSubtype.VULNERABLE_DEPENDENCY;
                yield FindingSubtype.SQL_INJECTION; // default
            }
            case MISCONFIGURATION -> {
                if (lower.contains("missing header")) yield FindingSubtype.MISSING_HEADER;
                if (lower.contains("cors")) yield FindingSubtype.CORS_MISCONFIG;
                if (lower.contains("cookie")) yield FindingSubtype.COOKIE_MISCONFIG;
                if (lower.contains("tls") || lower.contains("cleartext")) yield FindingSubtype.WEAK_TLS;
                if (lower.contains("debug") || lower.contains("actuator")) yield FindingSubtype.DEBUG_ENDPOINT;
                if (lower.contains("version") || lower.contains("disclosure")) yield FindingSubtype.VERSION_DISCLOSURE;
                yield FindingSubtype.MISSING_HEADER;
            }
            case EXPOSURE -> {
                if (lower.contains("sensitive file")) yield FindingSubtype.SENSITIVE_FILE;
                if (lower.contains("admin")) yield FindingSubtype.ADMIN_ENDPOINT;
                if (lower.contains("api")) yield FindingSubtype.PUBLIC_API;
                yield FindingSubtype.INTERNET_EXPOSED_SERVICE;
            }
            case SCAN_ISSUE -> {
                if (lower.contains("unreachable") || lower.contains("connection")) yield FindingSubtype.TARGET_UNREACHABLE;
                if (lower.contains("auth") || lower.contains("login")) yield FindingSubtype.AUTH_FAILED;
                if (lower.contains("rate") || lower.contains("429")) yield FindingSubtype.RATE_LIMITED;
                if (lower.contains("waf") || lower.contains("cloudflare")) yield FindingSubtype.WAF_BLOCKED;
                if (lower.contains("timeout")) yield FindingSubtype.SCAN_TIMEOUT;
                if (lower.contains("dns")) yield FindingSubtype.DNS_FAILURE;
                if (lower.contains("certificate") || lower.contains("tls")) yield FindingSubtype.CERTIFICATE_ERROR;
                yield FindingSubtype.TARGET_UNREACHABLE;
            }
            case COVERAGE_GAP -> FindingSubtype.UNCRAWLED_ENDPOINT;
            case INFORMATIONAL -> {
                if (lower.contains("scan completed") || lower.contains("no critical")) yield FindingSubtype.SCAN_COMPLETED;
                if (lower.contains("clean")) yield FindingSubtype.CLEAN_SCAN;
                yield FindingSubtype.INFO_DISCLOSURE;
            }
        };
    }

    private String validateCwe(FindingClass findingClass, String cwe, Boolean confirmed) {
        if (cwe == null) return null;
        if (findingClass != FindingClass.VULNERABILITY) return null;
        if (!Boolean.TRUE.equals(confirmed)) return null;

        // Validate CWE format
        if (!cwe.matches("CWE-\\d+")) return null;

        // CWE-693 is overused as fallback — reject unless specifically confirmed
        if ("CWE-693".equals(cwe)) return null;

        return cwe;
    }

    private String determineEvidenceStrength(FindingClass findingClass, Boolean confirmed, Map<String, Object> obs) {
        if (findingClass == FindingClass.SCAN_ISSUE) return "CONFIRMED"; // issue itself is confirmed
        if (findingClass == FindingClass.COVERAGE_GAP) return "CONFIRMED";
        if (findingClass == FindingClass.INFORMATIONAL) return "MODERATE";

        // For vulnerabilities, check evidence
        if (Boolean.TRUE.equals(confirmed)) {
            String payload = (String) obs.get("payload");
            if (payload != null) return "STRONG";
            return "MODERATE";
        }

        return "WEAK";
    }

    private Map<String, Double> calculateConfidence(FindingClass findingClass, Boolean confirmed, Map<String, Object> obs) {
        Map<String, Double> confidence = new LinkedHashMap<>();

        // Detection confidence: how sure are we that we saw something?
        confidence.put("detection", findingClass == FindingClass.SCAN_ISSUE ? 1.0 :
                findingClass == FindingClass.VULNERABILITY ? 0.9 : 0.7);

        // Classification confidence: how sure are we about the classification?
        confidence.put("classification", confirmed != null && confirmed ? 0.95 : 0.5);

        // Vulnerability confidence: how sure are we there's a real vulnerability?
        confidence.put("vulnerability", Boolean.TRUE.equals(confirmed) ? 0.85 : 0.0);

        // Root cause confidence: can we determine root cause?
        confidence.put("root_cause", Boolean.TRUE.equals(confirmed) ? 0.7 : 0.0);

        // Business impact confidence
        confidence.put("business_impact", Boolean.TRUE.equals(confirmed) ? 0.6 : 0.0);

        return confidence;
    }

    public record Classification(
            FindingClass findingClass,
            FindingSubtype findingSubtype,
            String validatedCwe,
            boolean assignCvss,
            String evidenceStrength,
            Map<String, Double> confidence
    ) {}
}
