package com.vulnerax.modules.scan.analyzers;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Real secret detection on file content - not mock.
 * Scans actual bytes/string for patterns, returns findings only if matched.
 */
public class SecretAnalyzer {

    private static final List<Rule> RULES = List.of(
        new Rule("AWS Access Key", "CWE-798", Pattern.compile("AKIA[0-9A-Z]{16}"), "Hardcoded AWS Access Key", "HIGH"),
        new Rule("AWS Secret Key", "CWE-798", Pattern.compile("aws_secret_access_key\\s*=\\s*[A-Za-z0-9/+=]{20,}"), "Hardcoded AWS Secret", "HIGH"),
        new Rule("Private Key", "CWE-798", Pattern.compile("-----BEGIN (?:RSA )?PRIVATE KEY-----"), "Private Key Exposed", "CRITICAL"),
        new Rule("Generic API Key", "CWE-798", Pattern.compile("api_?key\\s*[:=]\\s*['\"][A-Za-z0-9_\\-]{20,}['\"]", Pattern.CASE_INSENSITIVE), "Hardcoded API Key", "HIGH"),
        new Rule("JWT Secret", "CWE-798", Pattern.compile("jwt_?secret\\s*[:=]\\s*['\"][^'\"]{8,}['\"]", Pattern.CASE_INSENSITIVE), "JWT Secret Hardcoded", "HIGH"),
        new Rule("Firebase Key", "CWE-798", Pattern.compile("AIza[0-9A-Za-z_\\-]{35}"), "Firebase API Key", "MEDIUM")
    );

    public static List<Map<String,Object>> analyze(String content, String fileName) {
        List<Map<String,Object>> findings = new ArrayList<>();
        if (content == null || content.isEmpty()) return findings;
        for (Rule r : RULES) {
            var m = r.pattern.matcher(content);
            while (m.find()) {
                String match = m.group();
                String masked = match.length() > 8 ? match.substring(0,4) + "****" + match.substring(match.length()-4) : "****";
                findings.add(Map.of(
                    "rule", r.name,
                    "cwe", r.cwe,
                    "severity", r.severity,
                    "title", r.title,
                    "file", fileName != null ? fileName : "unknown",
                    "line", lineNumber(content, m.start()),
                    "match", masked,
                    "rawLength", match.length()
                ));
                if (findings.size() >= 20) break;
            }
        }
        return findings;
    }

    private static int lineNumber(String content, int offset) {
        return (int) content.substring(0, Math.min(offset, content.length())).chars().filter(ch -> ch == '\n').count() + 1;
    }

    private record Rule(String name, String cwe, Pattern pattern, String title, String severity) {}
}
