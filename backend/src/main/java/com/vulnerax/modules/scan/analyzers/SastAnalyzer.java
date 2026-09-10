package com.vulnerax.modules.scan.analyzers;

import java.util.*;
import java.util.regex.Pattern;

public class SastAnalyzer {

    private static final List<Rule> RULES = List.of(
        new Rule("SQL Injection", "CWE-89", Pattern.compile("Statement\\s+.*\\+.*|\"SELECT.*\"\\s*\\+|createQuery\\s*\\(.*\\+"), "Unsanitized SQL concatenation", "HIGH", "Use parameterized query / PreparedStatement"),
        new Rule("Command Injection", "CWE-78", Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|ProcessBuilder\\s*\\(|exec\\s*\\("), "Unsafe command execution", "CRITICAL", "Avoid exec with user input; use allowlist"),
        new Rule("XSS", "CWE-79", Pattern.compile("innerHTML\\s*=|document\\.write\\s*\\(|\\.html\\s*\\("), "Potential XSS via innerHTML", "MEDIUM", "Encode output, use textContent"),
        new Rule("Hardcoded Secret", "CWE-798", Pattern.compile("password\\s*[:=]\\s*\"[^\"]+\"|secret\\s*[:=]\\s*\"[^\"]+\"", Pattern.CASE_INSENSITIVE), "Hardcoded credential", "HIGH", "Move to Vault / env"),
        new Rule("Insecure Random", "CWE-330", Pattern.compile("new\\s+Random\\s*\\(|Math\\.random\\s*\\("), "Insecure randomness", "MEDIUM", "Use SecureRandom"),
        new Rule("SSRF", "CWE-918", Pattern.compile("http\\s*:\\s*//\\s*\\+|URL\\s*\\(.*\\+|RestTemplate.*exchange\\s*\\(.*\\+"), "Potential SSRF", "HIGH", "Validate allowlist URL"),
        new Rule("Path Traversal", "CWE-22", Pattern.compile("new\\s+File\\s*\\(.*\\+|Paths\\.get\\s*\\(.*\\+"), "Path traversal via concatenation", "HIGH", "Normalize and restrict path"),
        new Rule("XXE", "CWE-611", Pattern.compile("DocumentBuilderFactory\\.newInstance\\s*\\("), "Potential XXE", "HIGH", "Disable external entities"),
        new Rule("Insecure Deserialization", "CWE-502", Pattern.compile("ObjectInputStream\\s*\\(|readObject\\s*\\("), "Unsafe deserialization", "CRITICAL", "Avoid Java deserialization; use JSON"),
        new Rule("Weak Crypto", "CWE-327", Pattern.compile("MessageDigest\\.getInstance\\s*\\(\"MD5\"|Cipher\\.getInstance\\s*\\(\"DES"), "Weak cryptography", "MEDIUM", "Use SHA-256 / AES-GCM"),
        new Rule("BOLA", "CWE-639", Pattern.compile("/\\{id\\}|getAccount\\s*\\(|findById\\s*\\(.*id\\)"), "Potential BOLA - check ownership", "HIGH", "Validate object-level authorization")
    );

    public static List<Map<String,Object>> analyze(String content, String fileName) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (content == null || content.isEmpty()) return out;
        for (Rule r : RULES) {
            var m = r.pattern.matcher(content);
            if (m.find()) {
                out.add(Map.of(
                    "rule", r.name,
                    "cwe", r.cwe,
                    "severity", r.severity,
                    "title", r.title,
                    "file", fileName != null ? fileName : "unknown",
                    "line", lineNumber(content, m.start()),
                    "snippet", snippet(content, m.start()),
                    "recommendation", r.recommendation
                ));
            }
        }
        return out;
    }

    private static int lineNumber(String content, int off) {
        return (int) content.substring(0, Math.min(off, content.length())).chars().filter(ch -> ch=='\n').count()+1;
    }
    private static String snippet(String content, int off) {
        int start = Math.max(0, content.lastIndexOf('\n', off) + 1);
        int end = content.indexOf('\n', off);
        if (end==-1) end = Math.min(content.length(), start+120);
        else end = Math.min(end, start+120);
        return content.substring(start, end).trim();
    }
    private record Rule(String name, String cwe, Pattern pattern, String title, String severity, String recommendation) {}
}
