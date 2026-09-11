package com.vulnerax.modules.scan.analyzers;

import java.util.*;
import java.util.regex.Pattern;

public class SastAnalyzer {

    private static final List<Rule> RULES = List.of(
        // === INJECTION ===
        new Rule("SQL Injection", "CWE-89", Pattern.compile("Statement\\s+.*\\+.*|\"SELECT.*\"\\s*\\+|createQuery\\s*\\(.*\\+|createNativeQuery.*\\+"), "Unsanitized SQL concatenation", "CRITICAL", "Use parameterized query / PreparedStatement"),
        new Rule("NoSQL Injection", "CWE-943", Pattern.compile("\\$where\\s*:|\\$regex\\s*:|\\$gt\\s*:|\\.find\\s*\\(\\s*\\{.*\\+"), "NoSQL query injection via concatenation", "CRITICAL", "Use type-safe queries, validate input"),
        new Rule("Command Injection", "CWE-78", Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec\\s*\\(|ProcessBuilder|exec\\s*\\(|system\\s*\\(|os\\.system\\s*\\(|subprocess\\.call|subprocess\\.Popen"), "Unsafe command execution", "CRITICAL", "Avoid exec with user input; use allowlist"),
        new Rule("Template Injection (SSTI)", "CWE-1336", Pattern.compile("FreeMarker.*\\+.*|Thymeleaf.*\\+.*|\\.eval\\s*\\(.*\\+.*|template.*render.*\\+.*"), "Server-side template injection", "CRITICAL", "Never concatenate user input into templates"),
        new Rule("LDAP Injection", "CWE-90", Pattern.compile("DirContext\\.search|ldap\\.search|LdapContext.*\\+.*"), "LDAP query injection", "HIGH", "Escape special chars in LDAP input"),
        new Rule("XPath Injection", "CWE-91", Pattern.compile("XPathExpression|xpath\\.compile.*\\+|/xpath.*\\+"), "XPath query injection", "HIGH", "Use parameterized XPath"),
        new Rule("Expression Language Injection", "CWE-917", Pattern.compile("ExpressionFactory.*eval|ELProcessor.*eval|\\$\\{.*\\+.*\\}|SpelExpressionParser"), "EL injection", "HIGH", "Don't evaluate user-controlled EL expressions"),

        // === XSS / CLIENT INJECTION ===
        new Rule("Reflected XSS", "CWE-79", Pattern.compile("innerHTML\\s*=|document\\.write\\s*\\(|\\.html\\s*\\(|\\.append\\s*\\(.*\\+"), "XSS via DOM manipulation", "HIGH", "Use textContent, encode output"),
        new Rule("DOM XSS Source", "CWE-79", Pattern.compile("location\\.hash|location\\.search|document\\.URL|document\\.referrer|window\\.name"), "DOM XSS source — data flows to sink", "MEDIUM", "Validate and sanitize DOM sources"),

        // === SSRF ===
        new Rule("SSRF", "CWE-918", Pattern.compile("URL\\s*\\(.*\\+|new\\s+URL\\s*\\(.*\\+|RestTemplate.*exchange.*\\+|WebClient.*uri.*\\+|HttpClient.*GET.*\\+|http\\.get.*\\+|fetch\\s*\\(.*\\+|requests\\.get\\s*\\(.*\\+"), "Potential SSRF — user input in URL", "CRITICAL", "Validate URL against allowlist"),

        // === PATH TRAVERSAL ===
        new Rule("Path Traversal", "CWE-22", Pattern.compile("new\\s+File\\s*\\(.*\\+|Paths\\.get\\s*\\(.*\\+|fs\\.readFile.*\\+|open\\s*\\(.*\\+|Path\\.resolve.*\\+"), "Path traversal via concatenation", "CRITICAL", "Normalize path, restrict to allowed dirs"),

        // === FILE HANDLING ===
        new Rule("Unsafe File Upload", "CWE-434", Pattern.compile("MultipartFile.*getOriginalFilename|upload.*filename|multipart.*file.*name"), "Filename from user — potential path traversal", "HIGH", "Sanitize filename, don't use original name"),
        new Rule("Unsafe File Write", "CWE-73", Pattern.compile("FileOutputStream|Files\\.copy.*InputStream|writeFile.*\\+"), "File write with dynamic path", "HIGH", "Validate path, restrict directory"),

        // === DESERIALIZATION ===
        new Rule("Insecure Deserialization", "CWE-502", Pattern.compile("ObjectInputStream|readObject\\s*\\(|XMLDecoder|Yaml\\.load\\s*\\(|pickle\\.loads|marshal\\.loads|yaml\\.unsafe_load"), "Unsafe deserialization", "CRITICAL", "Avoid native deserialization; use JSON with type whitelist"),

        // === XXE ===
        new Rule("XXE", "CWE-611", Pattern.compile("DocumentBuilderFactory|SAXParser|XMLReader|TransformerFactory|SchemaFactory|xmllint"), "Potential XXE — parser may allow external entities", "HIGH", "Disable DTDs and external entities"),
        new Rule("XXE (Python)", "CWE-611", Pattern.compile("xml\\.etree\\.ElementTree|lxml\\.etree|defusedxml"), "XML parsing — check if defused", "MEDIUM", "Use defusedxml library"),

        // === CRYPTO ===
        new Rule("Weak Crypto (MD5/SHA1/DES)", "CWE-327", Pattern.compile("MessageDigest\\.getInstance\\s*\\(\"MD5\"|MessageDigest\\.getInstance\\s*\\(\"SHA-1\"|Cipher\\.getInstance\\s*\\(\"DES|MD5\\s*\\(|sha1\\s*\\("), "Weak cryptographic algorithm", "HIGH", "Use SHA-256+ / AES-GCM"),
        new Rule("Hardcoded Key", "CWE-798", Pattern.compile("secret\\s*[:=]\\s*\"[^\"]{8,}\"|apikey\\s*[:=]\\s*\"[^\"]+\"|private[_-]?key\\s*[:=]\\s*\"BEGIN"), "Hardcoded cryptographic key", "CRITICAL", "Use key management service"),
        new Rule("Insecure Random", "CWE-330", Pattern.compile("new\\s+Random\\s*\\(|Math\\.random\\s*\\(|random\\.random\\s*\\(|rand\\.random\\s*\\(|Math\\.random\\(\\)\\s*\\*"), "Insecure randomness for security context", "MEDIUM", "Use SecureRandom / secrets module"),

        // === AUTH / SESSION ===
        new Rule("Hardcoded Credential", "CWE-798", Pattern.compile("password\\s*[:=]\\s*\"[^\"]+\"|passwd\\s*[:=]\\s*\"[^\"]+\"|credential\\s*[:=]\\s*\"[^\"]+\""), "Hardcoded credential", "CRITICAL", "Move to Vault / env variable"),
        new Rule("Weak Password Hash", "CWE-328", Pattern.compile("MessageDigest\\.getInstance\\s*\\(\"MD5\"\\)|MessageDigest\\.getInstance\\s*\\(\"SHA-1\"\\)|sha1\\(|md5\\("), "Weak password hashing", "HIGH", "Use bcrypt/scrypt/argon2"),
        new Rule("JWT None Algorithm", "CWE-347", Pattern.compile("algorithm.*none|\"alg\"\\s*:\\s*\"none\"|verify\\s*\\(\\s*false"), "JWT algorithm none — signature bypass", "CRITICAL", "Always verify signature, reject 'none'"),
        new Rule("Session Fixation", "CWE-384", Pattern.compile("session\\.getId\\s*\\(|request\\.getSession\\s*\\(true\\)"), "Session fixation risk — not regenerating ID", "MEDIUM", "Regenerate session ID after login"),

        // === BOLA / AUTHORIZATION ===
        new Rule("BOLA (IDOR)", "CWE-639", Pattern.compile("/\\{id\\}|getAccount\\s*\\(|findById\\s*\\(.*id\\)|@PathVariable.*id"), "Potential BOLA — check object-level auth", "HIGH", "Validate ownership for every object access"),
        new Rule("Mass Assignment", "CWE-915", Pattern.compile("@RequestBody|@ModelAttribute|setProperties|setattr.*\\+"), "Mass assignment risk — bind all user input", "MEDIUM", "Use DTO with explicit whitelist"),

        // === INFO DISCLOSURE ===
        new Rule("Verbose Error", "CWE-209", Pattern.compile("printStackTrace\\s*\\(|e\\.getMessage\\s*\\(\\)|err\\.printStackTrace|console\\.log.*error"), "Stack trace / error detail exposed", "MEDIUM", "Return generic error, log details server-side"),
        new Rule("Debug Mode", "CWE-489", Pattern.compile("debug\\s*=\\s*true|DEBUG\\s*=\\s*True|console\\.log\\s*\\("), "Debug mode enabled in production", "MEDIUM", "Disable debug in production"),

        // === CACHE ===
        new Rule("Cache-Control Missing", "CWE-525", Pattern.compile("Cache-Control|no-cache|no-store"), "Check if cache-control is set properly", "INFO", "Set Cache-Control: no-store for sensitive data"),

        // === CRYPTO INDICATORS ===
        new Rule("Base64 as Encoding", "CWE-327", Pattern.compile("Base64\\.getEncoder|b64encode|base64\\.b64encode"), "Base64 is encoding, not encryption — may hide secrets", "INFO", "Don't use Base64 as security measure"),

        // === RACE CONDITION INDICATORS ===
        new Rule("Race Condition Risk", "CWE-362", Pattern.compile("synchronized\\s*\\(|ReentrantLock|AtomicInteger|compareAndSet|@Transactional.*propagation"), "Concurrency control — potential race condition", "MEDIUM", "Use proper locking / optimistic concurrency"),

        // === OAUTH ===
        new Rule("OAuth State Missing", "CWE-352", Pattern.compile("oauth.*redirect|authorization_code|access_token.*url"), "OAuth flow — verify state parameter is used", "MEDIUM", "Implement state/nonce for CSRF protection"),

        // === API SECURITY ===
        new Rule("API Key in Code", "CWE-798", Pattern.compile("api[_-]?key\\s*[:=]\\s*\"[A-Za-z0-9]{20,}\"|AKIA[A-Z0-9]{16}"), "API key found in source", "HIGH", "Move to environment / secrets manager"),

        // === SUPPLY CHAIN ===
        new Rule("Untrusted Dependency Import", "CWE-829", Pattern.compile("import.*from\\s+\"[^\"]+\"|require\\s*\\(\\s*\"[^\"]+\""), "External dependency import — check trust", "INFO", "Audit dependencies regularly")
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
                    "title", r.name + " — " + r.cwe,
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
