package com.vulnerax.modules.scan.analyzers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

public class DastAnalyzer {

    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public static List<Map<String,Object>> analyze(String target, String fileName) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (target == null || !target.startsWith("http")) return out;
        String base = target.trim();
        String url = base;
        long start = System.currentTimeMillis();
        try {
            HttpResponse<String> resp = fetch(url);
            if (resp == null) {
                out.add(mk("Target Unreachable", "CWE-693", "MEDIUM", "Tidak bisa fetch target " + url, url, 1, "Periksa apakah target internet-exposed"));
                return out;
            }
            int code = resp.statusCode();
            String body = resp.body() != null ? resp.body() : "";
            Map<String, List<String>> headers = resp.headers().map();

            // ===== SECURITY HEADERS =====
            checkHeader(out, headers, url, "Content-Security-Policy", "CWE-693", "MEDIUM", "Missing CSP — rentan XSS/data injection");
            checkHeader(out, headers, url, "Strict-Transport-Security", "CWE-319", "MEDIUM", "Missing HSTS — rentan downgrade attack");
            checkHeader(out, headers, url, "X-Frame-Options", "CWE-1021", "LOW", "Missing X-Frame-Options — clickjacking");
            checkHeader(out, headers, url, "X-Content-Type-Options", "CWE-693", "LOW", "Missing X-Content-Type-Options nosniff");
            checkHeader(out, headers, url, "Referrer-Policy", "CWE-200", "INFO", "Missing Referrer-Policy — info leakage");
            checkHeader(out, headers, url, "Permissions-Policy", "CWE-693", "INFO", "Missing Permissions-Policy — browser features uncontrolled");
            checkHeader(out, headers, url, "X-XSS-Protection", "CWE-79", "INFO", "Missing X-XSS-Protection (legacy but defense-in-depth)");
            checkHeader(out, headers, url, "Cross-Origin-Opener-Policy", "CWE-346", "INFO", "Missing COOP — Spectre-class risk");
            checkHeader(out, headers, url, "Cross-Origin-Resource-Policy", "CWE-346", "INFO", "Missing CORP — cross-origin resource leak");
            checkHeader(out, headers, url, "Cross-Origin-Embedder-Policy", "CWE-346", "INFO", "Missing COEP — cross-origin leak");

            // ===== TLS / HTTP =====
            if (url.startsWith("http://")) {
                out.add(mk("Cleartext HTTP", "CWE-319", "HIGH", "Target pakai HTTP — kredensial bisa di-sniff", url, 1, "Enforce HTTPS + redirect http->https"));
            }

            // ===== CORS =====
            List<String> cors = headers.getOrDefault("access-control-allow-origin", List.of());
            if (cors.stream().anyMatch(v -> v.equals("*"))) {
                out.add(mk("Wildcard CORS", "CWE-942", "HIGH", "CORS: * — API bisa diakses cross-origin tanpa batas", url, 1, "Restrict ke origin whitelist"));
            }
            List<String> cac = headers.getOrDefault("access-control-allow-credentials", List.of());
            if (cors.stream().anyMatch(v -> v.equals("*")) && cac.stream().anyMatch(v -> v.equalsIgnoreCase("true"))) {
                out.add(mk("CORS + Credentials", "CWE-942", "CRITICAL", "CORS * + credentials:true — attacker bisa curi data user", url, 1, "Gunakan origin spesifik"));
            }

            // ===== SESSION / COOKIE =====
            List<String> cookies = headers.getOrDefault("set-cookie", List.of());
            for (String ck : cookies) {
                String low = ck.toLowerCase();
                if (!low.contains("httponly")) out.add(mk("Cookie Missing HttpOnly", "CWE-1004", "MEDIUM", "Cookie tanpa HttpOnly: " + ck.substring(0, Math.min(80, ck.length())), url, 1, "Set HttpOnly"));
                if (!low.contains("secure") && url.startsWith("https://")) out.add(mk("Cookie Missing Secure", "CWE-614", "MEDIUM", "Cookie tanpa Secure flag di HTTPS", url, 1, "Set Secure"));
                if (!low.contains("samesite")) out.add(mk("Cookie Missing SameSite", "CWE-16", "LOW", "Cookie tanpa SameSite", url, 1, "Set SameSite=Lax/Strict"));
                break;
            }

            // ===== INFO DISCLOSURE =====
            // Server banner
            List<String> server = headers.getOrDefault("server", List.of());
            if (!server.isEmpty()) {
                String sv = server.get(0);
                if (sv.matches(".*\\d+\\..*") || sv.length() > 30)
                    out.add(mk("Server Version Disclosure", "CWE-200", "INFO", "Server header expose version: " + sv, url, 1, "Hide server version"));
            }
            List<String> powered = headers.getOrDefault("x-powered-by", List.of());
            if (!powered.isEmpty())
                out.add(mk("X-Powered-By Disclosure", "CWE-200", "MEDIUM", "X-Powered-By: " + powered.get(0) + " — info leakage", url, 1, "Remove X-Powered-By"));

            // Debug endpoints
            String[] debugPaths = {"/actuator", "/actuator/env", "/actuator/health", "/debug", "/trace", "/swagger-ui.html", "/swagger-ui/", "/api-docs"};
            for (String p : debugPaths) {
                try {
                    HttpResponse<String> r = fetch(url.replaceAll("/$", "") + p);
                    if (r != null && r.statusCode() == 200 && r.body() != null && r.body().length() > 50) {
                        if (p.contains("actuator/env") || p.equals("/trace"))
                            out.add(mk("Debug Endpoint Exposed: " + p, "CWE-200", "HIGH", "Endpoint " + p + " bisa diakses publik", url + p, 1, "Restrict admin endpoints"));
                        else
                            out.add(mk("Admin Endpoint: " + p, "CWE-200", "INFO", "Endpoint " + p + " accessible", url + p, 1, "Restrict if not intended"));
                    }
                } catch (Exception ignored) {}
            }

            // ===== SENSITIVE FILE EXPOSURE =====
            String[] sensitivePaths = {"/.env", "/.git/HEAD", "/.git/config", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/backup.zip", "/config.yml", "/config.json", "/.DS_Store", "/wp-config.php.bak", "/web.config"};
            for (String p : sensitivePaths) {
                try {
                    HttpResponse<String> r = fetch(url.replaceAll("/$", "") + p);
                    if (r != null && r.statusCode() == 200 && r.body() != null && r.body().length() > 10 && !r.body().contains("404")) {
                        if (p.equals("/.env") || p.startsWith("/.git") || p.equals("/.DS_Store")) {
                            out.add(mk("Sensitive File Exposed: " + p, "CWE-538", "HIGH", "File " + p + " bisa diakses publik (200 OK, " + r.body().length() + " bytes)", url + p, 1, "Block via nginx/ACL"));
                        } else if (p.equals("/robots.txt")) {
                            out.add(mk("Robots.txt Disclosure", "CWE-200", "INFO", "robots.txt expose directory structure", url + p, 1, "Review disallowed paths"));
                        }
                    }
                } catch (Exception ignored) {}
            }

            // ===== INJECTION TESTS =====
            // XSS reflection
            try {
                String xssPayload = "<script>alert(1)</script>";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "vulnerax_test=" + java.net.URLEncoder.encode(xssPayload, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null && r.body().contains(xssPayload)) {
                    out.add(mk("Reflected XSS", "CWE-79", "CRITICAL", "Payload XSS direfleksikan di response body", testUrl, 1, "Encode output, set CSP"));
                }
            } catch (Exception ignored) {}

            // SQLi error-based
            try {
                String sqli = "' OR '1'='1";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "id=" + java.net.URLEncoder.encode(sqli, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null) {
                    String low = r.body().toLowerCase();
                    if (low.contains("sql syntax") || low.contains("mysql") || low.contains("psql") || low.contains("ora-") || low.contains("sqlite") || low.contains("unterminated")) {
                        out.add(mk("SQL Injection (Error-based)", "CWE-89", "CRITICAL", "SQL error ter-expose saat inject", testUrl, 1, "Use parameterized query"));
                    }
                }
            } catch (Exception ignored) {}

            // NoSQL injection
            try {
                String nosql = "{\"$gt\":\"\"}";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "q=" + java.net.URLEncoder.encode(nosql, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null) {
                    String low = r.body().toLowerCase();
                    if (low.contains("mongodb") || low.contains("mongod") || low.contains("nosql")) {
                        out.add(mk("NoSQL Injection Indicator", "CWE-943", "HIGH", "NoSQL error ter-expose — mungkin rentan NoSQL injection", testUrl, 1, "Sanitize input, gunakan type-safe queries"));
                    }
                }
            } catch (Exception ignored) {}

            // Command injection indicator
            try {
                String cmd = "`id`";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "cmd=" + java.net.URLEncoder.encode(cmd, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null && (r.body().contains("uid=") || r.body().contains("root:"))) {
                    out.add(mk("Command Injection", "CWE-78", "CRITICAL", "Command output ter-expose — command injection confirmed", testUrl, 1, "Never pass user input to shell commands"));
                }
            } catch (Exception ignored) {}

            // Path traversal
            try {
                String traversal = "../../../etc/passwd";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "file=" + java.net.URLEncoder.encode(traversal, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null && (r.body().contains("root:x:") || r.body().contains("root:0:0"))) {
                    out.add(mk("Path Traversal", "CWE-22", "CRITICAL", "File /etc/passwd terbaca via traversal", testUrl, 1, "Normalize path, restrict to allowed dirs"));
                }
            } catch (Exception ignored) {}

            // Open redirect
            try {
                String redir = "https://evil.com";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "redirect=" + java.net.URLEncoder.encode(redir, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && (r.statusCode() == 301 || r.statusCode() == 302)) {
                    String loc = r.headers().firstValue("location").orElse("");
                    if (loc.contains("evil.com")) {
                        out.add(mk("Open Redirect", "CWE-601", "HIGH", "Redirect ke evil.com via Location header", testUrl, 1, "Whitelist redirect targets"));
                    }
                }
            } catch (Exception ignored) {}

            // SSRF indicator — check if URL param reflects external content
            try {
                String ssrfUrl = "http://169.254.169.254/latest/meta-data/";
                String testUrl = url + (url.contains("?") ? "&" : "?") + "url=" + java.net.URLEncoder.encode(ssrfUrl, java.nio.charset.StandardCharsets.UTF_8);
                HttpResponse<String> r = fetch(testUrl);
                if (r != null && r.body() != null && (r.body().contains("ami-id") || r.body().contains("instance-id"))) {
                    out.add(mk("SSRF to Cloud Metadata", "CWE-918", "CRITICAL", "SSRF ke AWS metadata endpoint — bisa curi credentials", testUrl, 1, "Block outbound to metadata IP, validate URL input"));
                }
            } catch (Exception ignored) {}

            // XXE via POST
            try {
                String xxe = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>";
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/xml")
                    .POST(HttpRequest.BodyPublishers.ofString(xxe)).build();
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r != null && r.body() != null && r.body().contains("root:x:")) {
                    out.add(mk("XXE Injection", "CWE-611", "CRITICAL", "File content ter-expose via XXE", url, 1, "Disable external entities in XML parser"));
                }
            } catch (Exception ignored) {}

            // CSRF indicator — check if forms lack CSRF token
            if (body.toLowerCase().contains("<form") && !body.toLowerCase().contains("csrf") && !body.toLowerCase().contains("_token") && !body.toLowerCase().contains("xsrf")) {
                out.add(mk("No CSRF Token in Forms", "CWE-352", "MEDIUM", "Form ditemukan tanpa CSRF token — rentan cross-site request forgery", url, 1, "Tambahkan anti-CSRF token"));
            }

            // ===== JWT / AUTH =====
            // JWT in URL
            if (url.contains("token=") || url.contains("access_token=")) {
                out.add(mk("JWT/Token in URL", "CWE-598", "MEDIUM", "Token ter-expose di URL — bisa leak via Referer/Logs", url, 1, "Gunakan Authorization header"));
            }

            // ===== GRAPHQL =====
            try {
                String gql = "{\"query\":\"{__schema{types{name,fields{name}}}}\"}";
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url.replaceAll("/$", "") + "/graphql"))
                    .timeout(Duration.ofSeconds(8))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(gql)).build();
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r != null && r.statusCode() == 200 && r.body() != null && r.body().contains("__schema")) {
                    out.add(mk("GraphQL Introspection Enabled", "CWE-200", "HIGH", "GraphQL schema exposed via introspection — attacker bisa enumerate semua type", url + "/graphql", 1, "Disable introspection in production"));
                }
            } catch (Exception ignored) {}

            // Try /graphql GET
            try {
                HttpResponse<String> r = fetch(url.replaceAll("/$", "") + "/graphql?query={__typename}");
                if (r != null && r.statusCode() == 200 && r.body() != null && r.body().contains("__typename")) {
                    if (out.stream().noneMatch(m -> ((String)m.get("title")).contains("GraphQL")))
                        out.add(mk("GraphQL Endpoint Exposed", "CWE-200", "MEDIUM", "GraphQL accessible via GET without auth", url + "/graphql", 1, "Restrict GraphQL access"));
                }
            } catch (Exception ignored) {}

            // ===== WEBSOCKET =====
            try {
                HttpResponse<String> r = fetch(url.replaceAll("/$", "") + "/ws");
                if (r != null && (r.statusCode() == 101 || r.statusCode() == 426)) {
                    out.add(mk("WebSocket Endpoint Found", "CWE-693", "MEDIUM", "WebSocket endpoint detected — periksa autentikasi & validasi pesan", url + "/ws", 1, "Authenticasi WebSocket, validasi input"));
                }
            } catch (Exception ignored) {}

            // ===== RATE LIMITING =====
            // Check for rate limit headers
            boolean hasRateLimit = headers.keySet().stream().anyMatch(k ->
                k.equalsIgnoreCase("x-ratelimit-limit") || k.equalsIgnoreCase("retry-after") || k.equalsIgnoreCase("ratelimit-limit"));
            if (!hasRateLimit && !url.contains("localhost")) {
                // Check if multiple rapid requests succeed
                boolean rateLimited = false;
                for (int i = 0; i < 5; i++) {
                    try {
                        HttpResponse<String> r = fetch(url);
                        if (r != null && r.statusCode() == 429) { rateLimited = true; break; }
                    } catch (Exception ignored) {}
                }
                if (!rateLimited) {
                    out.add(mk("No Rate Limiting Detected", "CWE-770", "MEDIUM", "Tidak ada rate limit header, 5 rapid request semua sukses — rentan brute-force/DoS", url, 1, "Tambahkan rate limiting + 429 response"));
                }
            }

            // ===== BUSINESS LOGIC indicators =====
            // Check for common state-changing endpoints without auth
            String[] stateEndpoints = {"/api/admin", "/api/users", "/api/delete", "/api/update", "/api/transfer"};
            for (String ep : stateEndpoints) {
                try {
                    HttpResponse<String> r = fetch(url.replaceAll("/$", "") + ep);
                    if (r != null && r.statusCode() == 200) {
                        out.add(mk("Unauthenticated State-Change: " + ep, "CWE-862", "HIGH", "Endpoint " + ep + " accessible tanpa auth — bypass authorization check", url + ep, 1, "Require authentication + RBAC"));
                    }
                } catch (Exception ignored) {}
            }

            // ===== SPEED / PERFORMANCE =====
            long dur = System.currentTimeMillis() - start;
            if (dur > 5000) {
                out.add(mk("Slow Response (>5s)", "CWE-770", "INFO", "Response time " + dur + "ms — rentan DoS/slowloris", url, 1, "Optimize + rate limit"));
            }

            // ===== WAF DETECTION =====
            if (body.toLowerCase().contains("cloudflare") || body.toLowerCase().contains("attention required") || body.toLowerCase().contains("checking your browser")) {
                out.add(mk("WAF Detected", "CWE-693", "INFO", "Target di belakang WAF — DAST mungkin terbatas", url, 1, "Test via direct origin"));
            }

            // Ensure at least 1 finding
            if (out.isEmpty()) {
                out.add(mk("DAST Scan Completed — No Critical Issue", "CWE-693", "INFO", "Semua header utama present, injection tests negative", url, 1, "Pertahankan hardening"));
            }
        } catch (Exception e) {
            out.add(mk("DAST Error", "CWE-693", "INFO", "Error: " + e.getMessage(), target, 1, "Pastikan target accessible"));
        }
        return out;
    }

    private static HttpResponse<String> fetch(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "VulneraX-DAST/1.0 (+https://vulnerax.io)")
                    .header("Accept", "text/html,application/json,*/*")
                    .GET().build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) { return null; }
    }

    private static void checkHeader(List<Map<String,Object>> out, Map<String, List<String>> headers, String url, String headerName, String cwe, String severity, String rec) {
        boolean present = headers.keySet().stream().anyMatch(k -> k.equalsIgnoreCase(headerName));
        if (!present) {
            out.add(mk("Missing Header: " + headerName, cwe, severity, rec, url, 1, "Add " + headerName));
        }
    }

    private static Map<String,Object> mk(String title, String cwe, String severity, String desc, String url, int line, String rec) {
        Map<String,Object> m = new HashMap<>();
        m.put("title", title);
        m.put("rule", title);
        m.put("cwe", cwe);
        m.put("severity", severity);
        m.put("file", url);
        m.put("line", line);
        m.put("snippet", desc);
        m.put("recommendation", rec);
        m.put("match", title);
        return m;
    }
}
