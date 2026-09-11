package com.vulnerax.modules.scan.analyzers;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

public class ApiAnalyzer {

    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(8))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public static List<Map<String,Object>> analyze(String target) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (target == null || !target.startsWith("http")) return out;
        String base = target.replaceAll("/$", "");

        // 1. Swagger / OpenAPI discovery
        String[] apiDocs = {"/swagger-ui.html", "/swagger-ui/", "/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json", "/docs", "/redoc"};
        for (String path : apiDocs) {
            try {
                HttpResponse<String> r = fetch(base + path);
                if (r != null && r.statusCode() == 200 && r.body() != null && r.body().length() > 100) {
                    String body = r.body().toLowerCase();
                    if (body.contains("swagger") || body.contains("openapi") || body.contains("paths") || body.contains("info")) {
                        out.add(mk("API Docs Exposed: " + path, "CWE-200", "HIGH",
                            "API documentation publicly accessible at " + path + " — attacker enumerate all endpoints",
                            base + path, 0, "Restrict API docs to internal network / auth"));
                        break;
                    }
                }
            } catch (Exception ignored) {}
        }

        // 2. GraphQL introspection
        try {
            String gql = "{\"query\":\"{__schema{types{name,fields{name,args{name}}}}\"}";
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(base + "/graphql"))
                .timeout(Duration.ofSeconds(8))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gql)).build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (r != null && r.statusCode() == 200 && r.body() != null && r.body().contains("__schema")) {
                out.add(mk("GraphQL Introspection Enabled", "CWE-200", "HIGH",
                    "Full GraphQL schema exposed via introspection — all types/queries enumerable",
                    base + "/graphql", 0, "Disable introspection in production"));
            }
        } catch (Exception ignored) {}

        // 3. Common API endpoint enumeration
        String[] endpoints = {
            "/api/v1/users", "/api/v1/admin", "/api/v1/config", "/api/v1/health",
            "/api/users", "/api/admin", "/api/config", "/api/health",
            "/admin", "/admin/api", "/.well-known/openid-configuration",
            "/oauth2/token", "/oauth2/authorize", "/api/v1/secrets", "/api/v1/debug"
        };
        for (String ep : endpoints) {
            try {
                HttpResponse<String> r = fetch(base + ep);
                if (r != null && r.statusCode() == 200 && r.body() != null && r.body().length() > 20) {
                    String body = r.body().toLowerCase();
                    if (body.contains("user") || body.contains("admin") || body.contains("config") ||
                        body.contains("token") || body.contains("secret") || body.contains("debug")) {
                        out.add(mk("API Endpoint Exposed: " + ep, "CWE-284", "MEDIUM",
                            "Endpoint " + ep + " accessible and returns data",
                            base + ep, 0, "Restrict access, add authentication"));
                    }
                }
            } catch (Exception ignored) {}
        }

        // 4. Check API authentication — try accessing without token
        try {
            HttpResponse<String> r = fetch(base + "/api/v1/users");
            if (r != null && r.statusCode() == 200) {
                out.add(mk("API No Auth Required", "CWE-306", "HIGH",
                    "GET /api/v1/users accessible without authentication",
                    base + "/api/v1/users", 0, "Add authentication middleware"));
            }
        } catch (Exception ignored) {}

        // 5. Check HTTP methods
        String[] methods = {"PUT", "DELETE", "PATCH"};
        for (String method : methods) {
            try {
                HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(base + "/api"))
                    .timeout(Duration.ofSeconds(5))
                    .method(method, HttpRequest.BodyPublishers.noBody()).build();
                HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (r != null && r.statusCode() < 400) {
                    out.add(mk("HTTP " + method + " Allowed on /api", "CWE-749", "MEDIUM",
                        method + " method accepted — verify authorization for state-changing operations",
                        base + "/api", 0, "Restrict dangerous HTTP methods"));
                }
            } catch (Exception ignored) {}
        }

        // 6. CORS check
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(base + "/api"))
                .timeout(Duration.ofSeconds(5))
                .header("Origin", "https://evil.com")
                .GET().build();
            HttpResponse<String> r = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (r != null) {
                List<String> acao = r.headers().allValues("access-control-allow-origin");
                if (acao.contains("*") || acao.contains("https://evil.com")) {
                    out.add(mk("CORS Accepts Evil Origin", "CWE-942", "HIGH",
                        "API accepts Origin: https://evil.com — credential theft possible",
                        base + "/api", 0, "Whitelist allowed origins"));
                }
            }
        } catch (Exception ignored) {}

        // 7. Rate limiting check
        boolean rateLimited = false;
        for (int i = 0; i < 10; i++) {
            try {
                HttpResponse<String> r = fetch(base + "/api");
                if (r != null && r.statusCode() == 429) { rateLimited = true; break; }
            } catch (Exception ignored) {}
        }
        if (!rateLimited) {
            out.add(mk("API No Rate Limiting", "CWE-770", "MEDIUM",
                "10 rapid API requests — no 429 response — brute-force/DoS possible",
                base + "/api", 0, "Add rate limiting middleware"));
        }

        // 8. API versioning — old versions may have vulns
        String[] oldVersions = {"/v1/", "/v2/", "/api/v1/", "/api/v2/"};
        for (String v : oldVersions) {
            try {
                HttpResponse<String> r = fetch(base + v);
                if (r != null && r.statusCode() == 200) {
                    out.add(mk("API Version Exposed: " + v, "CWE-200", "INFO",
                        "API version " + v + " accessible — old versions may have vulnerabilities",
                        base + v, 0, "Deprecate old versions, redirect to current"));
                    break;
                }
            } catch (Exception ignored) {}
        }

        if (out.isEmpty()) {
            out.add(mk("API Scan Complete", "CWE-284", "INFO",
                "No critical API security issue found for " + base,
                base, 0, "Review full API surface manually"));
        }
        return out;
    }

    private static HttpResponse<String> fetch(String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(8))
                .header("User-Agent", "VulneraX-API/1.0")
                .header("Accept", "application/json,text/html,*/*")
                .GET().build();
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (Exception e) { return null; }
    }

    private static Map<String,Object> mk(String title, String cwe, String severity, String desc, String file, int line, String rec) {
        Map<String,Object> m = new HashMap<>();
        m.put("title", title); m.put("rule", title); m.put("cwe", cwe);
        m.put("severity", severity); m.put("file", file); m.put("line", line);
        m.put("snippet", desc); m.put("recommendation", rec); m.put("match", title);
        return m;
    }
}
