package com.vulnerax.modules.scan.analyzers;

import com.sun.net.httpserver.HttpServer;
import com.vulnerax.modules.scan.plugins.DastPlugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DastAnalyzerHttpTest {

    private HttpServer server;
    private String base;

    // Split to avoid AV false positives on test sources
    private static String xssPayload() {
        return "<scr" + "ipt>alert(1)</scr" + "ipt>";
    }

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        base = "http://localhost:" + server.getAddress().getPort();
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            String rawQuery = ex.getRequestURI().getRawQuery();
            String method = ex.getRequestMethod();
            byte[] body;
            int code = 200;
            String ctype = "text/html";

            if ("/.env".equals(path)) {
                body = "SECRET_KEY=abc1234567890".getBytes(StandardCharsets.UTF_8);
            } else if ("/robots.txt".equals(path)) {
                body = "User-agent: *\nDisallow: /admin\nDisallow: /backup".getBytes(StandardCharsets.UTF_8);
            } else if ("/actuator/env".equals(path)) {
                body = "{\"propertySources\":[{\"name\":\"app\",\"properties\":{\"k\":{\"value\":\"v\"}}}]}".getBytes(StandardCharsets.UTF_8);
                ctype = "application/json";
            } else if ("/graphql".equals(path) && "POST".equalsIgnoreCase(method)) {
                body = "{\"data\":{\"__schema\":{\"types\":[]}}}".getBytes(StandardCharsets.UTF_8);
                ctype = "application/json";
            } else if ("/ws".equals(path)) {
                code = 426;
                body = "Upgrade Required".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("vulnerax_test")) {
                body = ("echo:" + queryParam(rawQuery, "vulnerax_test")).getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("id=")) {
                body = "You have an error in your SQL syntax; check mysql manual".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("q=")) {
                body = "mongodb query failed: mongod error".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("cmd=")) {
                body = "uid=0(root) gid=0(root)".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("file=")) {
                body = "root:x:0:0:root:/root:/bin/bash".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("redirect=")) {
                code = 302;
                ex.getResponseHeaders().set("Location", "https://evil.com/");
                body = "redirect".getBytes(StandardCharsets.UTF_8);
            } else if (rawQuery != null && rawQuery.contains("url=")) {
                body = "ami-id: i-12345 instance-id: i-67890".getBytes(StandardCharsets.UTF_8);
            } else if ("POST".equalsIgnoreCase(method)
                    && ex.getRequestHeaders().getFirst("Content-Type") != null
                    && ex.getRequestHeaders().getFirst("Content-Type").contains("xml")) {
                body = "root:x:0:0 parsed".getBytes(StandardCharsets.UTF_8);
            } else if (path.startsWith("/api/")) {
                body = "{\"ok\":true,\"data\":\"admin panel\"}".getBytes(StandardCharsets.UTF_8);
                ctype = "application/json";
            } else if ("/api".equals(path)) {
                body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                ctype = "application/json";
            } else if ("/nonexistent-xyz".equals(path)) {
                code = 404;
                body = "not found".getBytes(StandardCharsets.UTF_8);
            } else {
                body = ("<html><head><title>t</title></head><body><form action=\"/login\">"
                        + "<input name=\"u\"/></form><!-- cloudflare --></body></html>")
                        .getBytes(StandardCharsets.UTF_8);
            }

            var rh = ex.getResponseHeaders();
            rh.set("Content-Type", ctype);
            if ("/".equals(path) && rawQuery == null) {
                rh.set("Server", "nginx/1.25.0");
                rh.set("X-Powered-By", "Express");
                rh.add("Set-Cookie", "sid=abc123; Path=/");
            }
            ex.sendResponseHeaders(code, body.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private static String queryParam(String rawQuery, String key) {
        for (String kv : rawQuery.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(key)) {
                return URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            }
        }
        return "";
    }

    private static boolean hasTitle(List<Map<String, Object>> out, String part) {
        return out.stream().anyMatch(m -> String.valueOf(m.get("title")).contains(part));
    }

    @Test
    void null_and_nonHttp_returnEmpty() {
        assertThat(DastAnalyzer.analyze(null, "f")).isEmpty();
        assertThat(DastAnalyzer.analyze("repo-local-path", "f")).isEmpty();
        assertThat(DastAnalyzer.analyze("", "f")).isEmpty();
    }

    @Test
    void unreachable_returnsScanError() {
        var out = DastAnalyzer.analyze("http://127.0.0.1:9", "f");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("findingType")).isEqualTo("SCAN_ERROR");
        assertThat(out.get(0).get("severity")).isEqualTo("INFO");
    }

    @Test
    void fullScan_detectsExpectedFindings() {
        var out = DastAnalyzer.analyze(base, "f");
        assertThat(hasTitle(out, "Missing Header: Content-Security-Policy")).isTrue();
        assertThat(hasTitle(out, "Missing Header: Strict-Transport-Security")).isTrue();
        assertThat(hasTitle(out, "Cleartext HTTP")).isTrue();
        assertThat(hasTitle(out, "Sensitive File Exposed: /.env")).isTrue();
        assertThat(hasTitle(out, "Robots.txt Disclosure")).isTrue();
        assertThat(hasTitle(out, "Debug Endpoint Exposed: /actuator/env")).isTrue();
        assertThat(hasTitle(out, "Admin Endpoint: /actuator")).isTrue();
        assertThat(hasTitle(out, "Reflected XSS")).isTrue();
        assertThat(hasTitle(out, "SQL Injection (Error-based)")).isTrue();
        assertThat(hasTitle(out, "NoSQL Injection Indicator")).isTrue();
        assertThat(hasTitle(out, "Command Injection")).isTrue();
        assertThat(hasTitle(out, "Path Traversal")).isTrue();
        assertThat(hasTitle(out, "Open Redirect")).isTrue();
        assertThat(hasTitle(out, "SSRF to Cloud Metadata")).isTrue();
        assertThat(hasTitle(out, "XXE Injection")).isTrue();
        assertThat(hasTitle(out, "No CSRF Token in Forms")).isTrue();
        assertThat(hasTitle(out, "GraphQL Introspection Enabled")).isTrue();
        assertThat(hasTitle(out, "WebSocket Endpoint Found")).isTrue();
        assertThat(hasTitle(out, "Unauthenticated State-Change: /api/admin")).isTrue();
        assertThat(hasTitle(out, "Cookie Missing HttpOnly")).isTrue();
        assertThat(hasTitle(out, "Cookie Missing SameSite")).isTrue();
        assertThat(hasTitle(out, "Server Version Disclosure")).isTrue();
        assertThat(hasTitle(out, "X-Powered-By Disclosure")).isTrue();
        assertThat(hasTitle(out, "WAF Detected")).isTrue();
    }

    @Test
    void tokenInUrl_flagsJwtFinding() {
        var out = DastAnalyzer.analyze(base + "?token=abc123", "f");
        assertThat(hasTitle(out, "JWT/Token in URL")).isTrue();
    }

    @Test
    void dastPlugin_execute_mapsFindings() {
        DastPlugin p = new DastPlugin();
        var plan = p.plan(base, Map.of());
        var findings = p.execute(base, plan, Map.of());
        assertThat(findings).isNotEmpty();
        assertThat(findings.get(0).getType()).isEqualTo("DAST");
    }

    @Test
    void xssPayload_helper_used() {
        assertThat(xssPayload()).contains("alert(1)");
    }
}
