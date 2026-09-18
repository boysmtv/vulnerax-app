package com.vulnerax.modules.scan.analyzers;

import com.sun.net.httpserver.HttpServer;
import com.vulnerax.modules.scan.plugins.ApiPlugin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiAnalyzerHttpTest {

    private HttpServer server;
    private String base;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        base = "http://localhost:" + server.getAddress().getPort();
        server.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            byte[] body;
            int code = 404;
            String ctype = "application/json";

            if ("/openapi.json".equals(path)) {
                body = "{\"openapi\":\"3.0.0\",\"info\":{\"title\":\"demo\",\"version\":\"1.0.0\"},\"paths\":{\"/users\":{\"get\":{\"summary\":\"list users\"}},\"/admin\":{\"get\":{}}}}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else if ("/graphql".equals(path) && "POST".equalsIgnoreCase(method)) {
                body = "{\"data\":{\"__schema\":{\"types\":[]}}}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else if ("/api/v1/users".equals(path)) {
                body = "{\"users\":[{\"name\":\"admin\",\"token\":\"secret-config-debug\"}]}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else if ("/api".equals(path)
                    && ("PUT".equalsIgnoreCase(method) || "DELETE".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method))) {
                body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else if ("/api".equals(path)) {
                String origin = ex.getRequestHeaders().getFirst("Origin");
                if ("https://evil.com".equals(origin)) {
                    ex.getResponseHeaders().set("Access-Control-Allow-Origin", "https://evil.com");
                }
                body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else if ("/v1/".equals(path)) {
                body = "{\"version\":\"v1\"}".getBytes(StandardCharsets.UTF_8);
                code = 200;
            } else {
                body = "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8);
            }

            ex.getResponseHeaders().set("Content-Type", ctype);
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

    private static boolean hasTitle(List<Map<String, Object>> out, String part) {
        return out.stream().anyMatch(m -> String.valueOf(m.get("title")).contains(part));
    }

    @Test
    void null_and_nonHttp_returnEmpty() {
        assertThat(ApiAnalyzer.analyze(null)).isEmpty();
        assertThat(ApiAnalyzer.analyze("local-file.json")).isEmpty();
    }

    @Test
    void fullScan_detectsExpectedFindings() {
        var out = ApiAnalyzer.analyze(base);
        assertThat(hasTitle(out, "API Docs Exposed: /openapi.json")).isTrue();
        assertThat(hasTitle(out, "GraphQL Introspection Enabled")).isTrue();
        assertThat(hasTitle(out, "API Endpoint Exposed: /api/v1/users")).isTrue();
        assertThat(hasTitle(out, "API No Auth Required")).isTrue();
        assertThat(hasTitle(out, "HTTP PUT Allowed on /api")).isTrue();
        assertThat(hasTitle(out, "HTTP DELETE Allowed on /api")).isTrue();
        assertThat(hasTitle(out, "HTTP PATCH Allowed on /api")).isTrue();
        assertThat(hasTitle(out, "CORS Accepts Evil Origin")).isTrue();
        assertThat(hasTitle(out, "API No Rate Limiting")).isTrue();
        assertThat(hasTitle(out, "API Version Exposed: /v1/")).isTrue();
    }

    @Test
    void unreachable_stillFlagsMissingRateLimit() {
        var out = ApiAnalyzer.analyze("http://127.0.0.1:9");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("API No Rate Limiting");
    }

    @Test
    void apiPlugin_execute_mapsFindings() {
        ApiPlugin p = new ApiPlugin();
        var plan = p.plan(base, Map.of());
        var findings = p.execute(base, plan, Map.of());
        assertThat(findings).isNotEmpty();
        assertThat(findings.get(0).getType()).isEqualTo("API");
    }
}
