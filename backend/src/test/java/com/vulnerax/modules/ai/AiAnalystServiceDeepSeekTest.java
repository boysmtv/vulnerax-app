package com.vulnerax.modules.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AiAnalystServiceDeepSeekTest {

    @Mock FindingRepository findingRepo;

    private AiAnalystService service;
    private final ObjectMapper om = new ObjectMapper();
    private HttpServer server;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();

        service = createService();
        setField("deepseekKey", "test-api-key-123");
        setField("deepseekBase", "http://localhost:" + port);
        setField("deepseekModel", "deepseek-chat");
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private AiAnalystService createService() throws Exception {
        var ctor = AiAnalystService.class.getDeclaredConstructor(FindingRepository.class);
        ctor.setAccessible(true);
        return ctor.newInstance(findingRepo);
    }

    private void setField(String name, Object value) throws Exception {
        Field f = AiAnalystService.class.getDeclaredField(name);
        f.setAccessible(true);
        f.set(service, value);
    }

    private Finding sampleFinding() {
        return Finding.builder()
                .findingId("F-001")
                .title("SQL Injection in Login")
                .type("INJECTION")
                .severity("CRITICAL")
                .confidence("HIGH")
                .cwe("CWE-89")
                .owasp("A03:2021")
                .filePath("/src/main/java/com/example/UserRepo.java")
                .lineNumber(42)
                .functionName("findById")
                .codeSnippet("String q = \"SELECT * FROM users WHERE id=\" + input;")
                .dataFlow("user input -> HTTP param -> SQL query")
                .assetName("api.example.com")
                .environment("production")
                .internetExposed(true)
                .reachable(true)
                .cvss(9.8)
                .kev(true)
                .businessCriticality("CRITICAL")
                .source("sast-analyzer")
                .riskScore(90.0)
                .riskLevel("CRITICAL")
                .findingType("VULNERABILITY")
                .vulnerabilityConfirmed(true)
                .securityVulnerability(true)
                .build();
    }

    // ─── Test 1: Valid DeepSeek response ────────────────────────────

    @Test
    void explain_withValidDeepSeekResponse_parsesCorrectly() throws Exception {
        String innerJson = om.writeValueAsString(Map.of(
                "summary", "Test summary",
                "rootCause", "Test root cause",
                "evidenceSummary", "Test evidence",
                "impact", "Test impact",
                "remediation", "Test remediation",
                "codeFix", "Test code fix",
                "testRecommendation", "Test recommendation",
                "priority", "P0",
                "isLikelyFalsePositive", false,
                "isLikelyDuplicate", false
        ));

        Map<String, Object> choice = Map.of("message", Map.of("content", innerJson));
        String deepseekResponse = om.writeValueAsString(Map.of(
                "choices", List.of(choice)
        ));

        AtomicReference<String> capturedBody = new AtomicReference<>();
        server.createContext("/chat/completions", exchange -> {
            capturedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] resp = deepseekResponse.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        });
        server.start();

        when(findingRepo.findById(any(UUID.class))).thenReturn(Optional.of(sampleFinding()));

        Map<String, Object> result = service.explain(UUID.randomUUID());

        assertThat(result).isNotNull();
        assertThat(result.get("aiProvider")).isEqualTo("deepseek:deepseek-chat");
        assertThat(result.get("summary")).isEqualTo("DeepSeek analysis for SQL Injection in Login");
        assertThat(result.get("rootCause")).isEqualTo("Test root cause");
        assertThat(result.get("impact")).isEqualTo("Test impact");
        assertThat(result.get("remediation")).isEqualTo("Test remediation");
        assertThat(result.get("codeFix")).isEqualTo("Test code fix");
        assertThat(result.get("testRecommendation")).isEqualTo("Test recommendation");
        assertThat(result.get("isLikelyFalsePositive")).isEqualTo(false);
        assertThat(result.get("isLikelyDuplicate")).isEqualTo(false);
        assertThat(result).containsKey("rawDeepSeek");
        assertThat(result.get("findingId")).isNotNull();
        assertThat(result.get("title")).isEqualTo("SQL Injection in Login");

        String body = capturedBody.get();
        assertThat(body).isNotNull();
        Map<?, ?> req = om.readValue(body, Map.class);
        assertThat(req.get("model")).isEqualTo("deepseek-chat");
        assertThat(req.get("messages")).isNotNull();
    }

    // ─── Test 2: Invalid JSON in content falls back ─────────────────

    @Test
    void explain_withInvalidJson_fallsBackToRuleBased() throws Exception {
        Map<String, Object> choice = Map.of("message", Map.of("content", "Sorry, I could not analyze this finding properly."));
        String deepseekResponse = om.writeValueAsString(Map.of(
                "choices", List.of(choice)
        ));

        server.createContext("/chat/completions", exchange -> {
            byte[] resp = deepseekResponse.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        });
        server.start();

        when(findingRepo.findById(any(UUID.class))).thenReturn(Optional.of(sampleFinding()));

        Map<String, Object> result = service.explain(UUID.randomUUID());

        assertThat(result).isNotNull();
        assertThat(result.get("aiProvider")).toString().contains("rule-based");
        assertThat(result.get("rootCause").toString()).contains("Unsanitized input");
    }

    // ─── Test 3: API returns 500 error falls back ──────────────────

    @Test
    void explain_withApiError_fallsBackToRuleBased() throws Exception {
        server.createContext("/chat/completions", exchange -> {
            byte[] resp = "{\"error\":\"internal server error\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(500, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        });
        server.start();

        when(findingRepo.findById(any(UUID.class))).thenReturn(Optional.of(sampleFinding()));

        Map<String, Object> result = service.explain(UUID.randomUUID());

        assertThat(result).isNotNull();
        assertThat(result.get("aiProvider")).toString().contains("rule-based");
    }

    // ─── Test 4: Empty API key falls back (no HTTP call) ───────────

    @Test
    void explain_withEmptyApiKey_fallsBackToRuleBased() throws Exception {
        setField("deepseekKey", "");

        server.createContext("/chat/completions", exchange -> {
            exchange.sendResponseHeaders(501, -1);
        });
        server.start();

        when(findingRepo.findById(any(UUID.class))).thenReturn(Optional.of(sampleFinding()));

        Map<String, Object> result = service.explain(UUID.randomUUID());

        assertThat(result).isNotNull();
        assertThat(result.get("aiProvider")).toString().contains("rule-based");
    }

    // ─── Test 5: "change-me" API key falls back (no HTTP call) ─────

    @Test
    void explain_withChangeMeKey_fallsBackToRuleBased() throws Exception {
        setField("deepseekKey", "change-me");

        server.createContext("/chat/completions", exchange -> {
            exchange.sendResponseHeaders(501, -1);
        });
        server.start();

        when(findingRepo.findById(any(UUID.class))).thenReturn(Optional.of(sampleFinding()));

        Map<String, Object> result = service.explain(UUID.randomUUID());

        assertThat(result).isNotNull();
        assertThat(result.get("aiProvider")).toString().contains("rule-based");
    }
}
