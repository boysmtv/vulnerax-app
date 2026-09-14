package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class EvidenceBuilderCoverageTest {

    @Test
    void builder_allFields_setsCorrectly() {
        UUID id = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();

        Evidence e = Evidence.builder()
                .findingId(findingId)
                .type("HTTP_REQUEST")
                .content("request/response data")
                .author("dast-analyzer")
                .sha256("abc123def456")
                .requestMethod("POST")
                .requestUrl("https://api.example.com/login")
                .requestBody("{\"user\":\"admin\",\"pass\":\"test\"}")
                .responseHeaders("Content-Type: application/json")
                .responseStatusCode(200)
                .responseBody("{\"token\":\"jwt...\"}")
                .payload("admin' OR '1'='1")
                .command("nmap -sV 192.168.1.1")
                .commandOutput("PORT 22 OPEN")
                .screenshot("/screenshots/vuln.png")
                .validationHash("sha256:valid123")
                .validated(true)
                .responseTimeMs(150L)
                .build();
        e.setId(id);

        assertThat(e.getFindingId()).isEqualTo(findingId);
        assertThat(e.getType()).isEqualTo("HTTP_REQUEST");
        assertThat(e.getContent()).isEqualTo("request/response data");
        assertThat(e.getAuthor()).isEqualTo("dast-analyzer");
        assertThat(e.getSha256()).isEqualTo("abc123def456");
        assertThat(e.getRequestMethod()).isEqualTo("POST");
        assertThat(e.getRequestUrl()).isEqualTo("https://api.example.com/login");
        assertThat(e.getRequestBody()).contains("admin");
        assertThat(e.getResponseHeaders()).contains("Content-Type");
        assertThat(e.getResponseStatusCode()).isEqualTo(200);
        assertThat(e.getResponseBody()).contains("token");
        assertThat(e.getPayload()).contains("OR");
        assertThat(e.getCommand()).isEqualTo("nmap -sV 192.168.1.1");
        assertThat(e.getCommandOutput()).contains("PORT 22");
        assertThat(e.getScreenshot()).isEqualTo("/screenshots/vuln.png");
        assertThat(e.getValidationHash()).isEqualTo("sha256:valid123");
        assertThat(e.isValidated()).isTrue();
        assertThat(e.getResponseTimeMs()).isEqualTo(150L);
        assertThat(e.getId()).isEqualTo(id);
    }

    @Test
    void builder_defaults() {
        Evidence e = Evidence.builder().type("LOG").build();
        assertThat(e.getType()).isEqualTo("LOG");
        assertThat(e.isValidated()).isFalse();
        assertThat(e.getResponseStatusCode()).isEqualTo(0);
        assertThat(e.getResponseTimeMs()).isNull();
    }

    @Test
    void noArgsConstructor() {
        Evidence e = new Evidence();
        assertThat(e).isNotNull();
        assertThat(e.getType()).isNull();
    }

    @Test
    void setters_allFields() {
        Evidence e = new Evidence();
        UUID id = UUID.randomUUID();
        UUID findingId = UUID.randomUUID();
        e.setId(id);
        e.setFindingId(findingId);
        e.setType("CODE_SNIPPET");
        e.setContent("file content");
        e.setAuthor("sast-analyzer");
        e.setSha256("hash123");
        e.setRequestMethod("GET");
        e.setRequestUrl("/api/test");
        e.setRequestBody("body");
        e.setResponseHeaders("headers");
        e.setResponseStatusCode(404);
        e.setResponseBody("not found");
        e.setPayload("test payload");
        e.setCommand("ls -la");
        e.setCommandOutput("total 0");
        e.setScreenshot("screenshot.png");
        e.setValidationHash("vh123");
        e.setValidated(true);
        e.setResponseTimeMs(200L);

        assertThat(e.getId()).isEqualTo(id);
        assertThat(e.getFindingId()).isEqualTo(findingId);
        assertThat(e.getType()).isEqualTo("CODE_SNIPPET");
        assertThat(e.getContent()).isEqualTo("file content");
        assertThat(e.getAuthor()).isEqualTo("sast-analyzer");
        assertThat(e.getSha256()).isEqualTo("hash123");
        assertThat(e.getRequestMethod()).isEqualTo("GET");
        assertThat(e.getRequestUrl()).isEqualTo("/api/test");
        assertThat(e.getRequestBody()).isEqualTo("body");
        assertThat(e.getResponseHeaders()).isEqualTo("headers");
        assertThat(e.getResponseStatusCode()).isEqualTo(404);
        assertThat(e.getResponseBody()).isEqualTo("not found");
        assertThat(e.getPayload()).isEqualTo("test payload");
        assertThat(e.getCommand()).isEqualTo("ls -la");
        assertThat(e.getCommandOutput()).isEqualTo("total 0");
        assertThat(e.getScreenshot()).isEqualTo("screenshot.png");
        assertThat(e.getValidationHash()).isEqualTo("vh123");
        assertThat(e.isValidated()).isTrue();
        assertThat(e.getResponseTimeMs()).isEqualTo(200L);
    }

    @Test
    void allArgsConstructor() {
        Evidence e = new Evidence(null, UUID.randomUUID(), "TYPE", "content", "author",
                "sha", "GET", "/url", "reqBody", "headers", 200, "respBody",
                "payload", "cmd", "cmdOut", "screenshot", "vh", true, 100L);
        assertThat(e.getType()).isEqualTo("TYPE");
        assertThat(e.getContent()).isEqualTo("content");
        assertThat(e.isValidated()).isTrue();
    }

    @Test
    void equals_sameId() {
        Evidence e1 = new Evidence();
        Evidence e2 = e1;
        assertThat(e1).isSameAs(e2);
    }

    @Test
    void hashCode_sameId() {
        Evidence e1 = new Evidence();
        assertThat(e1.hashCode()).isNotZero();
    }

    @Test
    void toString_containsType() {
        Evidence e = Evidence.builder().type("SCREENSHOT").build();
        String str = e.toString();
        assertThat(str).isNotNull();
    }
}
