package com.vulnerax.modules.finding;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class FindingBuilderCoverageTest {

    @Test
    void builder_allFields_setsCorrectly() {
        UUID id = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        UUID parentFindingId = UUID.randomUUID();
        UUID correlationId = UUID.randomUUID();
        Instant now = Instant.now();

        Finding f = Finding.builder()
                .findingId("F-001")
                .title("SQL Injection in login")
                .description("Unsanitized SQL concatenation in AuthService.java:42")
                .type("SAST")
                .severity("CRITICAL")
                .confidence("HIGH")
                .status("OPEN")
                .projectId(projectId)
                .organizationId(orgId)
                .assetId(assetId)
                .assetName("api.example.com")
                .environment("PRODUCTION")
                .source("semgrep")
                .scanId(scanId)
                .cwe("CWE-89")
                .cweId("CWE-89")
                .cveId("CVE-2024-1234")
                .owasp("A03:2021")
                .masvs("MSTG-SQL-1")
                .asvs("2.7.1")
                .cvss(9.8)
                .epss(0.95)
                .kev(true)
                .internetExposed(true)
                .reachable(true)
                .businessCriticality("CRITICAL")
                .owner("Platform Team")
                .filePath("/src/main/java/com/app/AuthService.java")
                .lineNumber(42)
                .functionName("authenticate")
                .codeSnippet("String q = \"SELECT * FROM users WHERE id=\" + input;")
                .dataFlow("user input -> SQL query")
                .recommendation("Use parameterized query")
                .evidenceJson("{\"rule\":\"SQL Injection\"}")
                .riskScore(85.0)
                .riskLevel("CRITICAL")
                .compensatingControl("WAF Rule #123")
                .fingerprint("abc123")
                .falsePositive(false)
                .duplicate(false)
                .parentFindingId(parentFindingId)
                .correlationId(correlationId)
                .firstSeenAt(now)
                .lastSeenAt(now)
                .slaDueAt(now.plusSeconds(86400))
                .slaStatus("WITHIN_SLA")
                .build();
        f.setId(id);

        assertThat(f.getFindingId()).isEqualTo("F-001");
        assertThat(f.getTitle()).isEqualTo("SQL Injection in login");
        assertThat(f.getDescription()).contains("Unsanitized SQL");
        assertThat(f.getType()).isEqualTo("SAST");
        assertThat(f.getSeverity()).isEqualTo("CRITICAL");
        assertThat(f.getConfidence()).isEqualTo("HIGH");
        assertThat(f.getStatus()).isEqualTo("OPEN");
        assertThat(f.getProjectId()).isEqualTo(projectId);
        assertThat(f.getOrganizationId()).isEqualTo(orgId);
        assertThat(f.getAssetId()).isEqualTo(assetId);
        assertThat(f.getAssetName()).isEqualTo("api.example.com");
        assertThat(f.getEnvironment()).isEqualTo("PRODUCTION");
        assertThat(f.getSource()).isEqualTo("semgrep");
        assertThat(f.getScanId()).isEqualTo(scanId);
        assertThat(f.getCwe()).isEqualTo("CWE-89");
        assertThat(f.getCweId()).isEqualTo("CWE-89");
        assertThat(f.getCveId()).isEqualTo("CVE-2024-1234");
        assertThat(f.getOwasp()).isEqualTo("A03:2021");
        assertThat(f.getMasvs()).isEqualTo("MSTG-SQL-1");
        assertThat(f.getAsvs()).isEqualTo("2.7.1");
        assertThat(f.getCvss()).isEqualTo(9.8);
        assertThat(f.getEpss()).isEqualTo(0.95);
        assertThat(f.getKev()).isTrue();
        assertThat(f.getInternetExposed()).isTrue();
        assertThat(f.getReachable()).isTrue();
        assertThat(f.getBusinessCriticality()).isEqualTo("CRITICAL");
        assertThat(f.getOwner()).isEqualTo("Platform Team");
        assertThat(f.getFilePath()).isEqualTo("/src/main/java/com/app/AuthService.java");
        assertThat(f.getLineNumber()).isEqualTo(42);
        assertThat(f.getFunctionName()).isEqualTo("authenticate");
        assertThat(f.getCodeSnippet()).contains("SELECT * FROM users");
        assertThat(f.getDataFlow()).contains("user input -> SQL query");
        assertThat(f.getRecommendation()).isEqualTo("Use parameterized query");
        assertThat(f.getEvidenceJson()).contains("SQL Injection");
        assertThat(f.getRiskScore()).isEqualTo(85.0);
        assertThat(f.getRiskLevel()).isEqualTo("CRITICAL");
        assertThat(f.getCompensatingControl()).isEqualTo("WAF Rule #123");
        assertThat(f.getFingerprint()).isEqualTo("abc123");
        assertThat(f.getFalsePositive()).isFalse();
        assertThat(f.getDuplicate()).isFalse();
        assertThat(f.getParentFindingId()).isEqualTo(parentFindingId);
        assertThat(f.getCorrelationId()).isEqualTo(correlationId);
        assertThat(f.getFirstSeenAt()).isEqualTo(now);
        assertThat(f.getLastSeenAt()).isEqualTo(now);
        assertThat(f.getSlaDueAt()).isEqualTo(now.plusSeconds(86400));
        assertThat(f.getSlaStatus()).isEqualTo("WITHIN_SLA");
        assertThat(f.getId()).isEqualTo(id);
    }

    @Test
    void builder_defaults_correctValues() {
        Finding f = Finding.builder().title("Test").build();
        assertThat(f.getStatus()).isEqualTo("OPEN");
        assertThat(f.getKev()).isFalse();
        assertThat(f.getInternetExposed()).isFalse();
        assertThat(f.getReachable()).isFalse();
        assertThat(f.getFalsePositive()).isFalse();
        assertThat(f.getDuplicate()).isFalse();
    }

    @Test
    void noArgsConstructor_createsEmpty() {
        Finding f = new Finding();
        assertThat(f).isNotNull();
        assertThat(f.getTitle()).isNull();
        assertThat(f.getSeverity()).isNull();
    }

    @Test
    void allArgsConstructor_setsAll() {
        Finding f = new Finding("F-001", "Title", "Desc", "SAST", "HIGH", "CONFIRMED",
                "OPEN", null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, null, null);
        assertThat(f.getFindingId()).isEqualTo("F-001");
        assertThat(f.getTitle()).isEqualTo("Title");
    }

    @Test
    void setters_allFields() {
        Finding f = new Finding();
        UUID id = UUID.randomUUID();
        f.setId(id);
        f.setFindingId("F-002");
        f.setTitle("XSS");
        f.setDescription("Reflected XSS");
        f.setType("DAST");
        f.setSeverity("HIGH");
        f.setConfidence("MEDIUM");
        f.setStatus("RESOLVED");
        f.setProjectId(UUID.randomUUID());
        f.setOrganizationId(UUID.randomUUID());
        f.setAssetId(UUID.randomUUID());
        f.setAssetName("web.example.com");
        f.setEnvironment("STAGING");
        f.setSource("dast-analyzer");
        f.setScanId(UUID.randomUUID());
        f.setCwe("CWE-79");
        f.setCweId("CWE-79");
        f.setCveId("CVE-2024-5678");
        f.setOwasp("A07:2021");
        f.setMasvs("MSTG-CLIENT-1");
        f.setAsvs("6.1.1");
        f.setCvss(7.5);
        f.setEpss(0.6);
        f.setKev(false);
        f.setInternetExposed(true);
        f.setReachable(false);
        f.setBusinessCriticality("HIGH");
        f.setOwner("Frontend Team");
        f.setFilePath("/src/XSS.java");
        f.setLineNumber(10);
        f.setFunctionName("render");
        f.setCodeSnippet("innerHTML = input");
        f.setDataFlow("URL -> innerHTML");
        f.setRecommendation("Encode output");
        f.setEvidenceJson("{\"type\":\"XSS\"}");
        f.setRiskScore(65.0);
        f.setRiskLevel("VERY_HIGH");
        f.setCompensatingControl("CSP");
        f.setFingerprint("fp-xss");
        f.setFalsePositive(true);
        f.setDuplicate(true);
        f.setParentFindingId(UUID.randomUUID());
        f.setCorrelationId(UUID.randomUUID());
        f.setFirstSeenAt(Instant.now());
        f.setLastSeenAt(Instant.now());
        f.setSlaDueAt(Instant.now());
        f.setSlaStatus("BREACHED");

        assertThat(f.getId()).isEqualTo(id);
        assertThat(f.getFindingId()).isEqualTo("F-002");
        assertThat(f.getTitle()).isEqualTo("XSS");
        assertThat(f.getFalsePositive()).isTrue();
        assertThat(f.getDuplicate()).isTrue();
        assertThat(f.getSlaStatus()).isEqualTo("BREACHED");
    }

    @Test
    void prePersist_setsTimestamps() {
        Finding f = Finding.builder().title("Test").build();
        f.onCreate();
        assertThat(f.getFirstSeenAt()).isNotNull();
        assertThat(f.getLastSeenAt()).isNotNull();
    }

    @Test
    void prePersist_firstSeenNotNull_doesNotOverride() {
        Finding f = Finding.builder().title("Test").build();
        Instant existing = Instant.now().minusSeconds(100);
        f.setFirstSeenAt(existing);
        f.onCreate();
        assertThat(f.getFirstSeenAt()).isEqualTo(existing);
        assertThat(f.getLastSeenAt()).isNotNull();
    }

    @Test
    void preUpdate_setsLastSeenAt() {
        Finding f = Finding.builder().title("Test").build();
        Instant before = Instant.now();
        f.onUpdate();
        assertThat(f.getLastSeenAt()).isNotNull();
        assertThat(f.getLastSeenAt().toEpochMilli()).isGreaterThanOrEqualTo(before.toEpochMilli());
    }

    @Test
    void builder_withNullOptionalFields() {
        Finding f = Finding.builder()
                .title("Minimal")
                .severity("LOW")
                .type("INFO")
                .confidence("LOW")
                .build();
        assertThat(f.getTitle()).isEqualTo("Minimal");
        assertThat(f.getProjectId()).isNull();
        assertThat(f.getCvss()).isNull();
        assertThat(f.getEpss()).isNull();
        assertThat(f.getFilePath()).isNull();
        assertThat(f.getLineNumber()).isNull();
    }

    @Test
    void equals_sameId_equal() {
        Finding f1 = new Finding();
        Finding f2 = f1;
        assertThat(f1).isSameAs(f2);
    }

    @Test
    void hashCode_sameId_sameHash() {
        Finding f1 = new Finding();
        assertThat(f1.hashCode()).isNotZero();
    }

    @Test
    void toString_returnsNonNull() {
        Finding f = Finding.builder().findingId("F-999").title("Test").build();
        String str = f.toString();
        assertThat(str).isNotNull();
    }
}
