package com.vulnerax.modules.ai;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AiAnalystServiceAdditionalTest {

    @Mock FindingRepository findingRepo;
    @InjectMocks AiAnalystService service;

    @BeforeEach
    void setUp() throws Exception {
        // Set deepseekKey to blank to ensure rule-based fallback
        Field keyField = AiAnalystService.class.getDeclaredField("deepseekKey");
        keyField.setAccessible(true);
        keyField.set(service, "");
    }

    @Test
    void explain_findingNotFound_throws() {
        UUID id = UUID.randomUUID();
        when(findingRepo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.explain(id))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Finding not found");
    }

    @Test
    void explain_sastInjection_returnsRuleBased() {
        Finding f = Finding.builder()
                .findingId("F-001").title("SQL Injection").type("INJECTION")
                .severity("CRITICAL").confidence("HIGH").cwe("CWE-89")
                .filePath("/src/main.java").lineNumber(42)
                .codeSnippet("String q = \"SELECT * FROM users WHERE id=\" + input;")
                .dataFlow("user input -> SQL query")
                .assetName("api.example.com").source("sast-analyzer")
                .cvss(9.8).riskScore(85.0).riskLevel("CRITICAL")
                .internetExposed(true).kev(true).businessCriticality("CRITICAL")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result).containsKey("rootCause");
        assertThat(result).containsKey("impact");
        assertThat(result).containsKey("remediation");
        assertThat(result).containsKey("codeFix");
        assertThat(result.get("aiProvider")).toString().contains("rule-based");
    }

    @Test
    void explain_secretType_returnsSecretRemediation() {
        Finding f = Finding.builder()
                .findingId("F-002").title("Hardcoded Secret").type("SECRET")
                .severity("CRITICAL").confidence("HIGH").cwe("CWE-798")
                .source("secret-analyzer").cvss(8.0).riskScore(70.0).riskLevel("VERY_HIGH")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("remediation").toString()).contains("Rotate secret");
    }

    @Test
    void explain_scaType_returnsScaRemediation() {
        Finding f = Finding.builder()
                .findingId("F-003").title("Vulnerable Dep").type("SCA")
                .severity("HIGH").confidence("HIGH").cwe("CWE-1104")
                .source("sca-analyzer").cvss(7.5).riskScore(60.0).riskLevel("HIGH")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("rootCause").toString()).contains("Transitive vulnerable dependency");
    }

    @Test
    void explain_authorizationType_returnsAuthRemediation() {
        Finding f = Finding.builder()
                .findingId("F-004").title("BOLA").type("AUTHORIZATION_BYPASS")
                .severity("HIGH").confidence("HIGH").cwe("CWE-639")
                .functionName("getAccount").source("dast-analyzer")
                .cvss(7.0).riskScore(55.0).riskLevel("HIGH")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("remediation").toString()).contains("object-level authorization");
    }

    @Test
    void explain_lowConfidenceLowCvss_isFalsePositive() {
        Finding f = Finding.builder()
                .findingId("F-005").title("Minor Issue").type("INFO")
                .severity("LOW").confidence("LOW").cwe("CWE-200")
                .cvss(2.0).riskScore(10.0).riskLevel("LOW")
                .source("dast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("isLikelyFalsePositive")).isEqualTo(true);
    }

    @Test
    void explain_highRiskScore_priorityP0() {
        Finding f = Finding.builder()
                .findingId("F-006").title("Critical Vuln").type("INJECTION")
                .severity("CRITICAL").confidence("CONFIRMED").cwe("CWE-89")
                .cvss(10.0).riskScore(90.0).riskLevel("CRITICAL")
                .internetExposed(true).kev(true).businessCriticality("CRITICAL")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("priority").toString()).contains("P0");
    }

    @Test
    void explain_mediumRiskScore_priorityP1() {
        Finding f = Finding.builder()
                .findingId("F-007").title("High Vuln").type("SAST")
                .severity("HIGH").confidence("HIGH").cwe("CWE-79")
                .cvss(7.0).riskScore(65.0).riskLevel("VERY_HIGH")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("priority").toString()).contains("P1");
    }

    @Test
    void explain_lowRiskScore_priorityP2() {
        Finding f = Finding.builder()
                .findingId("F-008").title("Medium Vuln").type("SAST")
                .severity("MEDIUM").confidence("MEDIUM").cwe("CWE-525")
                .cvss(5.0).riskScore(45.0).riskLevel("HIGH")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("priority").toString()).contains("P2");
    }

    @Test
    void explain_veryLowRiskScore_priorityP3() {
        Finding f = Finding.builder()
                .findingId("F-009").title("Low Vuln").type("INFO")
                .severity("LOW").confidence("LOW").cwe("CWE-200")
                .cvss(1.0).riskScore(15.0).riskLevel("LOW")
                .source("dast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("priority").toString()).contains("P3");
    }

    @Test
    void explain_impact_internetExposedCritical() {
        Finding f = Finding.builder()
                .findingId("F-010").title("Critical").type("INJECTION")
                .severity("CRITICAL").confidence("HIGH").cwe("CWE-89")
                .internetExposed(true).businessCriticality("CRITICAL")
                .cvss(9.0).riskScore(85.0).riskLevel("CRITICAL")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("impact").toString()).contains("Critical");
    }

    @Test
    void explain_impact_kev() {
        Finding f = Finding.builder()
                .findingId("F-011").title("KEV Vuln").type("SAST")
                .severity("HIGH").confidence("HIGH").cwe("CWE-79")
                .kev(true).cvss(7.0).riskScore(65.0).riskLevel("VERY_HIGH")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("impact").toString()).contains("Known exploited");
    }

    @Test
    void prioritize_withFindings_returnsTop10() {
        Finding f1 = Finding.builder().findingId("F-001").title("Critical").severity("CRITICAL")
                .riskScore(90.0).cvss(9.8).kev(true).internetExposed(true).build();
        f1.setId(UUID.randomUUID());
        Finding f2 = Finding.builder().findingId("F-002").title("High").severity("HIGH")
                .riskScore(65.0).cvss(7.0).build();
        f2.setId(UUID.randomUUID());
        when(findingRepo.findByProjectId(any())).thenReturn(new ArrayList<>(List.of(f1, f2)));

        Map<String, Object> result = service.prioritize(UUID.randomUUID());
        assertThat(result.get("total")).isEqualTo(2);
        List<?> prioritized = (List<?>) result.get("prioritized");
        assertThat(prioritized).hasSize(2);
    }

    @Test
    void prioritize_nullProjectId_returnsAll() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());
        Map<String, Object> result = service.prioritize(null);
        assertThat(result.get("total")).isEqualTo(0);
    }

    @Test
    void reportDraft_returnsSections() {
        when(findingRepo.findByProjectId(any())).thenReturn(new ArrayList<>());
        Map<String, Object> result = service.reportDraft(UUID.randomUUID(), "EXECUTIVE");
        assertThat(result).containsKey("type");
        assertThat(result).containsKey("executiveSummary");
        assertThat(result).containsKey("keyFindings");
        assertThat(result).containsKey("recommendations");
        assertThat(result).containsKey("generatedBy");
    }

    @Test
    void reportDraft_nullType_defaultsToExecutive() {
        when(findingRepo.findByProjectId(any())).thenReturn(new ArrayList<>());
        Map<String, Object> result = service.reportDraft(UUID.randomUUID(), null);
        assertThat(result.get("type")).isEqualTo("EXECUTIVE");
    }

    @Test
    void explain_impact_defaultCase() {
        Finding f = Finding.builder()
                .findingId("F-012").title("Default").type("SAST")
                .severity("MEDIUM").confidence("MEDIUM").cwe("CWE-0")
                .cvss(5.0).riskScore(30.0).riskLevel("MODERATE")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("impact").toString()).contains("Risk level");
    }

    @Test
    void explain_codeFix_defaultCase() {
        Finding f = Finding.builder()
                .findingId("F-013").title("Default").type("CUSTOM_TYPE")
                .severity("MEDIUM").confidence("MEDIUM").cwe("CWE-0")
                .cvss(5.0).riskScore(30.0).riskLevel("MODERATE")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("codeFix").toString()).contains("Apply secure pattern");
    }

    @Test
    void explain_remediation_withRecommendation() {
        Finding f = Finding.builder()
                .findingId("F-014").title("Custom").type("CUSTOM_TYPE")
                .severity("MEDIUM").confidence("MEDIUM").cwe("CWE-0")
                .recommendation("Custom recommendation here")
                .cvss(5.0).riskScore(30.0).riskLevel("MODERATE")
                .source("sast-analyzer")
                .build();
        when(findingRepo.findById(any())).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(UUID.randomUUID());
        assertThat(result.get("remediation")).isEqualTo("Custom recommendation here");
    }
}
