package com.vulnerax.modules.ai;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AiAnalystServiceTest2 {

    @Mock private FindingRepository findingRepo;
    @InjectMocks private AiAnalystService service;

    private Finding buildFinding(String type, String severity, Double cvss, String cwe) {
        Finding f = Finding.builder()
                .findingId("FIND-001")
                .title("Test Finding")
                .type(type)
                .severity(severity)
                .cwe(cwe)
                .confidence("HIGH")
                .status("OPEN")
                .source("sast-analyzer")
                .assetName("test-app")
                .filePath("src/Main.java")
                .lineNumber(42)
                .codeSnippet("Runtime.exec(input)")
                .dataFlow("source->sink")
                .recommendation("Fix this")
                .cvss(cvss)
                .riskScore(cvss != null ? cvss * 10 : null)
                .riskLevel(cvss != null && cvss >= 9 ? "CRITICAL" : cvss != null && cvss >= 7 ? "HIGH" : "MEDIUM")
                .build();
        f.setId(UUID.randomUUID());
        return f;
    }

    @Test
    void explain_injection_findsFindingAndReturnsRuleBased() {
        Finding f = buildFinding("INJECTION", "CRITICAL", 9.8, "CWE-78");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertNotNull(result);
        assertEquals("Test Finding", result.get("title"));
        assertNotNull(result.get("rootCause"));
        assertNotNull(result.get("impact"));
        assertNotNull(result.get("remediation"));
        assertNotNull(result.get("codeFix"));
        assertNotNull(result.get("priority"));
        assertTrue(result.get("rootCause").toString().contains("parameterized"));
    }

    @Test
    void explain_secretType_returnsSecretRemediation() {
        Finding f = buildFinding("SECRET", "HIGH", 7.5, "CWE-798");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("rootCause").toString().contains("Hardcoded credential"));
        assertTrue(result.get("remediation").toString().contains("Rotate secret"));
    }

    @Test
    void explain_authorizationType_returnsAuthRemediation() {
        Finding f = buildFinding("AUTHORIZATION_BYPASS", "CRITICAL", 9.5, "CWE-639");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("rootCause").toString().contains("authorization"));
        assertTrue(result.get("remediation").toString().contains("object-level"));
        assertTrue(result.get("codeFix").toString().contains("getOwnerId"));
    }

    @Test
    void explain_scaType_returnsSCARemediation() {
        Finding f = buildFinding("SCA", "CRITICAL", 9.1, "CWE-1104");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("rootCause").toString().contains("Transitive vulnerable dependency"));
    }

    @Test
    void explain_genericType_returnsDefaultRootCause() {
        Finding f = buildFinding("XSS", "MEDIUM", 6.5, "CWE-79");
        f.setRecommendation(null);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertNotNull(result.get("rootCause"));
        assertTrue(result.get("remediation").toString().contains("secure coding"));
    }

    @Test
    void explain_withLowCvss_marksAsLikelyFalsePositive() {
        Finding f = buildFinding("INFORMATION", "LOW", 2.0, "CWE-200");
        f.setConfidence("LOW");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertEquals(true, result.get("isLikelyFalsePositive"));
    }

    @Test
    void explain_notFound_throws() {
        when(findingRepo.findById(any())).thenReturn(Optional.empty());
        assertThrows(RuntimeException.class, () -> service.explain(UUID.randomUUID()));
    }

    @Test
    void prioritize_withProjectId_returnsSorted() {
        Finding f1 = buildFinding("XSS", "CRITICAL", 9.5, "CWE-79");
        f1.setRiskScore(95.0);
        Finding f2 = buildFinding("SCA", "HIGH", 7.0, "CWE-1104");
        f2.setRiskScore(70.0);
        when(findingRepo.findByProjectId(any())).thenReturn(new ArrayList<>(List.of(f2, f1)));

        Map<String,Object> result = service.prioritize(UUID.randomUUID());

        assertEquals(2, result.get("total"));
        @SuppressWarnings("unchecked")
        List<Map<String,Object>> prioritized = (List<Map<String,Object>>) result.get("prioritized");
        assertEquals(95.0, prioritized.get(0).get("risk"));
    }

    @Test
    void prioritize_nullProjectId_findsAll() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String,Object> result = service.prioritize(null);

        assertEquals(0, result.get("total"));
    }

    @Test
    void reportDraft_returnsSections() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String,Object> result = service.reportDraft(null, "EXECUTIVE");

        assertEquals("EXECUTIVE", result.get("type"));
        assertNotNull(result.get("executiveSummary"));
        assertNotNull(result.get("recommendations"));
        assertEquals("AI Security Analyst", result.get("generatedBy"));
    }

    @Test
    void reportDraft_nullType_defaultsToExecutive() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String,Object> result = service.reportDraft(null, null);

        assertEquals("EXECUTIVE", result.get("type"));
    }

    @Test
    void impact_internetExposedCritical_returnsCriticalMessage() {
        Finding f = buildFinding("INJECTION", "CRITICAL", 9.8, "CWE-78");
        f.setInternetExposed(true);
        f.setBusinessCriticality("CRITICAL");
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("impact").toString().contains("Critical"));
    }

    @Test
    void impact_kev_returnsHighMessage() {
        Finding f = buildFinding("SCA", "CRITICAL", 9.1, "CWE-1104");
        f.setKev(true);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("impact").toString().contains("Known exploited"));
    }

    @Test
    void priority_p0_forHighRisk() {
        Finding f = buildFinding("INJECTION", "CRITICAL", 9.8, "CWE-78");
        f.setRiskScore(85.0);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("priority").toString().contains("P0"));
    }

    @Test
    void priority_p1_forMediumHighRisk() {
        Finding f = buildFinding("SCA", "HIGH", 7.0, "CWE-1104");
        f.setRiskScore(65.0);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("priority").toString().contains("P1"));
    }

    @Test
    void priority_p2_forMediumRisk() {
        Finding f = buildFinding("XSS", "MEDIUM", 5.0, "CWE-79");
        f.setRiskScore(45.0);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("priority").toString().contains("P2"));
    }

    @Test
    void priority_p3_forLowRisk() {
        Finding f = buildFinding("INFO", "LOW", 2.0, "CWE-200");
        f.setRiskScore(15.0);
        when(findingRepo.findById(f.getId())).thenReturn(Optional.of(f));

        Map<String,Object> result = service.explain(f.getId());

        assertTrue(result.get("priority").toString().contains("P3"));
    }
}
