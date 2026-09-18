package com.vulnerax.modules.ai;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AiAnalystServiceTest {

    @Mock
    FindingRepository findingRepo;

    @InjectMocks
    AiAnalystService service;

    private Finding buildFinding(String type, String severity, Double riskScore, Double cvss) {
        Finding f = new Finding();
        f.setId(UUID.randomUUID());
        f.setFindingId(UUID.randomUUID().toString());
        f.setTitle("Test Finding");
        f.setType(type);
        f.setSeverity(severity);
        f.setConfidence("HIGH");
        f.setRiskScore(riskScore);
        f.setRiskLevel(riskScore != null && riskScore >= 81 ? "CRITICAL" : riskScore != null && riskScore >= 61 ? "HIGH" : "MEDIUM");
        f.setCvss(cvss);
        f.setAssetName("test-api.example.com");
        f.setEnvironment("PRODUCTION");
        f.setSource("SAST");
        f.setFilePath("src/main/java/com/app/UserService.java");
        f.setLineNumber(42);
        f.setFunctionName("getUser");
        f.setDataFlow("UserInput -> SQL Query");
        f.setInternetExposed(true);
        f.setBusinessCriticality("CRITICAL");
        f.setKev(false);
        f.setReachable(true);
        f.setFindingType("VULNERABILITY");
        f.setVulnerabilityConfirmed(true);
        f.setSecurityVulnerability(true);
        f.setCwe("CWE-89");
        f.setOwasp("A03:2021");
        f.setRecommendation("Use parameterized queries");
        f.setCodeSnippet("String q = \"SELECT * FROM users WHERE id=\" + input;");
        f.setConfidence("HIGH");
        return f;
    }

    @BeforeEach
    void setup() throws Exception {
        Field keyField = AiAnalystService.class.getDeclaredField("deepseekKey");
        keyField.setAccessible(true);
        keyField.set(service, "");
        Field baseField = AiAnalystService.class.getDeclaredField("deepseekBase");
        baseField.setAccessible(true);
        baseField.set(service, "https://api.deepseek.com");
        Field modelField = AiAnalystService.class.getDeclaredField("deepseekModel");
        modelField.setAccessible(true);
        modelField.set(service, "deepseek-chat");
    }

    @Test
    void explain_validFinding_returnsAllFields() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "CRITICAL", 90.0, 9.8);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertNotNull(result.get("findingId"));
        assertEquals("Test Finding", result.get("title"));
        assertNotNull(result.get("summary"));
        assertNotNull(result.get("rootCause"));
        assertNotNull(result.get("evidenceSummary"));
        assertNotNull(result.get("impact"));
        assertNotNull(result.get("remediation"));
        assertNotNull(result.get("codeFix"));
        assertNotNull(result.get("testRecommendation"));
        assertNotNull(result.get("priority"));
        assertNotNull(result.get("isLikelyFalsePositive"));
        assertNotNull(result.get("isLikelyDuplicate"));
        assertNotNull(result.get("aiProvider"));
    }

    @Test
    void explain_findingNotFound_throwsException() {
        UUID id = UUID.randomUUID();
        when(findingRepo.findById(id)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> service.explain(id));
    }

    @Test
    void explain_injectionType_returnsCorrectRootCause() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.5);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("rootCause").toString().contains("Unsanitized input"));
    }

    @Test
    void explain_authorizationType_returnsCorrectRootCause() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("AUTHORIZATION_BOLA", "HIGH", 75.0, 8.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("rootCause").toString().contains("Object-level authorization"));
    }

    @Test
    void explain_secretType_returnsCorrectRootCause() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SECRET", "CRITICAL", 85.0, 9.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("rootCause").toString().contains("Hardcoded credential"));
    }

    @Test
    void explain_scaType_returnsCorrectRootCause() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SCA", "MEDIUM", 50.0, 6.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("rootCause").toString().contains("Transitive vulnerable"));
    }

    @Test
    void explain_criticalInternetExposed_highImpact() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "CRITICAL", 95.0, 9.9);
        f.setId(id);
        f.setInternetExposed(true);
        f.setBusinessCriticality("CRITICAL");
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("impact").toString().contains("Critical - Internet exposed"));
    }

    @Test
    void explain_kevTrue_highImpact() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SCA", "HIGH", 80.0, 8.5);
        f.setId(id);
        f.setKev(true);
        f.setInternetExposed(false);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("impact").toString().contains("Known exploited"));
    }

    @Test
    void explain_lowRiskPriorityIsP3() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INFO", "LOW", 20.0, 3.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("priority").toString().contains("P3"));
    }

    @Test
    void explain_highRiskPriorityIsP0() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "CRITICAL", 90.0, 9.5);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("priority").toString().contains("P0"));
    }

    @Test
    void explain_mediumRiskPriorityIsP2() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SCA", "MEDIUM", 50.0, 5.5);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("priority").toString().contains("P2"));
    }

    @Test
    void explain_nullRiskScore_treatedAsZero() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INFO", "LOW", null, null);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("priority").toString().contains("P3"));
    }

    @Test
    void explain_lowConfidenceLowCvss_likelyFalsePositive() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INFO", "LOW", 15.0, 3.0);
        f.setId(id);
        f.setConfidence("LOW");
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertEquals(true, result.get("isLikelyFalsePositive"));
    }

    @Test
    void explain_highConfidence_notFalsePositive() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        f.setId(id);
        f.setConfidence("HIGH");
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertEquals(false, result.get("isLikelyFalsePositive"));
    }

    @Test
    void explain_authorizationType_codeFixSuggestsOwnershipCheck() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("AUTHORIZATION_BOLA", "HIGH", 70.0, 8.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("codeFix").toString().contains("AccessDeniedException"));
    }

    @Test
    void explain_injectionType_remediationMentionsParameterized() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("remediation").toString().contains("parameterized"));
    }

    @Test
    void explain_secretType_remediationMentionsRotation() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("SECRET", "CRITICAL", 85.0, 9.0);
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("remediation").toString().contains("Rotate secret"));
    }

    @Test
    void explain_withNullRecommendation_usesFallbackRemediation() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("XSS", "MEDIUM", 50.0, 6.0);
        f.setId(id);
        f.setRecommendation(null);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertTrue(result.get("remediation").toString().contains("secure coding"));
    }

    @Test
    void explain_withRecommendation_usesProvidedRemediation() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("XSS", "MEDIUM", 50.0, 6.0);
        f.setId(id);
        f.setRecommendation("Encode output and use CSP headers");
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertEquals("Encode output and use CSP headers", result.get("remediation"));
    }

    @Test
    void prioritize_withProjectId_filtersByProject() {
        UUID projectId = UUID.randomUUID();
        Finding f1 = buildFinding("INJECTION", "CRITICAL", 90.0, 9.5);
        Finding f2 = buildFinding("SCA", "HIGH", 70.0, 7.0);
        when(findingRepo.findByProjectId(projectId)).thenReturn(new ArrayList<>(List.of(f1, f2)));

        Map<String, Object> result = service.prioritize(projectId);

        assertEquals(2, result.get("total"));
        assertNotNull(result.get("prioritized"));
    }

    @Test
    void prioritize_nullProjectId_returnsAll() {
        Finding f1 = buildFinding("INJECTION", "CRITICAL", 90.0, 9.5);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f1)));

        Map<String, Object> result = service.prioritize(null);

        assertEquals(1, result.get("total"));
    }

    @Test
    void prioritize_sortsByRiskScoreDescending() {
        Finding f1 = buildFinding("SCA", "MEDIUM", 50.0, 5.0);
        Finding f2 = buildFinding("INJECTION", "CRITICAL", 95.0, 9.8);
        Finding f3 = buildFinding("SECRET", "HIGH", 75.0, 7.5);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f1, f2, f3)));

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertEquals(95.0, prioritized.get(0).get("risk"));
        assertEquals(75.0, prioritized.get(1).get("risk"));
        assertEquals(50.0, prioritized.get(2).get("risk"));
    }

    @Test
    void prioritize_limitsTo10() {
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < 15; i++) {
            Finding f = buildFinding("SCA", "MEDIUM", 50.0 + i, 5.0);
            findings.add(f);
        }
        when(findingRepo.findAll()).thenReturn(findings);

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertEquals(10, prioritized.size());
    }

    @Test
    void prioritize_emptyList_returnsEmptyPrioritized() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String, Object> result = service.prioritize(null);

        assertEquals(0, result.get("total"));
        assertTrue(((List<?>) result.get("prioritized")).isEmpty());
    }

    @Test
    void prioritize_nullRiskScore_treatedAsZero() {
        Finding f = buildFinding("INFO", "LOW", null, null);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f)));

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertEquals(0.0, ((Number) prioritized.get(0).get("risk")).doubleValue());
    }

    @Test
    void reportDraft_validProject_returnsAllSections() {
        UUID projectId = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        when(findingRepo.findByProjectId(projectId)).thenReturn(new ArrayList<>(List.of(f)));

        Map<String, Object> result = service.reportDraft(projectId, "EXECUTIVE");

        assertEquals("EXECUTIVE", result.get("type"));
        assertNotNull(result.get("executiveSummary"));
        assertNotNull(result.get("keyFindings"));
        assertNotNull(result.get("recommendations"));
        assertEquals("AI Security Analyst", result.get("generatedBy"));
    }

    @Test
    void reportDraft_nullType_defaultsToExecutive() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String, Object> result = service.reportDraft(null, null);

        assertEquals("EXECUTIVE", result.get("type"));
    }

    @Test
    void reportDraft_technicalType_returnsTechnical() {
        when(findingRepo.findAll()).thenReturn(new ArrayList<>());

        Map<String, Object> result = service.reportDraft(null, "TECHNICAL");

        assertEquals("TECHNICAL", result.get("type"));
    }

    @Test
    void rootCause_injectionType_containsUnsanitized() {
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("rootCause", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("Unsanitized input"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void rootCause_genericType_containsCwe() {
        Finding f = buildFinding("XSS", "MEDIUM", 50.0, 6.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("rootCause", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("CWE-89"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void impact_moderateRisk_returnsGenericImpact() {
        Finding f = buildFinding("SCA", "MEDIUM", 50.0, 6.0);
        f.setInternetExposed(false);
        f.setKev(false);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("impact", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("Risk level"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void codeFix_injectionType_suggestsPreparedStatement() {
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("codeFix", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("PreparedStatement"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void codeFix_genericType_containsCweReference() {
        Finding f = buildFinding("XSS", "MEDIUM", 50.0, 6.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("codeFix", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("CWE-89"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void priority_p0_whenRiskScore81() {
        Finding f = buildFinding("INJECTION", "CRITICAL", 81.0, 9.5);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("priority", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("P0"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void priority_p1_whenRiskScore61() {
        Finding f = buildFinding("SCA", "HIGH", 61.0, 7.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("priority", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("P1"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void priority_p2_whenRiskScore41() {
        Finding f = buildFinding("SCA", "MEDIUM", 41.0, 5.0);
        try {
            java.lang.reflect.Method method = AiAnalystService.class.getDeclaredMethod("priority", Finding.class);
            method.setAccessible(true);
            String result = (String) method.invoke(service, f);
            assertTrue(result.contains("P2"));
        } catch (Exception e) {
            fail("reflection failed: " + e.getMessage());
        }
    }

    @Test
    void prioritize_withKe_annotationInReason() {
        Finding f = buildFinding("SCA", "HIGH", 80.0, 8.0);
        f.setKev(true);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f)));

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertTrue(prioritized.get(0).get("reason").toString().contains("KEV"));
    }

    @Test
    void prioritize_withExposed_annotationInReason() {
        Finding f = buildFinding("SCA", "HIGH", 80.0, 8.0);
        f.setInternetExposed(true);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f)));

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertTrue(prioritized.get(0).get("reason").toString().contains("exposed"));
    }

    @Test
    void prioritize_nullAssetName_showsUnknown() {
        Finding f = buildFinding("SCA", "HIGH", 80.0, 8.0);
        f.setAssetName(null);
        when(findingRepo.findAll()).thenReturn(new ArrayList<>(List.of(f)));

        Map<String, Object> result = service.prioritize(null);

        List<Map<String, Object>> prioritized = (List<Map<String, Object>>) result.get("prioritized");
        assertEquals("unknown", prioritized.get(0).get("asset"));
    }

    @Test
    void explain_codeSnippetNull_usesEmptyString() {
        UUID id = UUID.randomUUID();
        Finding f = buildFinding("INJECTION", "HIGH", 70.0, 8.0);
        f.setId(id);
        f.setCodeSnippet(null);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));

        Map<String, Object> result = service.explain(id);

        assertNotNull(result.get("evidenceSummary"));
    }
}
