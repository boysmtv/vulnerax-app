package com.vulnerax.modules.finding;

import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.risk.RiskEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FindingServiceExtendedTest {

    @Mock private FindingRepository findingRepo;
    @Mock private EvidenceRepository evidenceRepo;
    @Mock private FindingInstanceRepository instanceRepo;
    @Mock private RiskEngine riskEngine;
    @Mock private AuditService auditService;
    @Mock private FindingCorrelationEngine correlationEngine;

    @InjectMocks private FindingService findingService;

    private Finding testFinding;

    @BeforeEach
    void setUp() {
        testFinding = Finding.builder()
                .findingId("FND-1001")
                .title("SQL Injection")
                .description("SQL injection in login form")
                .type("SAST")
                .severity("CRITICAL")
                .confidence("CONFIRMED")
                .status("OPEN")
                .projectId(UUID.randomUUID())
                .assetId(UUID.randomUUID())
                .assetName("auth-service")
                .source("sast-analyzer")
                .cwe("CWE-89")
                .cvss(9.8)
                .fingerprint("abc123")
                .businessCriticality("HIGH")
                .owner("Security Team")
                .filePath("src/main/java/Auth.java")
                .lineNumber(42)
                .build();
        testFinding.setId(UUID.randomUUID());
    }

    @Test
    void update_savesAndReturns() {
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);

        Finding result = findingService.update(testFinding);

        assertNotNull(result);
        verify(findingRepo).save(testFinding);
    }

    @Test
    void list_byAssetId_filtersCorrectly() {
        UUID assetId = testFinding.getAssetId();
        Page<Finding> page = new PageImpl<>(List.of(testFinding));
        when(findingRepo.findByAssetId(eq(assetId), any())).thenReturn(page);

        var result = findingService.list(null, assetId, null, null, null, null,
                org.springframework.data.domain.PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
        verify(findingRepo).findByAssetId(eq(assetId), any());
    }

    @Test
    void create_withEvidenceJson_createsScannerResultEvidence() {
        testFinding.setEvidenceJson("{\"scanner\":\"sast\",\"output\":\"vuln found\"}");
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        findingService.create(testFinding);

        verify(evidenceRepo).save(argThat(e -> "SCANNER_RESULT".equals(e.getType())));
    }

    @Test
    void create_withCodeSnippet_createsCodeSnippetEvidence() {
        testFinding.setCodeSnippet("SELECT * FROM users WHERE id = ?");
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        findingService.create(testFinding);

        verify(evidenceRepo).save(argThat(e -> "CODE_SNIPPET".equals(e.getType())));
    }

    @Test
    void create_withDataFlow_createsDataFlowEvidence() {
        testFinding.setDataFlow("UserInput -> QueryBuilder -> DB.execute");
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        findingService.create(testFinding);

        verify(evidenceRepo).save(argThat(e -> "DATA_FLOW".equals(e.getType())));
    }

    @Test
    void create_withAllEvidenceTypes_createsThreeEvidenceRecords() {
        testFinding.setEvidenceJson("{\"output\":\"vuln\"}");
        testFinding.setCodeSnippet("SELECT * FROM users");
        testFinding.setDataFlow("Input -> DB");
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        findingService.create(testFinding);

        verify(evidenceRepo, times(3)).save(any(Evidence.class));
    }

    @Test
    void create_noEvidenceTypes_createsNoEvidence() {
        testFinding.setEvidenceJson(null);
        testFinding.setCodeSnippet(null);
        testFinding.setDataFlow(null);
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        findingService.create(testFinding);

        verify(evidenceRepo, never()).save(any());
    }

    @Test
    void create_withCweIdOnly_syncsCweFromCweId() {
        testFinding.setCweId("CWE-79");
        testFinding.setCwe(null);
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        Finding result = findingService.create(testFinding);

        verify(findingRepo).save(argThat(f -> "CWE-79".equals(f.getCwe())));
    }

    @Test
    void create_withCweOnly_syncsCweIdFromCwe() {
        testFinding.setCwe("CWE-89");
        testFinding.setCweId(null);
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        Finding result = findingService.create(testFinding);

        verify(findingRepo).save(argThat(f -> "CWE-89".equals(f.getCweId())));
    }

    @Test
    void create_withNoFindingId_generatesOne() {
        testFinding.setFindingId(null);
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any())).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any())).thenReturn(testFinding);
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "INDEPENDENT"));

        Finding result = findingService.create(testFinding);

        verify(findingRepo).save(argThat(f -> f.getFindingId() != null && f.getFindingId().startsWith("FND-")));
    }

    @Test
    void updateStatus_falsePositive_logsAudit() {
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.save(any())).thenReturn(testFinding);

        findingService.updateStatus(testFinding.getId(), "FALSE_POSITIVE", "Not a real vuln");

        verify(auditService).log(eq("FINDING_STATUS"), eq("Finding"), eq(testFinding.getId().toString()), contains("FALSE_POSITIVE"));
    }

    @Test
    void updateStatus_riskAccepted_logsAudit() {
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.save(any())).thenReturn(testFinding);

        findingService.updateStatus(testFinding.getId(), "RISK_ACCEPTED", "Accepted risk");

        verify(auditService).log(eq("FINDING_STATUS"), eq("Finding"), eq(testFinding.getId().toString()), contains("RISK_ACCEPTED"));
    }

    @Test
    void correlation_withMatches_returnsCorrelatedFindings() {
        Finding match1 = Finding.builder().title("XSS").type("DAST").severity("HIGH").cwe("CWE-79").build();
        match1.setId(UUID.randomUUID());
        match1.setRiskScore(65.0);
        Finding match2 = Finding.builder().title("CSRF").type("DAST").severity("MEDIUM").cwe("CWE-352").build();
        match2.setId(UUID.randomUUID());
        match2.setRiskScore(45.0);

        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.findByProjectId(any(), any()))
                .thenReturn(new PageImpl<>(List.of(testFinding, match1, match2)));
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(
                        List.of(match1, match2), "CWE_SIMILARITY", false, "MERGE_CANDIDATES"));

        Map<String, Object> result = findingService.correlation(testFinding.getId());

        assertNotNull(result.get("finding"));
        assertNotNull(result.get("correlated"));
        assertNotNull(result.get("correlation"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> correlated = (List<Map<String, Object>>) result.get("correlated");
        assertEquals(2, correlated.size());
    }

    @Test
    void correlation_twoMatches_createsAttackPathCandidate() {
        Finding match1 = Finding.builder().title("XSS").type("DAST").severity("HIGH").cwe("CWE-79").build();
        match1.setId(UUID.randomUUID());
        match1.setRiskScore(65.0);
        Finding match2 = Finding.builder().title("CSRF").type("DAST").severity("MEDIUM").cwe("CWE-352").build();
        match2.setId(UUID.randomUUID());
        match2.setRiskScore(45.0);

        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.findByProjectId(any(), any()))
                .thenReturn(new PageImpl<>(List.of(testFinding, match1, match2)));
        when(correlationEngine.correlate(any(), anyList()))
                .thenReturn(new FindingCorrelationEngine.CorrelationResult(
                        List.of(match1, match2), "CWE_SIMILARITY", false, "MERGE_CANDIDATES"));

        Map<String, Object> result = findingService.correlation(testFinding.getId());

        assertTrue(result.containsKey("attackPathCandidate"),
                "Should contain attackPathCandidate when >= 2 matches");
    }

    @Test
    void stats_withNullAvgRiskScore_returnsZero() {
        List<Object[]> sevList = new ArrayList<>();
        sevList.add(new Object[]{"HIGH", 5L});
        List<Object[]> statusList = new ArrayList<>();
        statusList.add(new Object[]{"OPEN", 5L});
        List<Object[]> riskList = new ArrayList<>();
        riskList.add(new Object[]{"HIGH", 5L});
        when(findingRepo.countBySeverity()).thenReturn(sevList);
        when(findingRepo.countByStatusAgg()).thenReturn(statusList);
        when(findingRepo.countByRiskLevel()).thenReturn(riskList);
        when(findingRepo.count()).thenReturn(5L);
        when(findingRepo.countBySeverity("CRITICAL")).thenReturn(0L);
        when(findingRepo.countBySeverity("HIGH")).thenReturn(5L);
        when(findingRepo.countByKev(true)).thenReturn(0L);
        when(findingRepo.avgRiskScore()).thenReturn(null);

        Map<String, Object> result = findingService.stats(null);

        assertEquals(0.0, result.get("avgRiskScore"), "Null avgRiskScore should default to 0");
    }
}
