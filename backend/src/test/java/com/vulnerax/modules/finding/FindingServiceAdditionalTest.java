package com.vulnerax.modules.finding;

import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.risk.RiskEngine;
import com.vulnerax.modules.scan.Scan;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FindingServiceAdditionalTest {

    @Mock FindingRepository findingRepo;
    @Mock EvidenceRepository evidenceRepo;
    @Mock FindingInstanceRepository instanceRepo;
    @Mock RiskEngine riskEngine;
    @Mock AuditService auditService;
    @Mock FindingCorrelationEngine correlationEngine;
    @InjectMocks FindingService service;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID pid = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").title("SQLi").severity("CRITICAL").build();
        Page<Finding> page = new PageImpl<>(List.of(f), PageRequest.of(0, 10), 1);
        when(findingRepo.findByProjectId(pid, PageRequest.of(0, 10))).thenReturn(page);
        Page<Finding> result = service.list(pid, null, null, null, null, null, PageRequest.of(0, 10));
        assertThat(result.getContent()).hasSize(1);
    }

    @Test
    void list_withAssetId_filtersByAsset() {
        UUID aid = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-002").title("XSS").build();
        Page<Finding> page = new PageImpl<>(List.of(f), PageRequest.of(0, 10), 1);
        when(findingRepo.findByAssetId(aid, PageRequest.of(0, 10))).thenReturn(page);
        Page<Finding> result = service.list(null, aid, null, null, null, null, PageRequest.of(0, 10));
        assertThat(result.getContent()).hasSize(1);
    }

    @Test
    void list_withOrgId_filtersByOrg() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "test@test.com");
        Finding f = Finding.builder().findingId("F-003").title("CSRF").build();
        Page<Finding> page = new PageImpl<>(List.of(f), PageRequest.of(0, 10), 1);
        when(findingRepo.findByOrganizationId(orgId, PageRequest.of(0, 10))).thenReturn(page);
        Page<Finding> result = service.list(null, null, null, null, null, null, PageRequest.of(0, 10));
        assertThat(result.getContent()).hasSize(1);
    }

    @Test
    void list_noFilters_returnsAll() {
        TenantContext.clear();
        Finding f = Finding.builder().findingId("F-004").title("Info").build();
        Page<Finding> page = new PageImpl<>(List.of(f), PageRequest.of(0, 10), 1);
        when(findingRepo.findAll(PageRequest.of(0, 10))).thenReturn(page);
        Page<Finding> result = service.list(null, null, null, null, null, null, PageRequest.of(0, 10));
        assertThat(result.getContent()).hasSize(1);
    }

    @Test
    void get_returnsFinding() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").title("Test").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        Finding result = service.get(id);
        assertThat(result.getFindingId()).isEqualTo("F-001");
    }

    @Test
    void create_withNoDuplicate_setsFingerprint() {
        UUID assetId = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-NEW").title("SQLi").severity("CRITICAL")
                .assetId(assetId).fingerprint("fp-123").build();
        when(findingRepo.findByFingerprint("fp-123")).thenReturn(List.of());
        when(findingRepo.findByAssetId(eq(assetId), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getFindingId()).isEqualTo("F-NEW");
        verify(auditService).log(eq("FINDING_CREATED"), anyString(), anyString(), anyString());
    }

    @Test
    void create_withFingerprintDuplicate_createsInstance() {
        UUID assetId = UUID.randomUUID();
        Finding f = Finding.builder().title("SQLi").severity("CRITICAL")
                .assetId(assetId).fingerprint("fp-dup")
                .assetName("api.test.com").filePath("/src/main.java").lineNumber(42).source("semgrep").build();
        Finding existing = Finding.builder().findingId("F-EXISTING").title("SQLi").build();
        existing.setId(UUID.randomUUID());
        when(findingRepo.findByFingerprint("fp-dup")).thenReturn(List.of(existing));
        when(instanceRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Finding result = service.create(f);
        assertThat(result.getFindingId()).isEqualTo("F-EXISTING");
        verify(instanceRepo).save(any());
    }

    @Test
    void create_setsOrgIdFromContext() {
        UUID orgId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        TenantContext.set(orgId, null, "test@test.com");
        Finding f = Finding.builder().title("XSS").severity("HIGH").assetId(assetId).build();
        when(findingRepo.findByFingerprint(any())).thenReturn(List.of());
        when(findingRepo.findByAssetId(eq(assetId), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getOrganizationId()).isEqualTo(orgId);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void stats_returnsMapWithCounts() {
        List sevList = new java.util.ArrayList();
        sevList.add(new Object[]{"CRITICAL", 5L});
        sevList.add(new Object[]{"HIGH", 10L});
        when(findingRepo.countBySeverity()).thenReturn(sevList);

        List statusList = new java.util.ArrayList();
        statusList.add(new Object[]{"OPEN", 8L});
        statusList.add(new Object[]{"RESOLVED", 7L});
        when(findingRepo.countByStatusAgg()).thenReturn(statusList);

        List riskList = new java.util.ArrayList();
        riskList.add(new Object[]{"CRITICAL", 3L});
        when(findingRepo.countByRiskLevel()).thenReturn(riskList);

        when(findingRepo.count()).thenReturn(15L);
        when(findingRepo.countBySeverity("CRITICAL")).thenReturn(5L);
        when(findingRepo.countByKev(true)).thenReturn(2L);
        when(findingRepo.avgRiskScore()).thenReturn(7.5);
        Map<String, Object> stats = service.stats(null);
        assertThat(stats.get("total")).isEqualTo(15L);
        assertThat(stats.get("critical")).isEqualTo(5L);
        assertThat(stats.get("kev")).isEqualTo(2L);
        assertThat(stats.get("avgRiskScore")).isEqualTo(7.5);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    @Test
    void stats_avgRiskScoreNull_returnsZero() {
        when(findingRepo.countBySeverity()).thenReturn(new java.util.ArrayList());
        when(findingRepo.countByStatusAgg()).thenReturn(new java.util.ArrayList());
        when(findingRepo.countByRiskLevel()).thenReturn(new java.util.ArrayList());
        when(findingRepo.count()).thenReturn(0L);
        when(findingRepo.countBySeverity("CRITICAL")).thenReturn(0L);
        when(findingRepo.countByKev(true)).thenReturn(0L);
        when(findingRepo.avgRiskScore()).thenReturn(null);
        Map<String, Object> stats = service.stats(null);
        assertThat(stats.get("avgRiskScore")).isEqualTo(0.0);
    }

    @Test
    void evidences_returnsList() {
        UUID findingId = UUID.randomUUID();
        Evidence e = Evidence.builder().findingId(findingId).type("LOG").build();
        when(evidenceRepo.findByFindingId(findingId)).thenReturn(List.of(e));
        List<Evidence> result = service.evidences(findingId);
        assertThat(result).hasSize(1);
    }

    @Test
    void instances_returnsList() {
        UUID findingId = UUID.randomUUID();
        FindingInstance fi = FindingInstance.builder().findingId(findingId).assetName("api").build();
        when(instanceRepo.findByFindingId(findingId)).thenReturn(List.of(fi));
        List<FindingInstance> result = service.instances(findingId);
        assertThat(result).hasSize(1);
    }

    @Test
    void updateStatus_setsNewStatus() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").status("OPEN").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Finding result = service.updateStatus(id, "IN_PROGRESS", "Starting investigation");
        assertThat(result.getStatus()).isEqualTo("IN_PROGRESS");
    }

    @Test
    void updateStatus_resolvedToOpen_reopens() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").status("RESOLVED").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Finding result = service.updateStatus(id, "OPEN", "Reopening");
        assertThat(result.getStatus()).isEqualTo("REOPENED");
    }

    @Test
    void updateStatus_falsePositive_audits() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").status("OPEN").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        service.updateStatus(id, "FALSE_POSITIVE", "Not a real issue");
        verify(auditService).log(eq("FINDING_STATUS"), anyString(), anyString(), anyString());
    }

    @Test
    void correlation_returnsCorrelationMap() {
        UUID id = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").title("SQLi").severity("CRITICAL")
                .projectId(projectId).type("SAST").cwe("CWE-89").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.findByProjectId(projectId, PageRequest.of(0, 1000))).thenReturn(new PageImpl<>(List.of(f)));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(f), "EXACT_MATCH", false, "MERGE"));
        Map<String, Object> result = service.correlation(id);
        assertThat(result).containsKey("finding");
        assertThat(result).containsKey("correlated");
        assertThat(result).containsKey("correlation");
    }

    @Test
    void generateMockFindings_smokeTest() {
        Scan scan = new Scan();
        scan.setId(UUID.randomUUID());
        assertDoesNotThrow(() -> service.generateMockFindings(scan));
    }

    @Test
    void create_nullFindingId_autoGeneratesId() {
        Finding f = Finding.builder().title("XSS").severity("MEDIUM")
                .assetId(UUID.randomUUID()).fingerprint("fp-auto").build();
        when(findingRepo.findByFingerprint("fp-auto")).thenReturn(List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getFindingId()).startsWith("FND-");
    }

    @Test
    void create_cweIdSyncsFromCwe() {
        Finding f = Finding.builder().title("SQLi").severity("CRITICAL")
                .assetId(UUID.randomUUID()).fingerprint("fp-cwe").cwe("CWE-89").build();
        when(findingRepo.findByFingerprint("fp-cwe")).thenReturn(List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            if (saved.getId() == null) saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getCweId()).isEqualTo("CWE-89");
        assertThat(result.getCwe()).isEqualTo("CWE-89");
    }

    @Test
    void create_cweSyncsFromCweId() {
        Finding f = Finding.builder().title("XSS").severity("HIGH")
                .assetId(UUID.randomUUID()).fingerprint("fp-cwe2").cweId("CWE-79").build();
        when(findingRepo.findByFingerprint("fp-cwe2")).thenReturn(List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            if (saved.getId() == null) saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getCwe()).isEqualTo("CWE-79");
    }

    @Test
    void create_correlationDuplicate_setsDuplicateFlag() {
        Finding f = Finding.builder().title("SQLi").severity("CRITICAL")
                .assetId(UUID.randomUUID()).fingerprint("fp-corr").build();
        when(findingRepo.findByFingerprint("fp-corr")).thenReturn(List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any())).thenReturn(new PageImpl<>(List.of()));
        Finding match = Finding.builder().title("SQLi").severity("CRITICAL").build();
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(match), "EXACT_MATCH", true, "MERGE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            if (saved.getId() == null) saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result.getDuplicate()).isTrue();
    }

    @Test
    void create_withEvidenceJson_savesScannerEvidence() {
        Finding f = Finding.builder().title("SAST").severity("HIGH")
                .assetId(UUID.randomUUID()).fingerprint("fp-ev")
                .evidenceJson("{\"rule\":\"eval\"}")
                .codeSnippet("Runtime.exec(input)")
                .dataFlow("source->sink")
                .source("sast-analyzer")
                .filePath("/src/Main.java")
                .build();
        when(findingRepo.findByFingerprint("fp-ev")).thenReturn(List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any())).thenReturn(new PageImpl<>(List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        service.create(f);
        verify(evidenceRepo, atLeast(3)).save(any(Evidence.class));
    }

    @Test
    void updateStatus_riskAccepted_audits() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").status("OPEN").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        service.updateStatus(id, "RISK_ACCEPTED", "Accepted by business");
        verify(auditService).log(eq("FINDING_STATUS"), anyString(), anyString(), anyString());
    }

    @Test
    void correlation_twoMatches_returnsAttackPathCandidate() {
        UUID id = UUID.randomUUID();
        UUID projectId = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").title("SQLi").severity("CRITICAL")
                .projectId(projectId).type("SAST").cwe("CWE-89").build();
        f.setId(id);
        Finding match1 = Finding.builder().findingId("F-002").title("XSS").severity("HIGH").type("SAST").build();
        match1.setId(UUID.randomUUID());
        Finding match2 = Finding.builder().findingId("F-003").title("SSRF").severity("HIGH").type("DAST").build();
        match2.setId(UUID.randomUUID());
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.findByProjectId(projectId, PageRequest.of(0, 1000))).thenReturn(new PageImpl<>(List.of(f, match1, match2)));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(List.of(match1, match2), "EXACT_MATCH", false, "MERGE"));
        Map<String, Object> result = service.correlation(id);
        assertThat(result).containsKey("attackPathCandidate");
        assertThat(result.get("attackPathCandidate")).isInstanceOf(Map.class);
    }
}
