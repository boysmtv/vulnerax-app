package com.vulnerax.modules.finding;

import com.vulnerax.common.exception.ResourceNotFoundException;
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
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FindingServiceTest {

    @Mock private FindingRepository findingRepo;
    @Mock private EvidenceRepository evidenceRepo;
    @Mock private FindingInstanceRepository instanceRepo;
    @Mock private RiskEngine riskEngine;
    @Mock private AuditService auditService;

    @InjectMocks
    private FindingService findingService;

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
    void list_returnsPage() {
        Page<Finding> page = new PageImpl<>(List.of(testFinding));
        when(findingRepo.findAll(any(Pageable.class))).thenReturn(page);

        Page<Finding> result = findingService.list(null, null, null, null, null, null, PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
        assertEquals("SQL Injection", result.getContent().get(0).getTitle());
    }

    @Test
    void list_byProjectId_filtersCorrectly() {
        UUID projectId = testFinding.getProjectId();
        Page<Finding> page = new PageImpl<>(List.of(testFinding));
        when(findingRepo.findByProjectId(eq(projectId), any(Pageable.class))).thenReturn(page);

        Page<Finding> result = findingService.list(projectId, null, null, null, null, null, PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
        verify(findingRepo).findByProjectId(eq(projectId), any(Pageable.class));
    }

    @Test
    void get_existingId_returnsFinding() {
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        Finding result = findingService.get(testFinding.getId());
        assertEquals("SQL Injection", result.getTitle());
    }

    @Test
    void get_nonExistingId_throws() {
        UUID fakeId = UUID.randomUUID();
        when(findingRepo.findById(fakeId)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> findingService.get(fakeId));
    }

    @Test
    void create_newFinding_savesWithRiskEnrichment() {
        when(findingRepo.findByFingerprint(any())).thenReturn(Collections.emptyList());
        when(findingRepo.findByAssetId(any(), any(Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);

        Finding result = findingService.create(testFinding);

        assertNotNull(result);
        verify(riskEngine).enrich(any(Finding.class));
        verify(findingRepo).save(any(Finding.class));
    }

    @Test
    void create_duplicateFingerprint_createsInstance() {
        Finding existingFinding = Finding.builder()
                .findingId("FND-1000")
                .fingerprint("abc123")
                .type("SAST").severity("CRITICAL").confidence("HIGH").status("OPEN")
                .title("Existing").build();
        existingFinding.setId(UUID.randomUUID());
        when(findingRepo.findByFingerprint("abc123")).thenReturn(List.of(existingFinding));
        when(instanceRepo.save(any(FindingInstance.class))).thenReturn(null);

        Finding result = findingService.create(testFinding);

        verify(instanceRepo).save(any(FindingInstance.class));
    }

    @Test
    void updateStatus_changesStatus() {
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);

        Finding result = findingService.updateStatus(testFinding.getId(), "CONFIRMED", "Verified");

        assertEquals("CONFIRMED", result.getStatus());
    }

    @Test
    void updateStatus_resolvedToOpen_makesReopened() {
        testFinding.setStatus("RESOLVED");
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);

        Finding result = findingService.updateStatus(testFinding.getId(), "OPEN", "Reopening");
        assertEquals("REOPENED", result.getStatus());
    }

    @Test
    @SuppressWarnings("unchecked")
    void stats_returnsAggregations() {
        List<Object[]> sevList = new ArrayList<>();
        sevList.add(new Object[]{"CRITICAL", 5L});
        sevList.add(new Object[]{"HIGH", 10L});
        List<Object[]> statusList = new ArrayList<>();
        statusList.add(new Object[]{"OPEN", 15L});
        List<Object[]> riskList = new ArrayList<>();
        riskList.add(new Object[]{"VERY_HIGH", 3L});

        when(findingRepo.countBySeverity()).thenReturn(sevList);
        when(findingRepo.countByStatusAgg()).thenReturn(statusList);
        when(findingRepo.countByRiskLevel()).thenReturn(riskList);
        when(findingRepo.count()).thenReturn(15L);

        Map<String, Object> result = findingService.stats(null);

        assertNotNull(result.get("bySeverity"));
        assertNotNull(result.get("byStatus"));
        assertEquals(15L, result.get("total"));
    }
}
