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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FindingServiceTest {

    @Mock
    private FindingRepository findingRepo;

    @Mock
    private EvidenceRepository evidenceRepo;

    @Mock
    private FindingInstanceRepository instanceRepo;

    @Mock
    private RiskEngine riskEngine;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private FindingService findingService;

    private Finding testFinding;

    @BeforeEach
    void setUp() {
        testFinding = Finding.builder()
                .id(UUID.randomUUID())
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
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);
        when(evidenceRepo.save(any(Evidence.class))).thenReturn(null);

        Finding result = findingService.create(testFinding);

        assertNotNull(result);
        verify(riskEngine).enrich(any(Finding.class));
        verify(findingRepo).save(any(Finding.class));
        verify(evidenceRepo).save(any(Evidence.class));
        verify(auditService).log(eq("FINDING_CREATED"), anyString(), anyString(), anyString());
    }

    @Test
    void create_duplicateFingerprint_createsInstance() {
        Finding existingFinding = Finding.builder()
                .id(UUID.randomUUID())
                .findingId("FND-1000")
                .fingerprint("abc123")
                .build();
        when(findingRepo.findByFingerprint("abc123")).thenReturn(List.of(existingFinding));
        when(instanceRepo.save(any(FindingInstance.class))).thenReturn(null);

        Finding result = findingService.create(testFinding);

        verify(instanceRepo).save(any(FindingInstance.class));
        verify(findingRepo, never()).save(any(Finding.class));
    }

    @Test
    void updateStatus_changesStatus() {
        when(findingRepo.findById(testFinding.getId())).thenReturn(Optional.of(testFinding));
        when(findingRepo.save(any(Finding.class))).thenReturn(testFinding);

        Finding result = findingService.updateStatus(testFinding.getId(), "CONFIRMED", "Verified by pentester");

        assertEquals("CONFIRMED", result.getStatus());
        verify(auditService).log(eq("FINDING_STATUS"), anyString(), anyString(), anyString());
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
    void stats_returnsAggregations() {
        when(findingRepo.countBySeverity()).thenReturn(List.of(new Object[]{"CRITICAL", 5L}, new Object[]{"HIGH", 10L}));
        when(findingRepo.countByStatusAgg()).thenReturn(List.of(new Object[]{"OPEN", 15L}));
        when(findingRepo.countByRiskLevel()).thenReturn(List.of(new Object[]{"VERY_HIGH", 3L}));
        when(findingRepo.count()).thenReturn(15L);

        Map<String, Object> result = findingService.stats(null);

        assertNotNull(result.get("bySeverity"));
        assertNotNull(result.get("byStatus"));
        assertNotNull(result.get("total"));
        assertEquals(15L, result.get("total"));
    }
}
