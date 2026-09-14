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

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FindingServiceMockGenerationTest {

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
    void generateMockFindings_variousSeverities() {
        Scan scan = new Scan();
        scan.setId(UUID.randomUUID());
        assertDoesNotThrow(() -> service.generateMockFindings(scan));
    }

    @Test
    void generateMockFindings_multipleCalls() {
        Scan scan = new Scan();
        scan.setId(UUID.randomUUID());
        assertDoesNotThrow(() -> service.generateMockFindings(scan));
        assertDoesNotThrow(() -> service.generateMockFindings(scan));
    }

    @Test
    void correlation_nullProjectId_handlesGracefully() {
        UUID id = UUID.randomUUID();
        Finding f = Finding.builder().findingId("F-001").title("Test").severity("HIGH")
                .projectId(null).type("SAST").build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(java.util.Optional.of(f));
        when(findingRepo.findByProjectId(isNull(), any(org.springframework.data.domain.Pageable.class)))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(java.util.List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(java.util.List.of(), "NO_MATCH", false, "NONE"));
        Map<String, Object> result = service.correlation(id);
        assertThat(result).containsKey("finding");
    }

    @Test
    void create_noFingerprint_generatesOne() {
        Finding f = Finding.builder().title("No FP").severity("MEDIUM")
                .assetId(UUID.randomUUID()).fingerprint(null).build();
        when(findingRepo.findByFingerprint(any())).thenReturn(java.util.List.of());
        when(findingRepo.findByAssetId(any(UUID.class), any()))
                .thenReturn(new org.springframework.data.domain.PageImpl<>(java.util.List.of()));
        when(correlationEngine.correlate(any(), any())).thenReturn(
                new FindingCorrelationEngine.CorrelationResult(java.util.List.of(), "NO_MATCH", false, "NONE"));
        when(findingRepo.save(any())).thenAnswer(inv -> {
            Finding saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        Finding result = service.create(f);
        assertThat(result).isNotNull();
    }

    @Test
    void stats_withNullAvgRiskScore_returnsZero() {
        when(findingRepo.countBySeverity()).thenReturn(new java.util.ArrayList<>());
        when(findingRepo.countByStatusAgg()).thenReturn(new java.util.ArrayList<>());
        when(findingRepo.countByRiskLevel()).thenReturn(new java.util.ArrayList<>());
        when(findingRepo.count()).thenReturn(10L);
        when(findingRepo.countBySeverity("CRITICAL")).thenReturn(3L);
        when(findingRepo.countByKev(true)).thenReturn(1L);
        when(findingRepo.avgRiskScore()).thenReturn(null);
        Map<String, Object> stats = service.stats(UUID.randomUUID());
        assertThat(stats.get("avgRiskScore")).isEqualTo(0.0);
    }
}
