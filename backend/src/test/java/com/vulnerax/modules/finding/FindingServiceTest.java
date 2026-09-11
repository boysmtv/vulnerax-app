package com.vulnerax.modules.finding;

import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.risk.RiskEngine;
import com.vulnerax.modules.scan.Scan;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class FindingServiceTest {

    @Mock FindingRepository findingRepo;
    @Mock EvidenceRepository evidenceRepo;
    @Mock FindingInstanceRepository instanceRepo;
    @Mock RiskEngine riskEngine;
    @Mock AuditService auditService;
    @InjectMocks FindingService service;

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(findingRepo.findByProjectId(eq(pid), any())).thenReturn(new PageImpl<>(List.of()));
        var page = service.list(pid,null,null,null,null,null, PageRequest.of(0,10));
        assertThat(page).isNotNull();
    }

    @Test
    void create_enriches_and_saves_and_creates_evidence() {
        Finding f = Finding.builder().title("SQLi").type("INJECTION").severity("HIGH").confidence("HIGH").build();
        // risk enrich will set fingerprint; mock to set it
        doAnswer(inv -> {
            Finding arg = inv.getArgument(0);
            arg.setFingerprint("abc"); arg.setRiskScore(85.0); arg.setRiskLevel("CRITICAL");
            return null;
        }).when(riskEngine).enrich(any());
        when(findingRepo.findByFingerprint("abc")).thenReturn(List.of());
        when(findingRepo.save(any())).thenAnswer(i -> { Finding s=i.getArgument(0); s.setId(UUID.randomUUID()); return s; });
        when(evidenceRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        Finding saved = service.create(f);
        assertThat(saved.getId()).isNotNull();
        verify(evidenceRepo).save(any(Evidence.class));
        verify(auditService).log(any(), any(), any(), any());
    }

    @Test
    void create_dedup_creates_instance_instead_of_duplicate() {
        Finding f = Finding.builder().title("Dup").type("INJECTION").severity("HIGH").confidence("HIGH")
                .assetName("a").filePath("a.java").lineNumber(10).source("semgrep").build();
        doAnswer(inv -> { ((Finding)inv.getArgument(0)).setFingerprint("dup"); return null; }).when(riskEngine).enrich(any());
        Finding existing = Finding.builder().title("Dup").build();
        existing.setId(UUID.randomUUID()); existing.setFindingId("FND-1001"); existing.setFingerprint("dup");
        when(findingRepo.findByFingerprint("dup")).thenReturn(List.of(existing));
        Finding res = service.create(f);
        assertThat(res.getFindingId()).isEqualTo("FND-1001");
        verify(instanceRepo).save(any(FindingInstance.class));
        verify(findingRepo, never()).save(argThat(x -> x != existing && "Dup".equals(((Finding)x).getTitle())));
    }

    @Test
    void updateStatus_transitions() {
        UUID id = UUID.randomUUID();
        Finding cur = Finding.builder().title("t").type("INJECTION").severity("MEDIUM").confidence("MEDIUM").status("OPEN").build();
        cur.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(cur));
        when(findingRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        var updated = service.updateStatus(id, "FALSE_POSITIVE", "fp");
        assertThat(updated.getStatus()).isEqualTo("FALSE_POSITIVE");
        verify(auditService).log(any(), any(), any(), any());
    }

    @Test
    void updateStatus_reopened_when_resolved_to_open() {
        UUID id = UUID.randomUUID();
        Finding cur = Finding.builder().status("RESOLVED").title("t").type("INJECTION").severity("HIGH").confidence("HIGH").build();
        cur.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(cur));
        when(findingRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        var updated = service.updateStatus(id, "OPEN", "reopen");
        assertThat(updated.getStatus()).isEqualTo("REOPENED");
    }

    @Test
    void stats_aggregates() {
        List<Object[]> sev = new java.util.ArrayList<>(); sev.add(new Object[]{"HIGH", 2L});
        List<Object[]> sta = new java.util.ArrayList<>(); sta.add(new Object[]{"OPEN", 5L});
        List<Object[]> risk = new java.util.ArrayList<>(); risk.add(new Object[]{"CRITICAL", 1L});
        when(findingRepo.countBySeverity()).thenReturn(sev);
        when(findingRepo.countByStatusAgg()).thenReturn(sta);
        when(findingRepo.countByRiskLevel()).thenReturn(risk);
        when(findingRepo.count()).thenReturn(5L);
        var m = service.stats(null);
        assertThat(m).containsKeys("bySeverity","byStatus","byRiskLevel","total");
    }

    @Test
    void generateMockFindings_is_noop_when_mock_disabled() {
        Scan scan = Scan.builder().scannerType("SEMGREP").target("app.jar").build();
        scan.setId(UUID.randomUUID());
        scan.setProjectId(UUID.randomUUID());
        // after mock removal, method is no-op and should not create findings
        service.generateMockFindings(scan);
        verify(findingRepo, never()).save(any());
        verify(evidenceRepo, never()).save(any());
    }

    @Test
    void correlation_finds_related() {
        UUID id = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        Finding f = Finding.builder().title("main").type("INJECTION").cwe("CWE-89").assetId(assetId).build();
        f.setId(id);
        when(findingRepo.findById(id)).thenReturn(Optional.of(f));
        Finding other = Finding.builder().title("other").type("INJECTION").cwe("CWE-89").assetId(assetId).build();
        other.setId(UUID.randomUUID());
        when(findingRepo.findByAssetId(eq(assetId), any())).thenReturn(new PageImpl<>(List.of(f, other)));
        var corr = service.correlation(id);
        assertThat(corr).containsKeys("finding","correlated","attackPathCandidate");
        assertThat((List<?>)corr.get("correlated")).hasSize(1);
    }
}
