package com.vulnerax.modules.coverage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CoverageServiceAdditionalTest {

    @Mock CoverageRepository repo;
    @InjectMocks CoverageService service;

    @Test
    void upsert_savesAndReturns() {
        SecurityCoverage sc = SecurityCoverage.builder()
                .projectId(UUID.randomUUID()).domain("AUTH").build();
        when(repo.save(any())).thenReturn(sc);
        SecurityCoverage result = service.upsert(sc);
        assertThat(result).isEqualTo(sc);
        verify(repo).save(sc);
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID pid = UUID.randomUUID();
        SecurityCoverage sc = SecurityCoverage.builder()
                .projectId(pid).domain("AUTH").status("TESTED").build();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sc));
        List<SecurityCoverage> result = service.list(pid);
        assertThat(result).hasSize(1);
        assertThat(result.get(0).getDomain()).isEqualTo("AUTH");
    }

    @Test
    void list_nullProjectId_returnsAll() {
        SecurityCoverage sc = SecurityCoverage.builder()
                .projectId(UUID.randomUUID()).domain("AUTH").build();
        when(repo.findAll()).thenReturn(List.of(sc));
        List<SecurityCoverage> result = service.list(null);
        assertThat(result).hasSize(1);
    }

    @Test
    void summary_withTestedDomains() {
        UUID pid = UUID.randomUUID();
        SecurityCoverage tested = SecurityCoverage.builder()
                .projectId(pid).domain("AUTH").status("TESTED").build();
        SecurityCoverage notTested = SecurityCoverage.builder()
                .projectId(pid).domain("CRYPTO").status("NOT_TESTED").build();
        when(repo.findByProjectId(pid)).thenReturn(List.of(tested, notTested));
        Map<String, Object> summary = service.summary(pid);
        assertThat(summary.get("totalDomains")).isEqualTo(2);
        assertThat(summary.get("tested")).isEqualTo(1L);
        assertThat(summary.get("gap")).isEqualTo(1L);
    }

    @Test
    void summary_emptyList() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of());
        Map<String, Object> summary = service.summary(pid);
        assertThat(((Number)summary.get("totalDomains")).intValue()).isEqualTo(0);
        assertThat(((Number)summary.get("tested")).longValue()).isEqualTo(0L);
    }

    @Test
    void summary_allTested() {
        UUID pid = UUID.randomUUID();
        SecurityCoverage sc1 = SecurityCoverage.builder()
                .projectId(pid).domain("AUTH").status("TESTED").build();
        SecurityCoverage sc2 = SecurityCoverage.builder()
                .projectId(pid).domain("CRYPTO").status("PARTIAL").build();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sc1, sc2));
        Map<String, Object> summary = service.summary(pid);
        assertThat(summary.get("tested")).isEqualTo(2L);
        assertThat(summary.get("gap")).isEqualTo(0L);
    }

    @Test
    void summary_groupsByStatus() {
        UUID pid = UUID.randomUUID();
        SecurityCoverage sc1 = SecurityCoverage.builder()
                .projectId(pid).domain("AUTH").status("TESTED").build();
        SecurityCoverage sc2 = SecurityCoverage.builder()
                .projectId(pid).domain("CRYPTO").status("TESTED").build();
        SecurityCoverage sc3 = SecurityCoverage.builder()
                .projectId(pid).domain("NETWORK").status("NOT_TESTED").build();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sc1, sc2, sc3));
        Map<String, Object> summary = service.summary(pid);
        @SuppressWarnings("unchecked")
        Map<String, Long> byStatus = (Map<String, Long>) summary.get("byStatus");
        assertThat(byStatus).containsEntry("TESTED", 2L);
        assertThat(byStatus).containsEntry("NOT_TESTED", 1L);
    }
}
