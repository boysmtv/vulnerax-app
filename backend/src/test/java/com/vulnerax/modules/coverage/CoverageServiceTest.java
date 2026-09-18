package com.vulnerax.modules.coverage;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CoverageServiceTest {

    @Mock CoverageRepository repo;
    @InjectMocks CoverageService service;

    @Test
    void upsert_savesCoverage() {
        SecurityCoverage c = SecurityCoverage.builder()
                .projectId(UUID.randomUUID()).domain("AUTH").status("TESTED").coveragePercent(80).build();
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        SecurityCoverage result = service.upsert(c);
        assertThat(result.getDomain()).isEqualTo("AUTH");
        verify(repo).save(c);
    }

    @Test
    void list_withProjectId_filtersCorrectly() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").build()));
        List<SecurityCoverage> result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_nullProjectId_returnsAll() {
        when(repo.findAll()).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").build(),
                SecurityCoverage.builder().domain("CRYPTO").build()));
        List<SecurityCoverage> result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void list_empty_returnsEmpty() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of());
        assertThat(service.list(pid)).isEmpty();
    }

    @Test
    void summary_emptyList() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of());
        Map<String, Object> result = service.summary(pid);
        assertThat(result.get("totalDomains")).isEqualTo(0);
        assertThat(result.get("tested")).isEqualTo(0L);
        assertThat(result.get("gap")).isEqualTo(0L);
    }

    @Test
    void summary_allTested() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").status("TESTED").build(),
                SecurityCoverage.builder().domain("CRYPTO").status("TESTED").build()));
        Map<String, Object> result = service.summary(pid);
        assertThat(result.get("totalDomains")).isEqualTo(2);
        assertThat(result.get("tested")).isEqualTo(2L);
        assertThat(result.get("gap")).isEqualTo(0L);
    }

    @Test
    void summary_mixedStatuses() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").status("TESTED").build(),
                SecurityCoverage.builder().domain("CRYPTO").status("NOT_TESTED").build(),
                SecurityCoverage.builder().domain("NET").status("PARTIAL").build()));
        Map<String, Object> result = service.summary(pid);
        assertThat(result.get("totalDomains")).isEqualTo(3);
        assertThat(result.get("tested")).isEqualTo(2L);
        assertThat(result.get("gap")).isEqualTo(1L);
        assertThat(result.get("byStatus")).isNotNull();
    }

    @Test
    void summary_nullProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").status("TESTED").build()));
        Map<String, Object> result = service.summary(null);
        assertThat(result.get("totalDomains")).isEqualTo(1);
        assertThat(result.get("tested")).isEqualTo(1L);
    }

    @Test
    void summary_allNotTested() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                SecurityCoverage.builder().domain("AUTH").status("NOT_TESTED").build(),
                SecurityCoverage.builder().domain("CRYPTO").status("NOT_TESTED").build()));
        Map<String, Object> result = service.summary(pid);
        assertThat(result.get("tested")).isEqualTo(0L);
        assertThat(result.get("gap")).isEqualTo(2L);
    }
}
