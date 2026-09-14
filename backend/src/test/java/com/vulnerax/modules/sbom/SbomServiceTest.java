package com.vulnerax.modules.sbom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SbomServiceTest {

    @Mock SbomRepository repo;
    @InjectMocks SbomService service;

    @Test
    void create_setsVersionAndDefaults() {
        Sbom s = Sbom.builder().projectId(UUID.randomUUID()).format("CYCLONEDX").build();
        when(repo.save(any())).thenAnswer(i -> {
            Sbom arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.create(s);
        assertThat(result.getId()).isNotNull();
        assertThat(result.getVersion()).startsWith("1.0-");
        assertThat(result.getContentJson()).contains("CycloneDX");
        assertThat(result.getComponentCount()).isBetween(10, 60);
        assertThat(result.getVulnerableCount()).isBetween(0, 5);
        verify(repo).save(s);
    }

    @Test
    void create_preservesExistingContentJson() {
        Sbom s = Sbom.builder().projectId(UUID.randomUUID()).format("SPDX").contentJson("{\"custom\":true}").build();
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        service.create(s);
        assertThat(s.getContentJson()).isEqualTo("{\"custom\":true}");
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                Sbom.builder().projectId(pid).format("CYCLONEDX").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                Sbom.builder().format("CYCLONEDX").build(),
                Sbom.builder().format("SPDX").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Sbom s = Sbom.builder().format("CYCLONEDX").build();
        s.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(s));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void diff_returnsDelta() {
        UUID aId = UUID.randomUUID(), bId = UUID.randomUUID();
        Sbom sa = Sbom.builder().componentCount(10).vulnerableCount(1).build();
        sa.setId(aId);
        Sbom sb = Sbom.builder().componentCount(15).vulnerableCount(3).build();
        sb.setId(bId);
        when(repo.findById(aId)).thenReturn(Optional.of(sa));
        when(repo.findById(bId)).thenReturn(Optional.of(sb));
        var result = service.diff(aId, bId);
        assertThat(result.get("a")).isEqualTo(10);
        assertThat(result.get("b")).isEqualTo(15);
        assertThat(result.get("delta")).isEqualTo(5);
        assertThat(result.get("newVulns")).isEqualTo(3);
    }

    @Test
    void diff_throwsWhenSbomNotFound() {
        UUID aId = UUID.randomUUID(), bId = UUID.randomUUID();
        when(repo.findById(aId)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.diff(aId, bId)).isInstanceOf(NoSuchElementException.class);
    }
}
