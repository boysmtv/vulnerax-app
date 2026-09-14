package com.vulnerax.modules.supplychain;

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
class ProvenanceServiceTest {

    @Mock ProvenanceRepository repo;
    @InjectMocks ProvenanceService service;

    @Test
    void create_saves() {
        ArtifactProvenance a = ArtifactProvenance.builder()
                .projectId(UUID.randomUUID()).artifactName("lib-core").version("2.1.0").build();
        when(repo.save(any())).thenAnswer(i -> {
            ArtifactProvenance arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.create(a);
        assertThat(result.getId()).isNotNull();
        verify(repo).save(a);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                ArtifactProvenance.builder().projectId(pid).artifactName("lib-a").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                ArtifactProvenance.builder().artifactName("lib-a").build(),
                ArtifactProvenance.builder().artifactName("lib-b").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        ArtifactProvenance a = ArtifactProvenance.builder().artifactName("lib-core").build();
        a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void verify_setsVerifiedAndReturnsDetails() {
        UUID id = UUID.randomUUID();
        ArtifactProvenance a = ArtifactProvenance.builder().artifactName("lib-core").verified(false).build();
        a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        var result = service.verify(id);
        assertThat(result.get("verified")).isEqualTo(true);
        assertThat(result.get("signature")).isEqualTo("cosign valid");
        assertThat(result.get("provenance")).isEqualTo("SLSA L3");
        assertThat(a.getVerified()).isTrue();
        verify(repo).save(a);
    }
}
