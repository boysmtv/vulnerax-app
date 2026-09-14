package com.vulnerax.modules.cicd;

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
class CicdServiceTest {

    @Mock CicdRepository repo;
    @InjectMocks CicdService service;

    private CicdPipeline samplePipeline() {
        return CicdPipeline.builder()
                .projectId(UUID.randomUUID())
                .platform("GITHUB_ACTIONS")
                .repository("acme/backend")
                .pipelineName("CI Build")
                .configurationJson("{\"triggers\":[\"push\",\"pull_request\"]}")
                .build();
    }

    @Test
    void create_saves_and_returns() {
        CicdPipeline pipe = samplePipeline();
        CicdPipeline saved = samplePipeline();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(pipe);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(pipe);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(samplePipeline()));

        var result = service.list(pid);

        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_when_no_projectId() {
        when(repo.findAll()).thenReturn(List.of(samplePipeline(), samplePipeline()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        CicdPipeline pipe = samplePipeline();
        pipe.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(pipe));

        var result = service.get(id);

        assertThat(result.getId()).isEqualTo(id);
    }

    @Test
    void get_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.get(id))
                .isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void delete_delegates() {
        UUID id = UUID.randomUUID();
        CicdPipeline pipe = samplePipeline();
        pipe.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(pipe));

        service.delete(id);

        verify(repo).delete(pipe);
    }

    @Test
    void delete_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.delete(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
