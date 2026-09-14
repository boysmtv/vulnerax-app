package com.vulnerax.modules.aillm;

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
class AiLlmServiceTest {

    @Mock AiRepository repo;
    @InjectMocks AiLlmService service;

    private AiAsset sampleAi() {
        return AiAsset.builder()
                .projectId(UUID.randomUUID())
                .name("gpt-deployment")
                .type("LLM")
                .model("gpt-4")
                .provider("OPENAI")
                .endpointsJson("[\"/v1/chat/completions\"]")
                .build();
    }

    @Test
    void create_saves_and_returns() {
        AiAsset ai = sampleAi();
        AiAsset saved = sampleAi();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(ai);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(ai);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sampleAi()));

        var result = service.list(pid);

        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_when_no_projectId() {
        when(repo.findAll()).thenReturn(List.of(sampleAi(), sampleAi()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        AiAsset ai = sampleAi();
        ai.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ai));

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
        AiAsset ai = sampleAi();
        ai.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(ai));

        service.delete(id);

        verify(repo).delete(ai);
    }

    @Test
    void delete_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.delete(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
