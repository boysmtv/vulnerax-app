package com.vulnerax.modules.retest;

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
class RetestServiceTest {

    @Mock RetestRepository repo;
    @InjectMocks RetestService service;

    @Test
    void request_setsStatusAndSaves() throws Exception {
        Retest r = Retest.builder().projectId(UUID.randomUUID()).findingId(UUID.randomUUID()).requestedBy("admin").build();
        when(repo.save(any())).thenAnswer(i -> {
            Retest arg = i.getArgument(0);
            if (arg.getId() == null) arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.request(r);
        assertThat(result.getId()).isNotNull();
        assertThat(result.getStatus()).isEqualTo("IN_PROGRESS");
        assertThat(result.getBeforeJson()).contains("SQL injection");
        verify(repo, atLeastOnce()).save(any());
        Thread.sleep(1500);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                Retest.builder().projectId(pid).status("COMPLETED").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                Retest.builder().status("COMPLETED").build(),
                Retest.builder().status("PENDING").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Retest r = Retest.builder().status("PASS").build();
        r.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(r));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }
}
