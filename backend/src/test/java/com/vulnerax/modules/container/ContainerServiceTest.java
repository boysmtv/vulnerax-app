package com.vulnerax.modules.container;

import com.vulnerax.common.exception.BusinessException;
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
class ContainerServiceTest {

    @Mock ContainerRepository repo;
    @InjectMocks ContainerService service;

    @Test
    void create_saves() {
        ContainerImage c = ContainerImage.builder()
                .projectId(UUID.randomUUID()).imageName("nginx").tag("1.25").build();
        when(repo.save(any())).thenAnswer(i -> {
            ContainerImage arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.create(c);
        assertThat(result.getId()).isNotNull();
        verify(repo).save(c);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                ContainerImage.builder().projectId(pid).imageName("nginx").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                ContainerImage.builder().imageName("nginx").build(),
                ContainerImage.builder().imageName("redis").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        ContainerImage c = ContainerImage.builder().imageName("nginx").build();
        c.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(c));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }

    @Test
    void scanMock_throwsBusinessException() {
        assertThatThrownBy(() -> service.scanMock(UUID.randomUUID()))
                .isInstanceOf(BusinessException.class)
                .hasMessageContaining("Real container scan required");
    }
}
