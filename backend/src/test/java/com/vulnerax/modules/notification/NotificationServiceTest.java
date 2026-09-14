package com.vulnerax.modules.notification;

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
class NotificationServiceTest {

    @Mock NotificationRepository repo;
    @InjectMocks NotificationService service;

    @Test
    void send_setsStatusAndSaves() {
        Notification n = Notification.builder()
                .projectId(UUID.randomUUID()).type("VULN_ALERT")
                .channel("EMAIL").recipient("admin@example.com").subject("Critical vuln").build();
        when(repo.save(any())).thenAnswer(i -> {
            Notification arg = i.getArgument(0);
            arg.setId(UUID.randomUUID());
            return arg;
        });
        var result = service.send(n);
        assertThat(result.getId()).isNotNull();
        assertThat(result.getStatus()).isEqualTo("SENT");
        verify(repo).save(n);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(
                Notification.builder().projectId(pid).type("VULN_ALERT").build()
        ));
        var result = service.list(pid);
        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_whenNoProjectId() {
        when(repo.findAll()).thenReturn(List.of(
                Notification.builder().type("VULN_ALERT").build(),
                Notification.builder().type("SCAN_COMPLETE").build()
        ));
        var result = service.list(null);
        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Notification n = Notification.builder().type("VULN_ALERT").build();
        n.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(n));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_throwsWhenNotFound() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(NoSuchElementException.class);
    }
}
