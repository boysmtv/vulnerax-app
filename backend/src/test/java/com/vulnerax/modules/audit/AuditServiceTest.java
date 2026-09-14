package com.vulnerax.modules.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock AuditRepository repo;
    @InjectMocks AuditService service;

    @Test
    void log_savesEventWithSystemActor() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        service.log("FINDING_CREATED", "Finding", "abc-123", "Critical SQL injection found");
        verify(repo).save(argThat(ev ->
                ev.getAction().equals("FINDING_CREATED") &&
                ev.getEntityType().equals("Finding") &&
                ev.getEntityId().equals("abc-123") &&
                ev.getActor() != null &&
                ev.getDetails().equals("Critical SQL injection found")
        ));
    }

    @Test
    void log_handlesNullAuthentication() {
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        service.log("LOGIN", "User", "user-1", "Successful login");
        verify(repo).save(argThat(ev -> ev.getActor().equals("system")));
    }

    @Test
    void list_returnsPage() {
        AuditEvent ev = AuditEvent.builder().action("SCAN_CREATED").actor("admin").build();
        when(repo.findAll(any(org.springframework.data.domain.Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(ev), PageRequest.of(0, 10), 1));
        var page = service.list(PageRequest.of(0, 10));
        assertThat(page.getContent()).hasSize(1);
        assertThat(page.getContent().get(0).getAction()).isEqualTo("SCAN_CREATED");
        verify(repo).findAll(any(org.springframework.data.domain.Pageable.class));
    }
}
