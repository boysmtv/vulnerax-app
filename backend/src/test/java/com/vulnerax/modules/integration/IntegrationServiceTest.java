package com.vulnerax.modules.integration;

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
class IntegrationServiceTest {

    @Mock IntegrationRepository repo;
    @InjectMocks IntegrationService service;

    private Integration sampleIntegration() {
        return Integration.builder()
                .organizationId(UUID.randomUUID())
                .type("SCANNER")
                .provider("NESSUS")
                .name("Nessus Scanner")
                .configurationJson("{\"host\":\"scanner.internal\",\"port\":8834}")
                .build();
    }

    @Test
    void create_saves_and_returns() {
        Integration integ = sampleIntegration();
        Integration saved = sampleIntegration();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(integ);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(integ);
    }

    @Test
    void list_byOrgId() {
        UUID orgId = UUID.randomUUID();
        when(repo.findByOrganizationId(orgId)).thenReturn(List.of(sampleIntegration()));

        var result = service.list(orgId);

        assertThat(result).hasSize(1);
        verify(repo).findByOrganizationId(orgId);
    }

    @Test
    void list_all_when_no_orgId() {
        when(repo.findAll()).thenReturn(List.of(sampleIntegration(), sampleIntegration()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Integration integ = sampleIntegration();
        integ.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(integ));

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
    void testConnection_success() {
        UUID id = UUID.randomUUID();
        Integration integ = sampleIntegration();
        integ.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(integ));

        var result = service.testConnection(id);

        assertThat(result).containsKey("id");
        assertThat(result).containsKey("provider");
        assertThat(result.get("status")).isEqualTo("CONNECTED");
        assertThat(result).containsKey("latencyMs");
    }

    @Test
    void testConnection_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.testConnection(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
