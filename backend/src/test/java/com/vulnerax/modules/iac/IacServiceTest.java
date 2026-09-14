package com.vulnerax.modules.iac;

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
class IacServiceTest {

    @Mock IacScanRepository repo;
    @InjectMocks IacService service;

    private IacScan sampleScan() {
        return IacScan.builder()
                .projectId(UUID.randomUUID())
                .repository("https://github.com/acme/infra")
                .filePath("terraform/main.tf")
                .tool("CHECKOV")
                .passed(15)
                .failed(3)
                .build();
    }

    @Test
    void create_saves_and_returns() {
        IacScan scan = sampleScan();
        IacScan saved = sampleScan();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(scan);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(scan);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sampleScan()));

        var result = service.list(pid);

        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_when_no_projectId() {
        when(repo.findAll()).thenReturn(List.of(sampleScan(), sampleScan()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        IacScan scan = sampleScan();
        scan.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(scan));

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
        IacScan scan = sampleScan();
        scan.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(scan));

        service.delete(id);

        verify(repo).delete(scan);
    }

    @Test
    void delete_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.delete(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
