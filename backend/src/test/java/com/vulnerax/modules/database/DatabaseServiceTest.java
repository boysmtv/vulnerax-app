package com.vulnerax.modules.database;

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
class DatabaseServiceTest {

    @Mock DatabaseRepository repo;
    @InjectMocks DatabaseService service;

    private DatabaseAsset sampleAsset() {
        return DatabaseAsset.builder()
                .projectId(UUID.randomUUID())
                .name("prod-db")
                .engine("PostgreSQL")
                .version("15.3")
                .host("db.internal")
                .port(5432)
                .build();
    }

    @Test
    void create_saves_and_returns() {
        DatabaseAsset asset = sampleAsset();
        DatabaseAsset saved = sampleAsset();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);

        var result = service.create(asset);

        assertThat(result.getId()).isNotNull();
        verify(repo).save(asset);
    }

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(pid)).thenReturn(List.of(sampleAsset()));

        var result = service.list(pid);

        assertThat(result).hasSize(1);
        verify(repo).findByProjectId(pid);
    }

    @Test
    void list_all_when_no_projectId() {
        when(repo.findAll()).thenReturn(List.of(sampleAsset(), sampleAsset()));

        var result = service.list(null);

        assertThat(result).hasSize(2);
        verify(repo).findAll();
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        DatabaseAsset asset = sampleAsset();
        asset.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(asset));

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
        DatabaseAsset asset = sampleAsset();
        asset.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(asset));

        service.delete(id);

        verify(repo).delete(asset);
    }

    @Test
    void delete_throws_when_not_found() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.delete(id))
                .isInstanceOf(NoSuchElementException.class);
    }
}
