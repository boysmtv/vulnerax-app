package com.vulnerax.modules.asset;

import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.organization.ProjectRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AssetServiceTest {

    @Mock AssetRepository repo;
    @Mock AuditService auditService;
    @Mock ProjectRepository projectRepo;
    @InjectMocks AssetService service;

    // list
    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(eq(pid), any())).thenReturn(new PageImpl<>(List.of()));
        var page = service.list(pid, null, null, null, PageRequest.of(0,10));
        assertThat(page).isNotNull();
        verify(repo).findByProjectId(eq(pid), any());
    }

    @Test
    void list_all_when_no_filter() {
        when(repo.findAll(any(org.springframework.data.domain.Pageable.class))).thenReturn(new PageImpl<>(List.of()));
        service.list(null,null,null,null, PageRequest.of(0,10));
        verify(repo).findAll(any(org.springframework.data.domain.Pageable.class));
    }

    // create
    @Test
    void create_saves_and_audits() {
        Asset a = Asset.builder().name("api.example.com").type("DOMAIN").build();
        Asset saved = Asset.builder().name("api.example.com").type("DOMAIN").build();
        saved.setId(UUID.randomUUID());
        when(repo.save(any())).thenReturn(saved);
        var res = service.create(a);
        assertThat(res.getId()).isNotNull();
        verify(auditService).log(eq("ASSET_CREATED"), any(), any(), any());
    }

    // get
    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Asset a = new Asset(); a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    // update
    @Test
    void update_patches_fields() {
        UUID id = UUID.randomUUID();
        Asset cur = Asset.builder().name("old").criticality("MEDIUM").build();
        cur.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(cur));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        Asset patch = new Asset(); patch.setName("new"); patch.setCriticality("CRITICAL");
        var updated = service.update(id, patch);
        assertThat(updated.getName()).isEqualTo("new");
        assertThat(updated.getCriticality()).isEqualTo("CRITICAL");
    }

    // delete
    @Test
    void delete_delegates() {
        UUID id = UUID.randomUUID();
        Asset a = new Asset(); a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        service.delete(id);
        verify(repo).delete(a);
    }

    // stats
    @Test
    void stats_returns_expected_keys() {
        when(repo.count()).thenReturn(10L);
        when(repo.countByInternetExposedTrue()).thenReturn(3L);
        List<Object[]> byType = new java.util.ArrayList<>(); byType.add(new Object[]{"DOMAIN", 5L});
        List<Object[]> byCrit = new java.util.ArrayList<>(); byCrit.add(new Object[]{"HIGH", 2L});
        when(repo.countByType()).thenReturn(byType);
        when(repo.countByCriticality()).thenReturn(byCrit);
        when(repo.findAll()).thenReturn(List.of());
        var m = service.stats(null);
        assertThat(m).containsKeys("total","internetExposed","byType","byCriticality","discoveryDelta");
        assertThat(m.get("total")).isEqualTo(10L);
    }

    // discoverMock — mock removed, must require REAL
    @Test
    void discoverMock_rejects_non_real_and_empty_for_real() {
        UUID pid = UUID.randomUUID();
        // non-REAL should throw BusinessException (mock disabled)
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.discoverMock(pid, "MANUAL"))
                .isInstanceOf(com.vulnerax.common.exception.BusinessException.class);
        // REAL returns empty (no mock) until connectors configured
        var list = service.discoverMock(pid, "REAL");
        assertThat(list).isEmpty();
    }
}
