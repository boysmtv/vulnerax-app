package com.vulnerax.modules.asset;

import com.vulnerax.common.exception.BusinessException;
import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.organization.ProjectRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AssetServiceTest {

    @Mock AssetRepository repo;
    @Mock AuditService auditService;
    @Mock ProjectRepository projectRepo;
    @InjectMocks AssetService service;

    @Test
    void list_byProjectId() {
        UUID pid = UUID.randomUUID();
        when(repo.findByProjectId(eq(pid), any())).thenReturn(new PageImpl<>(List.of()));
        var page = service.list(pid, null, null, null, PageRequest.of(0, 10));
        assertThat(page).isNotNull();
        verify(repo).findByProjectId(eq(pid), any());
    }

    @Test
    void list_byOrgId() {
        UUID orgId = UUID.randomUUID();
        when(repo.findByOrganizationId(eq(orgId), any())).thenReturn(new PageImpl<>(List.of()));
        service.list(null, orgId, null, null, PageRequest.of(0, 10));
        verify(repo).findByOrganizationId(eq(orgId), any());
    }

    @Test
    void list_all_when_no_filter() {
        PageImpl<Asset> emptyPage = new PageImpl<>(List.of());
        doReturn(emptyPage).when(repo).findAll(any(org.springframework.data.domain.Pageable.class));
        service.list(null, null, null, null, PageRequest.of(0, 10));
        verify(repo).findAll(any(org.springframework.data.domain.Pageable.class));
    }

    @Test
    void get_success() {
        UUID id = UUID.randomUUID();
        Asset a = new Asset();
        a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        assertThat(service.get(id).getId()).isEqualTo(id);
    }

    @Test
    void get_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(id)).isInstanceOf(ResourceNotFoundException.class);
    }

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

    @Test
    void createAsset_setsFieldsCorrectly() {
        when(repo.save(any())).thenAnswer(i -> {
            Asset a = i.getArgument(0);
            a.setId(UUID.randomUUID());
            return a;
        });
        Asset result = service.createAsset("example.com", "DOMAIN", "admin");
        assertThat(result.getName()).isEqualTo("example.com");
        assertThat(result.getType()).isEqualTo("DOMAIN");
        assertThat(result.getOwner()).isEqualTo("admin");
        assertThat(result.getCriticality()).isEqualTo("MEDIUM");
        assertThat(result.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    void createAsset_httpPrefix_setsInternetExposed() {
        when(repo.save(any())).thenAnswer(i -> {
            Asset a = i.getArgument(0);
            a.setId(UUID.randomUUID());
            return a;
        });
        Asset result = service.createAsset("https://example.com", "URL", "admin");
        assertThat(result.getInternetExposed()).isTrue();
    }

    @Test
    void createAsset_nonHttp_setsNotExposed() {
        when(repo.save(any())).thenAnswer(i -> {
            Asset a = i.getArgument(0);
            a.setId(UUID.randomUUID());
            return a;
        });
        Asset result = service.createAsset("db.internal", "DB", "admin");
        assertThat(result.getInternetExposed()).isFalse();
    }

    @Test
    void update_patches_fields() {
        UUID id = UUID.randomUUID();
        Asset cur = Asset.builder().name("old").criticality("MEDIUM").build();
        cur.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(cur));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        Asset patch = new Asset();
        patch.setName("new");
        patch.setCriticality("CRITICAL");
        patch.setOwner("new-owner");
        patch.setTeam("security");
        patch.setTags("critical,web");
        patch.setTechnology("Java");
        var updated = service.update(id, patch);
        assertThat(updated.getName()).isEqualTo("new");
        assertThat(updated.getCriticality()).isEqualTo("CRITICAL");
        assertThat(updated.getOwner()).isEqualTo("new-owner");
        assertThat(updated.getTeam()).isEqualTo("security");
        assertThat(updated.getTags()).isEqualTo("critical,web");
        assertThat(updated.getTechnology()).isEqualTo("Java");
    }

    @Test
    void update_patchesInternetExposed() {
        UUID id = UUID.randomUUID();
        Asset cur = Asset.builder().name("api").internetExposed(false).build();
        cur.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(cur));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        Asset patch = new Asset();
        patch.setInternetExposed(true);
        service.update(id, patch);
        assertThat(cur.getInternetExposed()).isTrue();
    }

    @Test
    void update_patchesStatus() {
        UUID id = UUID.randomUUID();
        Asset cur = Asset.builder().name("api").status("ACTIVE").build();
        cur.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(cur));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        Asset patch = new Asset();
        patch.setStatus("DEPRECATED");
        service.update(id, patch);
        assertThat(cur.getStatus()).isEqualTo("DEPRECATED");
    }

    @Test
    void update_nullFields_notPatched() {
        UUID id = UUID.randomUUID();
        Asset cur = Asset.builder().name("original").criticality("LOW").build();
        cur.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(cur));
        when(repo.save(any())).thenAnswer(i -> i.getArgument(0));
        Asset patch = new Asset();
        patch.setCriticality(null);
        service.update(id, patch);
        assertThat(cur.getName()).isEqualTo("original");
        assertThat(cur.getCriticality()).isEqualTo("LOW");
    }

    @Test
    void delete_delegates() {
        UUID id = UUID.randomUUID();
        Asset a = new Asset();
        a.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(a));
        service.delete(id);
        verify(repo).delete(a);
    }

    @Test
    void delete_notFound_throws() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.delete(id)).isInstanceOf(ResourceNotFoundException.class);
    }

    @Test
    void stats_returnsExpectedKeys() {
        when(repo.count()).thenReturn(10L);
        when(repo.countByInternetExposedTrue()).thenReturn(3L);
        List<Object[]> byType = new ArrayList<>();
        byType.add(new Object[]{"DOMAIN", 5L});
        List<Object[]> byCrit = new ArrayList<>();
        byCrit.add(new Object[]{"HIGH", 2L});
        when(repo.countByType()).thenReturn(byType);
        when(repo.countByCriticality()).thenReturn(byCrit);
        doReturn(List.of()).when(repo).findAll();
        var m = service.stats(null);
        assertThat(m).containsKey("total");
        assertThat(m).containsKey("internetExposed");
        assertThat(m).containsKey("byType");
        assertThat(m).containsKey("byCriticality");
        assertThat(m).containsKey("discoveryDelta");
        assertThat(m.get("total")).isEqualTo(10L);
        assertThat(m.get("internetExposed")).isEqualTo(3L);
    }

    @Test
    void stats_withProjectId_usesCountByProject() {
        UUID pid = UUID.randomUUID();
        when(repo.countByProjectId(pid)).thenReturn(5L);
        when(repo.countByInternetExposedTrue()).thenReturn(1L);
        when(repo.countByType()).thenReturn(List.of());
        when(repo.countByCriticality()).thenReturn(List.of());
        doReturn(List.of()).when(repo).findByProjectId(pid);
        var m = service.stats(pid);
        assertThat(m.get("total")).isEqualTo(5L);
    }

    @Test
    void stats_discoveryDelta_computesCorrectly() {
        when(repo.count()).thenReturn(10L);
        when(repo.countByInternetExposedTrue()).thenReturn(0L);
        when(repo.countByType()).thenReturn(List.of());
        when(repo.countByCriticality()).thenReturn(List.of());
        Asset recent = new Asset();
        recent.setCreatedAt(Instant.now());
        Asset old = new Asset();
        old.setCreatedAt(Instant.now().minusSeconds(200000));
        doReturn(List.of(recent, old)).when(repo).findAll();
        var m = service.stats(null);
        var delta = (Map<String, Object>) m.get("discoveryDelta");
        assertThat(delta).containsKeys("newLast24h", "previousTotal");
        assertThat(delta.get("newLast24h")).isEqualTo(1L);
        assertThat(delta.get("previousTotal")).isEqualTo(1L);
    }

    @Test
    void discoverMock_rejects_non_real() {
        assertThatThrownBy(() -> service.discoverMock(UUID.randomUUID(), "MANUAL"))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    void discoverMock_rejects_null_source() {
        assertThatThrownBy(() -> service.discoverMock(UUID.randomUUID(), null))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    void discoverMock_real_returnsEmpty() {
        var list = service.discoverMock(UUID.randomUUID(), "REAL");
        assertThat(list).isEmpty();
    }

    @Test
    void discoverMock_caseInsensitive_real() {
        var list = service.discoverMock(UUID.randomUUID(), "real");
        assertThat(list).isEmpty();
    }

    @Test
    void discoverMock_rejects_github() {
        assertThatThrownBy(() -> service.discoverMock(UUID.randomUUID(), "GITHUB"))
                .isInstanceOf(BusinessException.class);
    }

    @Test
    void stats_allAssetsOld_noNewLast24h() {
        when(repo.count()).thenReturn(5L);
        when(repo.countByInternetExposedTrue()).thenReturn(0L);
        when(repo.countByType()).thenReturn(List.of());
        when(repo.countByCriticality()).thenReturn(List.of());
        Asset old = new Asset();
        old.setCreatedAt(Instant.now().minusSeconds(200000));
        doReturn(List.of(old, old, old, old, old)).when(repo).findAll();
        var m = service.stats(null);
        var delta = (Map<String, Object>) m.get("discoveryDelta");
        assertThat(delta.get("newLast24h")).isEqualTo(0L);
        assertThat(delta.get("previousTotal")).isEqualTo(5L);
    }

    @Test
    void stats_allAssetsNew() {
        when(repo.count()).thenReturn(3L);
        when(repo.countByInternetExposedTrue()).thenReturn(0L);
        when(repo.countByType()).thenReturn(List.of());
        when(repo.countByCriticality()).thenReturn(List.of());
        Asset recent1 = new Asset();
        recent1.setCreatedAt(Instant.now());
        Asset recent2 = new Asset();
        recent2.setCreatedAt(Instant.now());
        Asset recent3 = new Asset();
        recent3.setCreatedAt(Instant.now());
        doReturn(List.of(recent1, recent2, recent3)).when(repo).findAll();
        var m = service.stats(null);
        var delta = (Map<String, Object>) m.get("discoveryDelta");
        assertThat(delta.get("newLast24h")).isEqualTo(3L);
        assertThat(delta.get("previousTotal")).isEqualTo(0L);
    }

    @Test
    void createAsset_setsIdentifierToName() {
        when(repo.save(any())).thenAnswer(i -> {
            Asset a = i.getArgument(0);
            a.setId(UUID.randomUUID());
            return a;
        });
        Asset result = service.createAsset("myapp.example.com", "WEBAPP", "team");
        assertThat(result.getIdentifier()).isEqualTo("myapp.example.com");
    }
}
