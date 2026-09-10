package com.vulnerax.modules.asset;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface AssetRepository extends JpaRepository<Asset, UUID> {
    Page<Asset> findByProjectId(UUID projectId, Pageable p);
    Page<Asset> findByOrganizationId(UUID orgId, Pageable p);
    List<Asset> findByProjectId(UUID projectId);
    long countByProjectId(UUID projectId);
    long countByInternetExposedTrue();
    @Query("select a.type, count(a) from Asset a group by a.type")
    List<Object[]> countByType();
    @Query("select a.criticality, count(a) from Asset a group by a.criticality")
    List<Object[]> countByCriticality();
}
