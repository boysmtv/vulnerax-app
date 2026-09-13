package com.vulnerax.modules.asset;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface AssetRepository extends JpaRepository<Asset, UUID> {
    Page<Asset> findByProjectId(UUID projectId, Pageable p);
    Page<Asset> findByOrganizationId(UUID orgId, Pageable p);
    List<Asset> findByProjectId(UUID projectId);
    long countByProjectId(UUID projectId);
    long countByInternetExposedTrue();

    @Query("select count(a) > 0 from Asset a where a.internetExposed = :exposed")
    boolean existsByInternetExposed(@Param("exposed") boolean exposed);

    @Query("select count(a) from Asset a where a.type = :type")
    long countByType(@Param("type") String type);

    @Query("select a.type, count(a) from Asset a group by a.type")
    List<Object[]> countByType();

    @Query("select a.criticality, count(a) from Asset a group by a.criticality")
    List<Object[]> countByCriticality();

    @Query(value = "select * from assets a where a.criticality = 'CRITICAL' order by a.created_at desc limit :limit", nativeQuery = true)
    List<Asset> findTopRiskAssets(@Param("limit") int limit);

    long countByOrganizationId(UUID orgId);

    @Query("select count(a) from Asset a where a.organizationId = :orgId")
    long countByOrgId(@Param("orgId") UUID orgId);
}
