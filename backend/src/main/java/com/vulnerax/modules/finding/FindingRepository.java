package com.vulnerax.modules.finding;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;
import java.util.UUID;

public interface FindingRepository extends JpaRepository<Finding, UUID> {
    Page<Finding> findByProjectId(UUID projectId, Pageable p);
    Page<Finding> findByAssetId(UUID assetId, Pageable p);
    List<Finding> findByProjectId(UUID projectId);
    List<Finding> findByFindingId(String findingId);
    long countByProjectIdAndSeverity(UUID projectId, String severity);
    long countByStatus(String status);
    @Query("select f.severity, count(f) from Finding f group by f.severity")
    List<Object[]> countBySeverity();
    @Query("select f.status, count(f) from Finding f group by f.status")
    List<Object[]> countByStatusAgg();
    @Query("select f.riskLevel, count(f) from Finding f group by f.riskLevel")
    List<Object[]> countByRiskLevel();
    List<Finding> findByFingerprint(String fingerprint);
}
