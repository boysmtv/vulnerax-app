package com.vulnerax.modules.scan;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {
    Page<Scan> findByProjectId(UUID projectId, Pageable p);
    Page<Scan> findByStatus(String status, Pageable p);
    Page<Scan> findByOrganizationId(UUID orgId, Pageable p);

    @Query("select count(s) > 0 from Scan s where s.scannerType = :scannerType")
    boolean existsByScannerType(@Param("scannerType") String scannerType);
}
