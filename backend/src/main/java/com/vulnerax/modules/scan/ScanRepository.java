package com.vulnerax.modules.scan;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;

public interface ScanRepository extends JpaRepository<Scan, UUID> {
    Page<Scan> findByProjectId(UUID projectId, Pageable p);
    Page<Scan> findByStatus(String status, Pageable p);
}
