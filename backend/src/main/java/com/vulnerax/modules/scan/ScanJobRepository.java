package com.vulnerax.modules.scan;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface ScanJobRepository extends JpaRepository<ScanJob, UUID> {
    List<ScanJob> findByScanId(UUID scanId);
}
