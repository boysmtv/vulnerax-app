package com.vulnerax.modules.coverage;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface CoverageRepository extends JpaRepository<SecurityCoverage, UUID> {
    List<SecurityCoverage> findByProjectId(UUID projectId);
}
