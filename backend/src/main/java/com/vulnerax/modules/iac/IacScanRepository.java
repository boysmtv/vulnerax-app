package com.vulnerax.modules.iac;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface IacScanRepository extends JpaRepository<IacScan, UUID> {
    List<IacScan> findByProjectId(UUID projectId);
}
