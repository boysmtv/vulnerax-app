package com.vulnerax.modules.firmware;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface FirmwareRepository extends JpaRepository<FirmwareAsset, UUID> {
    List<FirmwareAsset> findByProjectId(UUID projectId);
}
