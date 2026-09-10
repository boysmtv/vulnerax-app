package com.vulnerax.modules.supplychain;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface ProvenanceRepository extends JpaRepository<ArtifactProvenance, UUID> {
    List<ArtifactProvenance> findByProjectId(UUID projectId);
}
