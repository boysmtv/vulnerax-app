package com.vulnerax.modules.aillm;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface AiRepository extends JpaRepository<AiAsset, UUID> {
    List<AiAsset> findByProjectId(UUID projectId);
}
