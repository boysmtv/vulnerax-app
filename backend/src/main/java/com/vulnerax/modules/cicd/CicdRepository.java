package com.vulnerax.modules.cicd;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface CicdRepository extends JpaRepository<CicdPipeline, UUID> {
    List<CicdPipeline> findByProjectId(UUID projectId);
}
