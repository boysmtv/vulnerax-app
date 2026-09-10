package com.vulnerax.modules.threatmodel;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface ThreatModelRepository extends JpaRepository<ThreatModel, UUID> {
    List<ThreatModel> findByProjectId(UUID projectId);
}
