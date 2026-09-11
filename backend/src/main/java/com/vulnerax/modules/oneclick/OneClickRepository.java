package com.vulnerax.modules.oneclick;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface OneClickRepository extends JpaRepository<OneClickRun, UUID> {
    List<OneClickRun> findByProjectIdOrderByCreatedAtDesc(UUID projectId);
}
