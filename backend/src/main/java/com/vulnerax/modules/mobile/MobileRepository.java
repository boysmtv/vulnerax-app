package com.vulnerax.modules.mobile;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface MobileRepository extends JpaRepository<MobileAnalysis, UUID> { List<MobileAnalysis> findByProjectId(UUID projectId); }
