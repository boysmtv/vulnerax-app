package com.vulnerax.modules.sbom;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface SbomRepository extends JpaRepository<Sbom, UUID> { List<Sbom> findByProjectId(UUID projectId); }
