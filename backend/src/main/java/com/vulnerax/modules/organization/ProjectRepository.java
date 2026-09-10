package com.vulnerax.modules.organization;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface ProjectRepository extends JpaRepository<Project, UUID> {
    List<Project> findByWorkspaceId(UUID wsId);
    List<Project> findByOrganizationId(UUID orgId);
}
