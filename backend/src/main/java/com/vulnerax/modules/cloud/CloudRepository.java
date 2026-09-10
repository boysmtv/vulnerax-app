package com.vulnerax.modules.cloud;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface CloudRepository extends JpaRepository<CloudResource, UUID> { List<CloudResource> findByProjectId(UUID projectId); }
