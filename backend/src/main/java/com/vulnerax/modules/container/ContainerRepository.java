package com.vulnerax.modules.container;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface ContainerRepository extends JpaRepository<ContainerImage, UUID> { List<ContainerImage> findByProjectId(UUID projectId); }
