package com.vulnerax.modules.browser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface BrowserRepository extends JpaRepository<BrowserExtension, UUID> {
    List<BrowserExtension> findByProjectId(UUID projectId);
}
