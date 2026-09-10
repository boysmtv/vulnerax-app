package com.vulnerax.modules.integration;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface IntegrationRepository extends JpaRepository<Integration, UUID> {
    List<Integration> findByOrganizationId(UUID organizationId);
}
