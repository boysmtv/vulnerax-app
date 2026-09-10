package com.vulnerax.modules.policy;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface PolicyRepository extends JpaRepository<SecurityPolicy, UUID> { List<SecurityPolicy> findByOrganizationId(UUID orgId); }
