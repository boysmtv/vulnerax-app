package com.vulnerax.modules.compliance;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.UUID;
public interface ComplianceFrameworkRepository extends JpaRepository<ComplianceFramework, UUID> {}
