package com.vulnerax.modules.compliance;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface ComplianceAssessmentRepository extends JpaRepository<ComplianceAssessment, UUID> { List<ComplianceAssessment> findByProjectId(UUID projectId); }
