package com.vulnerax.modules.retest;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List; import java.util.UUID;
public interface RetestRepository extends JpaRepository<Retest, UUID> { List<Retest> findByProjectId(UUID projectId); List<Retest> findByFindingId(UUID findingId); }
