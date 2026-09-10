package com.vulnerax.modules.finding;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface FindingInstanceRepository extends JpaRepository<FindingInstance, UUID> {
    List<FindingInstance> findByFindingId(UUID findingId);
}
