package com.vulnerax.modules.finding;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface EvidenceRepository extends JpaRepository<Evidence, UUID> {
    List<Evidence> findByFindingId(UUID findingId);

    @Query("select count(e) from Evidence e where e.validated = true")
    long countValidated();

    @Query("select count(e) from Evidence e where e.findingId = :findingId and e.validated = true")
    long countValidatedByFinding(@Param("findingId") UUID findingId);
}
