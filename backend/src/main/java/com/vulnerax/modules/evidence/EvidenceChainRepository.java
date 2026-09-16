package com.vulnerax.modules.evidence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface EvidenceChainRepository extends JpaRepository<EvidenceChain, UUID> {
    List<EvidenceChain> findByFindingIdOrderByCreatedAtDesc(UUID findingId);
    List<EvidenceChain> findByScanId(UUID scanId);
    List<EvidenceChain> findByFindingIdAndStatus(UUID findingId, String status);
    long countByFindingIdAndStatus(UUID findingId, String status);
}
