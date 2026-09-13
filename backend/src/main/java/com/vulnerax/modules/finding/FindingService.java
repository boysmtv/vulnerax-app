package com.vulnerax.modules.finding;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.risk.RiskEngine;
import com.vulnerax.modules.scan.Scan;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
@RequiredArgsConstructor
public class FindingService {
    private final FindingRepository findingRepo;
    private final EvidenceRepository evidenceRepo;
    private final FindingInstanceRepository instanceRepo;
    private final RiskEngine riskEngine;
    private final AuditService auditService;
    private final FindingCorrelationEngine correlationEngine;

    private final AtomicLong counter = new AtomicLong(1000);

    public Page<Finding> list(UUID projectId, UUID assetId, String severity, String status, String riskLevel, String search, Pageable p) {
        UUID orgId = TenantContext.getOrganizationId();
        if (projectId != null) return findingRepo.findByProjectId(projectId, p);
        if (assetId != null) return findingRepo.findByAssetId(assetId, p);
        if (orgId != null) return findingRepo.findByOrganizationId(orgId, p);
        return findingRepo.findAll(p);
    }

    public Finding get(UUID id) { return findingRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Finding not found")); }

    @Transactional
    public Finding create(Finding f) {
        UUID orgId = TenantContext.getOrganizationId();
        if (orgId != null) f.setOrganizationId(orgId);

        if (f.getFindingId() == null) f.setFindingId("FND-" + counter.incrementAndGet());
        riskEngine.enrich(f);

        // Dedup check using fingerprint
        var existing = findingRepo.findByFingerprint(f.getFingerprint());
        if (!existing.isEmpty()) {
            Finding parent = existing.get(0);
            FindingInstance inst = FindingInstance.builder()
                    .findingId(parent.getId())
                    .assetName(f.getAssetName())
                    .location(f.getFilePath() + ":" + f.getLineNumber())
                    .scanner(f.getSource())
                    .fingerprint(f.getFingerprint())
                    .build();
            instanceRepo.save(inst);
            parent.setDuplicate(false);
            log.info("Dedup: new instance for {}", parent.getFindingId());
            return parent;
        }

        // Correlation check
        List<Finding> recentFindings = findingRepo.findByAssetId(f.getAssetId(), PageRequest.of(0, 100)).getContent();
        var correlation = correlationEngine.correlate(f, recentFindings);
        if (correlation.isDuplicate()) {
            log.info("Correlation detected duplicate: {} reason={}", f.getTitle(), correlation.reason());
        }
        f.setCorrelationId(correlation.reason().equals("NO_MATCH") ? null : correlation.matches().stream().findFirst().map(Finding::getId).orElse(null));

        Finding saved = findingRepo.save(f);

        // Real evidence
        if (f.getEvidenceJson() != null && !f.getEvidenceJson().isBlank()) {
            Evidence ev = Evidence.builder()
                    .findingId(saved.getId())
                    .type("SCANNER_RESULT")
                    .content(f.getEvidenceJson())
                    .author(f.getSource())
                    .sha256(UUID.randomUUID().toString().replace("-", ""))
                    .build();
            evidenceRepo.save(ev);
        }

        auditService.log("FINDING_CREATED", "Finding", saved.getId().toString(), saved.getTitle());
        return saved;
    }

    @Transactional
    public Finding updateStatus(UUID id, String status, String comment) {
        Finding f = get(id);
        String old = f.getStatus();
        f.setStatus(status);
        if ("FALSE_POSITIVE".equals(status) || "RISK_ACCEPTED".equals(status)) {
            auditService.log("FINDING_STATUS", "Finding", id.toString(), old + " -> " + status + " : " + comment);
        }
        if ("RESOLVED".equals(old) && "OPEN".equals(status)) f.setStatus("REOPENED");
        return findingRepo.save(f);
    }

    public List<Evidence> evidences(UUID findingId) { return evidenceRepo.findByFindingId(findingId); }
    public List<FindingInstance> instances(UUID findingId) { return instanceRepo.findByFindingId(findingId); }

    public Map<String, Object> stats(UUID projectId) {
        List<Object[]> bySeverity = findingRepo.countBySeverity();
        List<Object[]> byStatus = findingRepo.countByStatusAgg();
        List<Object[]> byRisk = findingRepo.countByRiskLevel();
        Map<String, Object> m = new HashMap<>();
        m.put("bySeverity", toMap(bySeverity));
        m.put("byStatus", toMap(byStatus));
        m.put("byRiskLevel", toMap(byRisk));
        m.put("total", findingRepo.count());
        return m;
    }

    private Map<String, Long> toMap(List<Object[]> list) {
        Map<String, Long> m = new HashMap<>();
        for (Object[] o : list) m.put((String) o[0], (Long) o[1]);
        return m;
    }

    @Transactional
    public void generateMockFindings(Scan scan) {
        org.slf4j.LoggerFactory.getLogger(FindingService.class).warn("generateMockFindings called for scan {} but mock disabled", scan.getId());
    }

    @Transactional
    public Map<String, Object> correlation(UUID findingId) {
        Finding f = get(findingId);
        List<Finding> sameAsset = findingRepo.findByAssetId(f.getAssetId(), PageRequest.of(0, 100)).getContent();
        List<Finding> correlated = sameAsset.stream()
                .filter(x -> !x.getId().equals(f.getId()))
                .filter(x -> Objects.equals(x.getCwe(), f.getCwe()) || Objects.equals(x.getType(), f.getType()))
                .limit(5)
                .toList();

        // Build correlation graph
        var result = correlationEngine.correlate(f, correlated);
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("finding", Map.of("id", f.getId(), "title", f.getTitle(), "severity", f.getSeverity()));
        res.put("correlated", correlated.stream().map(x -> Map.of(
                "id", x.getId(), "title", x.getTitle(), "severity", x.getSeverity(),
                "riskScore", x.getRiskScore(), "cwe", x.getCwe())).toList());
        res.put("correlation", Map.of("reason", result.reason(), "isDuplicate", result.isDuplicate(), "merge", result.mergeRecommendation()));
        res.put("attackPathCandidate", correlated.size() >= 2 ?
                Map.of("chain", List.of(f.getType(), correlated.get(0).getType(), correlated.get(1).getType()),
                        "riskMultiplier", correlated.size() * 0.15) : "No strong chain");
        return res;
    }
}
