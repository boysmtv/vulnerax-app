package com.vulnerax.modules.finding;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.audit.AuditService;
import com.vulnerax.modules.risk.RiskEngine;
import com.vulnerax.modules.scan.Scan;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
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

    private final AtomicLong counter = new AtomicLong(1000);

    public Page<Finding> list(UUID projectId, UUID assetId, String severity, String status, String riskLevel, String search, Pageable p) {
        if (projectId != null) return findingRepo.findByProjectId(projectId, p);
        if (assetId != null) return findingRepo.findByAssetId(assetId, p);
        return findingRepo.findAll(p);
    }

    public Finding get(UUID id) { return findingRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Finding not found")); }

    @Transactional
    public Finding create(Finding f) {
        if (f.getFindingId() == null) f.setFindingId("FND-" + counter.incrementAndGet());
        riskEngine.enrich(f);
        // dedup check
        var existing = findingRepo.findByFingerprint(f.getFingerprint());
        if (!existing.isEmpty()) {
            // create instance instead of duplicate
            Finding parent = existing.get(0);
            FindingInstance inst = FindingInstance.builder()
                    .findingId(parent.getId())
                    .assetName(f.getAssetName())
                    .location(f.getFilePath() + ":" + f.getLineNumber())
                    .scanner(f.getSource())
                    .fingerprint(f.getFingerprint())
                    .build();
            instanceRepo.save(inst);
            parent.setDuplicate(false); // parent is original
            // correlate: increase risk if multiple instances
            log.info("Dedup: new instance for {}", parent.getFindingId());
            return parent;
        }
        Finding saved = findingRepo.save(f);
        // create evidence placeholder
        Evidence ev = Evidence.builder()
                .findingId(saved.getId())
                .type("SCANNER_RESULT")
                .content("Evidence for " + saved.getTitle())
                .author("scanner")
                .sha256(UUID.randomUUID().toString().replace("-",""))
                .build();
        evidenceRepo.save(ev);
        auditService.log("FINDING_CREATED", "Finding", saved.getId().toString(), saved.getTitle());
        return saved;
    }

    @Transactional
    public Finding updateStatus(UUID id, String status, String comment) {
        Finding f = get(id);
        String old = f.getStatus();
        f.setStatus(status);
        if ("FALSE_POSITIVE".equals(status) || "RISK_ACCEPTED".equals(status)) {
            // requires approval simulation
            auditService.log("FINDING_STATUS", "Finding", id.toString(), old + " -> " + status + " : " + comment);
        }
        // handle REOPENED if previously fixed
        if ("RESOLVED".equals(old) && "OPEN".equals(status)) f.setStatus("REOPENED");
        return findingRepo.save(f);
    }

    public List<Evidence> evidences(UUID findingId) { return evidenceRepo.findByFindingId(findingId); }
    public List<FindingInstance> instances(UUID findingId) { return instanceRepo.findByFindingId(findingId); }

    public Map<String,Object> stats(UUID projectId) {
        List<Object[]> bySeverity = findingRepo.countBySeverity();
        List<Object[]> byStatus = findingRepo.countByStatusAgg();
        List<Object[]> byRisk = findingRepo.countByRiskLevel();
        Map<String,Object> m = new HashMap<>();
        m.put("bySeverity", toMap(bySeverity));
        m.put("byStatus", toMap(byStatus));
        m.put("byRiskLevel", toMap(byRisk));
        m.put("total", findingRepo.count());
        return m;
    }

    private Map<String,Long> toMap(List<Object[]> list) {
        Map<String,Long> m = new HashMap<>();
        for (Object[] o : list) m.put((String)o[0], (Long)o[1]);
        return m;
    }

    // Mock removed per request "hilangkan semua data mock" — previously generated random findings
    // Now disabled: real findings only via ScanService.runRealAnalyzers (Sast/Sca/Secret). Keep method for backward compat but make no-op.
    @Transactional
    public void generateMockFindings(Scan scan) {
        // No-op: mock generation disabled. Real findings are created via ScanService.runRealAnalyzers only.
        // If legacy call occurs, log and do nothing.
        org.slf4j.LoggerFactory.getLogger(FindingService.class).warn("generateMockFindings called for scan {} but mock disabled — use real analyzers", scan.getId());
    }

    @Transactional
    public Map<String,Object> correlation(UUID findingId) {
        Finding f = get(findingId);
        // naive correlation: findings sharing same asset or cwe or type
        List<Finding> sameAsset = findingRepo.findByAssetId(f.getAssetId(), Pageable.unpaged()).getContent();
        List<Finding> correlated = sameAsset.stream().filter(x -> !x.getId().equals(f.getId()) && (Objects.equals(x.getCwe(), f.getCwe()) || Objects.equals(x.getType(), f.getType()))).limit(5).toList();
        Map<String,Object> res = new HashMap<>();
        res.put("finding", f);
        res.put("correlated", correlated);
        res.put("attackPathCandidate", correlated.size()>=2 ? "Potential chain: " + f.getType() + " -> " + correlated.get(0).getType() : "No strong chain");
        return res;
    }
}
