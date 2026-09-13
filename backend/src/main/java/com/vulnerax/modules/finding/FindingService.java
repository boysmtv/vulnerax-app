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

import java.security.MessageDigest;
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

        // Sync cweId from cwe if not set
        if (f.getCweId() == null && f.getCwe() != null) f.setCweId(f.getCwe());
        if (f.getCwe() == null && f.getCweId() != null) f.setCwe(f.getCweId());

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

        // Correlation check - use ALL findings for same asset, not pre-filtered
        List<Finding> candidateFindings = findingRepo.findByAssetId(f.getAssetId(), PageRequest.of(0, 500)).getContent();
        var correlation = correlationEngine.correlate(f, candidateFindings);
        if (correlation.isDuplicate()) {
            log.info("Correlation detected duplicate: {} reason={}", f.getTitle(), correlation.reason());
            f.setDuplicate(true);
        }
        f.setCorrelationId(correlation.reason().equals("NO_MATCH") ? null :
                correlation.matches().stream().findFirst().map(Finding::getId).orElse(null));

        Finding saved = findingRepo.save(f);

        // Create real evidence
        createEvidence(saved, f);

        auditService.log("FINDING_CREATED", "Finding", saved.getId().toString(), saved.getTitle());
        return saved;
    }

    private void createEvidence(Finding saved, Finding original) {
        List<Evidence> evidences = new ArrayList<>();

        // Evidence from evidenceJson (structured JSON blob)
        if (original.getEvidenceJson() != null && !original.getEvidenceJson().isBlank()) {
            evidences.add(Evidence.builder()
                    .findingId(saved.getId())
                    .type("SCANNER_RESULT")
                    .content(original.getEvidenceJson())
                    .author(original.getSource())
                    .sha256(computeSha256(original.getEvidenceJson()))
                    .build());
        }

        // Evidence from code snippet (SAST/IaC findings)
        if (original.getCodeSnippet() != null && !original.getCodeSnippet().isBlank()) {
            evidences.add(Evidence.builder()
                    .findingId(saved.getId())
                    .type("CODE_SNIPPET")
                    .content(original.getCodeSnippet())
                    .author(original.getSource())
                    .sha256(computeSha256(original.getCodeSnippet()))
                    .requestUrl(original.getFilePath())
                    .build());
        }

        // Evidence from data flow
        if (original.getDataFlow() != null && !original.getDataFlow().isBlank()) {
            evidences.add(Evidence.builder()
                    .findingId(saved.getId())
                    .type("DATA_FLOW")
                    .content(original.getDataFlow())
                    .author(original.getSource())
                    .sha256(computeSha256(original.getDataFlow()))
                    .build());
        }

        for (Evidence ev : evidences) {
            evidenceRepo.save(ev);
        }
    }

    private String computeSha256(String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return UUID.randomUUID().toString().replace("-", "");
        }
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
        m.put("critical", findingRepo.countBySeverity("CRITICAL"));
        m.put("high", findingRepo.countBySeverity("HIGH"));
        m.put("kev", findingRepo.countByKev(true));
        m.put("avgRiskScore", findingRepo.avgRiskScore() != null ? findingRepo.avgRiskScore() : 0);
        return m;
    }

    private Map<String, Long> toMap(List<Object[]> list) {
        Map<String, Long> m = new HashMap<>();
        for (Object[] o : list) m.put((String) o[0], (Long) o[1]);
        return m;
    }

    @Transactional
    public void generateMockFindings(Scan scan) {
        log.warn("generateMockFindings called for scan {} but mock disabled", scan.getId());
    }

    @Transactional
    public Map<String, Object> correlation(UUID findingId) {
        Finding f = get(findingId);
        // Use the engine directly with broader candidate set
        List<Finding> allFindings = findingRepo.findByProjectId(f.getProjectId(), PageRequest.of(0, 1000)).getContent();
        var result = correlationEngine.correlate(f, allFindings);

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("finding", Map.of("id", f.getId(), "title", f.getTitle(), "severity", f.getSeverity(),
                "type", f.getType(), "cwe", f.getCwe() != null ? f.getCwe() : "N/A"));
        res.put("correlated", result.matches().stream().map(x -> Map.of(
                "id", x.getId(), "title", x.getTitle(), "severity", x.getSeverity(),
                "riskScore", x.getRiskScore() != null ? x.getRiskScore() : 0,
                "cwe", x.getCwe() != null ? x.getCwe() : "N/A",
                "type", x.getType())).toList());
        res.put("correlation", Map.of(
                "reason", result.reason(),
                "isDuplicate", result.isDuplicate(),
                "merge", result.mergeRecommendation(),
                "matchCount", result.matches().size()));
        if (result.matches().size() >= 2) {
            res.put("attackPathCandidate", Map.of(
                    "chain", List.of(f.getType(), result.matches().get(0).getType(), result.matches().get(1).getType()),
                    "riskMultiplier", result.matches().size() * 0.15));
        }
        return res;
    }
}
