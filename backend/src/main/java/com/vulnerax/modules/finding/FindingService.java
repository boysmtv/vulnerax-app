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

    // Called by ScanService after scan completes - generate mock findings
    @Transactional
    public void generateMockFindings(Scan scan) {
        Random rnd = new Random();
        String[] titles = {
            "Broken Object Level Authorization", "SQL Injection via Unsanitized Input",
            "Hardcoded AWS Secret in Source", "Vulnerable Dependency log4j 2.14.1 (CVE-2021-44228)",
            "Cleartext Traffic Allowed (Android)", "Exported Activity Without Permission",
            "SSRF in Image Fetch Handler", "Insecure Deserialization in API", "Missing Authentication on /admin",
            "Container Running as Root", "Excessive IAM Wildcard Permission", "TLS 1.0 Enabled on Load Balancer"
        };
        String[] severities = {"CRITICAL","HIGH","HIGH","MEDIUM","LOW","INFO"};
        String[] cwes = {"CWE-639","CWE-89","CWE-798","CWE-1104","CWE-319","CWE-926"};
        String[] types = {"AUTHORIZATION","INJECTION","SECRET","SCA","CRYPTO","MOBILE","SSRF","DESERIALIZATION","AUTH","CONTAINER","IAM","TLS"};
        int n = 2 + rnd.nextInt(5);
        for (int i=0;i<n;i++) {
            int idx = rnd.nextInt(titles.length);
            Finding f = Finding.builder()
                    .title(titles[idx])
                    .description("Mock finding generated from scan " + scan.getId() + " via " + scan.getScannerType())
                    .type(types[idx % types.length])
                    .severity(severities[rnd.nextInt(severities.length)])
                    .confidence(rnd.nextDouble()<0.7? "HIGH":"MEDIUM")
                    .status("OPEN")
                    .projectId(scan.getProjectId())
                    .assetId(scan.getAssetId())
                    .assetName(scan.getTarget()!=null? scan.getTarget():"unknown-asset")
                    .environment("PRODUCTION")
                    .source(scan.getScannerType()!=null? scan.getScannerType().toLowerCase()+"-engine":"mock")
                    .scanId(scan.getId())
                    .cwe(cwes[idx % cwes.length])
                    .owasp(idx%2==0? "API1:2023":"A01:2021")
                    .cvss(2.0 + rnd.nextDouble()*8)
                    .epss(rnd.nextDouble())
                    .kev(rnd.nextDouble()<0.08)
                    .internetExposed(rnd.nextDouble()<0.4)
                    .reachable(rnd.nextDouble()<0.6)
                    .businessCriticality(rnd.nextDouble()<0.3? "CRITICAL":"HIGH")
                    .owner("Platform Team")
                    .filePath("src/main/java/com/example/Service.java")
                    .lineNumber(42 + rnd.nextInt(200))
                    .functionName("handleRequest")
                    .codeSnippet("String query = \"SELECT * FROM users WHERE id=\" + input;")
                    .dataFlow("source: request param -> sink: sql query")
                    .recommendation("Use parameterized queries and validate ownership before access.")
                    .build();
            create(f);
        }
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
