package com.vulnerax.modules.graph;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class SecurityGraphService {
    private final AssetRepository assetRepo;
    private final FindingRepository findingRepo;

    // CWE adjacency for real edges (attack chain relationships)
    private static final Map<String, Set<String>> CWE_CHAINS;
    static {
        CWE_CHAINS = new HashMap<>();
        CWE_CHAINS.put("CWE-79", Set.of("CWE-89", "CWE-918", "CWE-22"));
        CWE_CHAINS.put("CWE-89", Set.of("CWE-200", "CWE-284"));
        CWE_CHAINS.put("CWE-78", Set.of("CWE-200", "CWE-284", "CWE-862"));
        CWE_CHAINS.put("CWE-22", Set.of("CWE-200", "CWE-434"));
        CWE_CHAINS.put("CWE-798", Set.of("CWE-284", "CWE-862"));
        CWE_CHAINS.put("CWE-918", Set.of("CWE-200", "CWE-862"));
        CWE_CHAINS.put("CWE-287", Set.of("CWE-284", "CWE-862"));
        CWE_CHAINS.put("CWE-352", Set.of("CWE-284", "CWE-862"));
        CWE_CHAINS.put("CWE-611", Set.of("CWE-200"));
        CWE_CHAINS.put("CWE-502", Set.of("CWE-200", "CWE-284"));
        CWE_CHAINS.put("CWE-200", Set.of("CWE-284"));
        CWE_CHAINS.put("CWE-284", Set.of("CWE-862"));
    }

    public Map<String, Object> graphForProject(UUID projectId) {
        List<Asset> assets = projectId != null ? assetRepo.findByProjectId(projectId) : assetRepo.findAll();
        List<Finding> findings = projectId != null
                ? findingRepo.findByProjectId(projectId, PageRequest.of(0, 500)).getContent()
                : findingRepo.findAll(PageRequest.of(0, 500)).getContent();

        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        for (Asset a : assets) {
            nodes.add(Map.of("id", a.getId().toString(), "label", a.getName(), "type", "ASSET",
                    "assetType", a.getType(), "criticality", a.getCriticality() != null ? a.getCriticality() : "MEDIUM",
                    "exposed", a.getInternetExposed() != null ? a.getInternetExposed() : false));
        }
        for (Finding f : findings) {
            String fid = "FINDING-" + f.getId().toString().substring(0, 8);
            nodes.add(Map.of("id", fid, "label", f.getTitle(), "type", "FINDING",
                    "severity", f.getSeverity(), "risk", f.getRiskLevel() != null ? f.getRiskLevel() : "LOW"));
            if (f.getAssetId() != null) edges.add(Map.of("from", f.getAssetId().toString(), "to", fid, "label", "HAS_VULN"));
        }

        // Real edges: CWE-based attack chain relationships
        Map<String, List<Finding>> findingsByAsset = new HashMap<>();
        for (Finding f : findings) {
            if (f.getAssetId() != null) {
                findingsByAsset.computeIfAbsent(f.getAssetId().toString(), k -> new ArrayList<>()).add(f);
            }
        }
        for (var entry : findingsByAsset.entrySet()) {
            List<Finding> assetFindings = entry.getValue();
            for (int i = 0; i < assetFindings.size(); i++) {
                for (int j = i + 1; j < assetFindings.size(); j++) {
                    Finding a = assetFindings.get(i);
                    Finding b = assetFindings.get(j);
                    String cweA = a.getCwe() != null ? a.getCwe() : a.getCweId();
                    String cweB = b.getCwe() != null ? b.getCwe() : b.getCweId();
                    if (cweA != null && cweB != null) {
                        Set<String> chains = CWE_CHAINS.getOrDefault(cweA, Set.of());
                        if (chains.contains(cweB)) {
                            String from = "FINDING-" + a.getId().toString().substring(0, 8);
                            String to = "FINDING-" + b.getId().toString().substring(0, 8);
                            double multiplier = 1.0 + (a.getRiskScore() != null ? a.getRiskScore() / 100.0 : 0.1);
                            edges.add(Map.of("from", from, "to", to, "label", "CHAINS_TO",
                                    "riskMultiplier", Math.round(multiplier * 100.0) / 100.0,
                                    "reason", cweA + " -> " + cweB));
                        }
                    }
                }
            }
        }

        Map<String, Object> g = new HashMap<>();
        g.put("nodes", nodes);
        g.put("edges", edges);
        g.put("stats", Map.of("assets", assets.size(), "findings", findings.size(), "edges", edges.size()));
        return g;
    }

    public List<Map<String, Object>> attackPaths(UUID projectId) {
        List<Finding> allFindings = projectId != null
                ? findingRepo.findByProjectId(projectId, PageRequest.of(0, 200)).getContent()
                : findingRepo.findAll(PageRequest.of(0, 200)).getContent();

        // BFS from internet-exposed findings to find attack chains
        List<Finding> startingPoints = allFindings.stream()
                .filter(f -> Boolean.TRUE.equals(f.getInternetExposed()) || "CRITICAL".equals(f.getSeverity()))
                .sorted(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(10)
                .toList();

        List<Map<String, Object>> paths = new ArrayList<>();
        Set<UUID> visited = new HashSet<>();

        for (Finding start : startingPoints) {
            if (visited.contains(start.getId())) continue;
            visited.add(start.getId());

            List<String> chain = new ArrayList<>();
            chain.add(Boolean.TRUE.equals(start.getInternetExposed()) ? "Internet" : "Internal");
            chain.add(start.getAssetName() != null ? start.getAssetName() : "Web App");
            chain.add(start.getType());

            double cumulativeRisk = start.getRiskScore() != null ? start.getRiskScore() : 0;

            // BFS: find next CWE-linked finding
            String cweStart = start.getCwe() != null ? start.getCwe() : start.getCweId();
            if (cweStart != null) {
                Set<String> nextCwes = CWE_CHAINS.getOrDefault(cweStart, Set.of());
                for (Finding next : allFindings) {
                    if (visited.contains(next.getId())) continue;
                    String nextCwe = next.getCwe() != null ? next.getCwe() : next.getCweId();
                    if (nextCwe != null && nextCwes.contains(nextCwe) && Objects.equals(next.getAssetId(), start.getAssetId())) {
                        chain.add("-> " + next.getType());
                        cumulativeRisk += next.getRiskScore() != null ? next.getRiskScore() * 0.15 : 0;
                        visited.add(next.getId());
                        break;
                    }
                }
            }

            if ("SECRET".equals(start.getType())) chain.add("Credential Exposure");
            else if ("SAST".equals(start.getType())) chain.add("Code Exploitation");
            else chain.add("Compromise");

            String impact;
            double normRisk = Math.min(100, cumulativeRisk);
            if (normRisk >= 81) impact = "Full System Compromise + Data Exfiltration";
            else if (normRisk >= 61) impact = "Privilege Escalation + Data Exposure";
            else if (normRisk >= 41) impact = "Limited Access + Potential Lateral Movement";
            else impact = "Low Risk - Hardening Recommended";

            paths.add(Map.of(
                    "id", start.getId(),
                    "entryPoint", Boolean.TRUE.equals(start.getInternetExposed()) ? start.getAssetName() + " (Internet)" : "Internal",
                    "weakness", start.getTitle(),
                    "asset", start.getAssetName() != null ? start.getAssetName() : "unknown",
                    "risk", Math.round(cumulativeRisk * 10.0) / 10.0,
                    "riskLevel", normRisk >= 81 ? "CRITICAL" : normRisk >= 61 ? "VERY_HIGH" : normRisk >= 41 ? "HIGH" : "MODERATE",
                    "chain", chain,
                    "impact", impact,
                    "mitigation", start.getRecommendation() != null ? start.getRecommendation() : "Apply patch and validate access control"
            ));
        }
        return paths;
    }
}
