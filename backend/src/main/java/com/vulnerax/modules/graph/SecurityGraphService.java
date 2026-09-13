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

    public Map<String, Object> graphForProject(UUID projectId) {
        List<Asset> assets = projectId != null ? assetRepo.findByProjectId(projectId) : assetRepo.findAll();
        List<Finding> findings = projectId != null ? findingRepo.findByProjectId(projectId) : findingRepo.findAll();
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

        // Real edges: findings connected to same asset create attack paths
        Map<String, List<Finding>> findingsByAsset = new HashMap<>();
        for (Finding f : findings) {
            if (f.getAssetId() != null) {
                findingsByAsset.computeIfAbsent(f.getAssetId().toString(), k -> new ArrayList<>()).add(f);
            }
        }
        for (var entry : findingsByAsset.entrySet()) {
            List<Finding> assetFindings = entry.getValue();
            for (int i = 0; i < assetFindings.size() - 1; i++) {
                String from = "FINDING-" + assetFindings.get(i).getId().toString().substring(0, 8);
                String to = "FINDING-" + assetFindings.get(i + 1).getId().toString().substring(0, 8);
                edges.add(Map.of("from", from, "to", to, "label", "CHAINS_TO", "riskMultiplier", 1.15));
            }
        }

        Map<String, Object> g = new HashMap<>();
        g.put("nodes", nodes);
        g.put("edges", edges);
        g.put("stats", Map.of("assets", assets.size(), "findings", findings.size(), "edges", edges.size()));
        return g;
    }

    public List<Map<String, Object>> attackPaths(UUID projectId) {
        List<Finding> allFindings = projectId != null ? findingRepo.findByProjectId(projectId) : findingRepo.findAll();
        List<Finding> critical = allFindings.stream()
                .filter(f -> "CRITICAL".equals(f.getSeverity()) || "CRITICAL".equals(f.getRiskLevel()) || Boolean.TRUE.equals(f.getInternetExposed()))
                .sorted(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(5)
                .toList();

        List<Map<String, Object>> paths = new ArrayList<>();
        for (Finding f : critical) {
            List<String> chain = new ArrayList<>();
            chain.add(Boolean.TRUE.equals(f.getInternetExposed()) ? "Internet" : "Internal");
            chain.add(f.getAssetName() != null ? f.getAssetName() : "Web App");
            chain.add(f.getType());
            if ("SECRET".equals(f.getType())) chain.add("Credential Exposure");
            else if ("SAST".equals(f.getType())) chain.add("Data Breach");
            else chain.add("Compromise");

            String impact;
            if ("CRITICAL".equals(f.getSeverity())) impact = "Full System Compromise + Data Exfiltration";
            else if ("HIGH".equals(f.getSeverity())) impact = "Privilege Escalation + Data Exposure";
            else impact = "Limited Access + Potential Lateral Movement";

            paths.add(Map.of(
                    "id", f.getId(),
                    "entryPoint", Boolean.TRUE.equals(f.getInternetExposed()) ? f.getAssetName() + " (Internet)" : "Internal",
                    "weakness", f.getTitle(),
                    "asset", f.getAssetName() != null ? f.getAssetName() : "unknown",
                    "risk", f.getRiskScore() != null ? f.getRiskScore() : 0,
                    "riskLevel", f.getRiskLevel() != null ? f.getRiskLevel() : "LOW",
                    "chain", chain,
                    "impact", impact,
                    "mitigation", f.getRecommendation() != null ? f.getRecommendation() : "Apply patch and validate access control"
            ));
        }
        return paths;
    }
}
