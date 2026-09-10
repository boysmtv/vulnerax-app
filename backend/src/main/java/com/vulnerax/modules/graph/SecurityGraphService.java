package com.vulnerax.modules.graph;

import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class SecurityGraphService {
    private final AssetRepository assetRepo;
    private final FindingRepository findingRepo;

    public Map<String,Object> graphForProject(UUID projectId) {
        List<Asset> assets = projectId!=null? assetRepo.findByProjectId(projectId): assetRepo.findAll();
        List<Finding> findings = projectId!=null? findingRepo.findByProjectId(projectId): findingRepo.findAll();
        List<Map<String,Object>> nodes = new ArrayList<>();
        List<Map<String,Object>> edges = new ArrayList<>();
        for (Asset a: assets) {
            nodes.add(Map.of("id", a.getId().toString(), "label", a.getName(), "type", "ASSET", "assetType", a.getType(), "criticality", a.getCriticality()!=null?a.getCriticality():"MEDIUM", "exposed", a.getInternetExposed()!=null?a.getInternetExposed():false));
        }
        for (Finding f: findings) {
            String fid = "FINDING-" + f.getId().toString().substring(0,8);
            nodes.add(Map.of("id", fid, "label", f.getTitle(), "type", "FINDING", "severity", f.getSeverity(), "risk", f.getRiskLevel()!=null?f.getRiskLevel():"LOW"));
            if (f.getAssetId()!=null) edges.add(Map.of("from", f.getAssetId().toString(), "to", fid, "label", "HAS_VULN"));
        }
        // create synthetic edges asset-to-asset for demo (API -> Service -> DB)
        if (assets.size()>=3) {
            for (int i=0;i<Math.min(assets.size()-1,4);i++) {
                edges.add(Map.of("from", assets.get(i).getId().toString(), "to", assets.get(i+1).getId().toString(), "label", "CONNECTS"));
            }
        }
        Map<String,Object> g = new HashMap<>();
        g.put("nodes", nodes);
        g.put("edges", edges);
        g.put("stats", Map.of("assets", assets.size(), "findings", findings.size(), "edges", edges.size()));
        return g;
    }

    public List<Map<String,Object>> attackPaths(UUID projectId) {
        List<Finding> critical = findingRepo.findAll().stream()
                .filter(f-> projectId==null || projectId.equals(f.getProjectId()))
                .filter(f-> "CRITICAL".equals(f.getSeverity()) || "CRITICAL".equals(f.getRiskLevel()) || Boolean.TRUE.equals(f.getInternetExposed()))
                .sorted(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())))
                .limit(5).toList();
        List<Map<String,Object>> paths = new ArrayList<>();
        for (Finding f: critical) {
            paths.add(Map.of(
                "id", f.getId(),
                "entryPoint", f.getInternetExposed()!=null && f.getInternetExposed() ? f.getAssetName()+" (Internet)" : "Internal",
                "weakness", f.getTitle(),
                "asset", f.getAssetName()!=null?f.getAssetName():"unknown",
                "risk", f.getRiskScore()!=null?f.getRiskScore():0,
                "riskLevel", f.getRiskLevel()!=null?f.getRiskLevel():"LOW",
                "chain", List.of("Internet", f.getAssetName()!=null?f.getAssetName():"Web", "Service", "Database"),
                "impact", "HIGH".equals(f.getSeverity()) || "CRITICAL".equals(f.getSeverity()) ? "Confidential Data Exposure" : "Service Disruption",
                "mitigation", f.getRecommendation()!=null? f.getRecommendation(): "Apply patch and validate access control"
            ));
        }
        return paths;
    }
}
