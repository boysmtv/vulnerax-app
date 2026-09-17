package com.vulnerax.modules.assetgraph;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AssetGraphEngine {
    private final FindingRepository findingRepo;

    public AssetGraph buildGraph(UUID projectId) {
        List<Finding> findings = projectId != null ? findingRepo.findByProjectId(projectId) : findingRepo.findAll();

        Map<String, AssetNode> nodes = new LinkedHashMap<>();
        List<AssetEdge> edges = new ArrayList<>();

        for (Finding f : findings) {
            String asset = f.getAssetName() != null ? f.getAssetName() : "unknown";
            nodes.putIfAbsent(asset, new AssetNode(asset, "SERVICE", new ArrayList<>(), 0, 0, 0));
            AssetNode node = nodes.get(asset);

            if ("VULNERABILITY".equals(f.getFindingType()) && Boolean.TRUE.equals(f.getVulnerabilityConfirmed())) {
                node.getVulnerabilities().add(new AssetNode.VulnRef(f.getId(), f.getTitle(), f.getSeverity()));
                node.setVulnerabilityCount(node.getVulnerabilityCount() + 1);
            }

            if (f.getFilePath() != null) {
                String endpoint = f.getFilePath();
                if (!endpoint.startsWith("/")) endpoint = "/" + endpoint;

                String method = "GET";
                String path = endpoint;

                String endpointNode = asset + ":" + method + path;
                nodes.putIfAbsent(endpointNode, new AssetNode(endpointNode, "ENDPOINT", new ArrayList<>(), 0, 0, 0));

                edges.add(new AssetEdge(asset, endpointNode, "HOSTS", "CAN_ACCESS"));
            }
        }

        List<Finding> confirmed = findings.stream()
                .filter(f -> f.getCwe() != null && Boolean.TRUE.equals(f.getVulnerabilityConfirmed()))
                .toList();
        Map<String, Set<String>> cweToAssets = confirmed.stream()
                .collect(Collectors.groupingBy(Finding::getCwe, Collectors.mapping(Finding::getAssetName, Collectors.toSet())));
        cweToAssets.forEach((cwe, assets) -> {
            List<String> assetList = new ArrayList<>(assets);
            for (int i = 0; i < assetList.size() - 1; i++) {
                for (int j = i + 1; j < assetList.size(); j++) {
                    edges.add(new AssetEdge(assetList.get(i), assetList.get(j), "SHARED_VULNERABILITY", cwe));
                }
            }
        });

        return new AssetGraph(new ArrayList<>(nodes.values()), edges);
    }

    @Data @AllArgsConstructor
    public static class AssetGraph {
        private List<AssetNode> nodes;
        private List<AssetEdge> edges;
    }

    @Data @AllArgsConstructor @NoArgsConstructor
    public static class AssetNode {
        private String id;
        private String type;
        private List<VulnRef> vulnerabilities;
        private int vulnerabilityCount;
        private int scanIssueCount;
        private int infoCount;

        public record VulnRef(UUID findingId, String title, String severity) {}
    }

    @Data @AllArgsConstructor
    public static class AssetEdge {
        private String source;
        private String target;
        private String relationship;
        private String label;
    }
}
