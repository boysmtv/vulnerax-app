package com.vulnerax.modules.assetgraph;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
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
                node.vulnerabilities().add(new AssetNode.VulnRef(f.getId(), f.getTitle(), f.getSeverity()));
                node.incrementVulnCount();
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

        // Connect assets that have findings with same CWE
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

    public static class AssetGraph {
        private final List<AssetNode> nodes;
        private final List<AssetEdge> edges;
        public AssetGraph(List<AssetNode> nodes, List<AssetEdge> edges) { this.nodes = nodes; this.edges = edges; }
        public List<AssetNode> nodes() { return nodes; }
        public List<AssetEdge> edges() { return edges; }
    }

    public static class AssetNode {
        private final String id;
        private final String type;
        private final List<VulnRef> vulnerabilities;
        private int vulnerabilityCount;
        private int scanIssueCount;
        private int infoCount;

        public AssetNode(String id, String type, List<VulnRef> vulnerabilities, int vulnerabilityCount, int scanIssueCount, int infoCount) {
            this.id = id; this.type = type; this.vulnerabilities = vulnerabilities;
            this.vulnerabilityCount = vulnerabilityCount; this.scanIssueCount = scanIssueCount; this.infoCount = infoCount;
        }
        public String id() { return id; }
        public String type() { return type; }
        public List<VulnRef> vulnerabilities() { return vulnerabilities; }
        public int vulnerabilityCount() { return vulnerabilityCount; }
        public int scanIssueCount() { return scanIssueCount; }
        public int infoCount() { return infoCount; }
        public void incrementVulnCount() { this.vulnerabilityCount++; }

        public record VulnRef(UUID findingId, String title, String severity) {}
    }

    public static class AssetEdge {
        private final String source;
        private final String target;
        private final String relationship;
        private final String label;
        public AssetEdge(String source, String target, String relationship, String label) {
            this.source = source; this.target = target; this.relationship = relationship; this.label = label;
        }
        public String source() { return source; }
        public String target() { return target; }
        public String relationship() { return relationship; }
        public String label() { return label; }
    }
}
