package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.ContainerAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class ContainerPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "container-plugin"; }
    @Override public String getName() { return "Container Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "docker", "k8s"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("container-1", "IMAGE_CHECK", "Container image analysis", options)),
            Map.of("engine", "regex", "focus", "Dockerfile misconfig")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String config = options.getOrDefault("configJson", null);
        List<Map<String, Object>> results = ContainerAnalyzer.analyze(targetUrl, config);
        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("snippet"));
            f.setType("CONTAINER");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("container-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("DevOps Team");
            return f;
        }).toList();
    }

    @Override public Finding normalize(Finding raw, Map<String, String> options) { return raw; }
    @Override public ValidationResult validate(Finding f) {
        return f.getTitle() != null ? new ValidationResult(true, "Valid") : new ValidationResult(false, "Missing title");
    }
}
