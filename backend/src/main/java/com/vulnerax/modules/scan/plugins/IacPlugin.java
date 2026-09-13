package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.IaCAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class IacPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "iac-plugin"; }
    @Override public String getName() { return "IaC Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "code", "terraform", "kubernetes"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("iac-1", "CONFIG_CHECK", "IaC security analysis", options)),
            Map.of("engine", "regex", "rules", "Terraform, Kubernetes, CloudFormation")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String content = options.getOrDefault("fileContent", targetUrl);
        String fileName = options.getOrDefault("fileName", "unknown");
        List<Map<String, Object>> results = IaCAnalyzer.analyze(content, fileName);
        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("snippet"));
            f.setType("IAC");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("iac-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Platform Team");
            return f;
        }).toList();
    }

    @Override public Finding normalize(Finding raw, Map<String, String> options) { return raw; }
    @Override public ValidationResult validate(Finding f) {
        return f.getTitle() != null ? new ValidationResult(true, "Valid") : new ValidationResult(false, "Missing title");
    }
}
