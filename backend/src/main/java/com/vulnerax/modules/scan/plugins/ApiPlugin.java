package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.ApiAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class ApiPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "api-plugin"; }
    @Override public String getName() { return "API Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "api"); }
    @Override public String getSecurityLevel() { return "AGGRESSIVE"; }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("api-1", "ENDPOINT_CHECK", "API endpoint analysis", options)),
            Map.of("engine", "http-client", "focus", "auth, rate-limit, input-validation")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        List<Map<String, Object>> results = ApiAnalyzer.analyze(targetUrl);
        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("snippet"));
            f.setType("API");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("api-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Security Team");
            return f;
        }).toList();
    }

    @Override public Finding normalize(Finding raw, Map<String, String> options) { return raw; }
    @Override public ValidationResult validate(Finding f) {
        return f.getTitle() != null ? new ValidationResult(true, "Valid") : new ValidationResult(false, "Missing title");
    }
}
