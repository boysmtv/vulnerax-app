package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.MobileAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class MobilePlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "mobile-plugin"; }
    @Override public String getName() { return "Mobile Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "mobile", "android", "ios"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("mobile-1", "APP_CHECK", "Mobile app security analysis", options)),
            Map.of("engine", "regex", "focus", "MASVS")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String config = options.getOrDefault("configJson", null);
        List<Map<String, Object>> results = MobileAnalyzer.analyze(targetUrl, config);
        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("snippet"));
            f.setType("MOBILE");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("mobile-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Mobile Team");
            return f;
        }).toList();
    }

    @Override public Finding normalize(Finding raw, Map<String, String> options) { return raw; }
    @Override public ValidationResult validate(Finding f) {
        return f.getTitle() != null ? new ValidationResult(true, "Valid") : new ValidationResult(false, "Missing title");
    }
}
