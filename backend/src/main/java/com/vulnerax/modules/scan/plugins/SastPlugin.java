package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingType;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.SastAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class SastPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "sast-plugin"; }
    @Override public String getName() { return "SAST Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "code"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("sast-1", "PATTERN_MATCH", "Static code analysis", options)),
            Map.of("engine", "regex", "rules", "30+")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String content = options.getOrDefault("fileContent", targetUrl);
        String fileName = options.getOrDefault("fileName", "unknown");
        List<Map<String, Object>> results = SastAnalyzer.analyze(content, fileName);

        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("rule") + " detected");
            f.setType("SAST");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setLineNumber((Integer) r.get("line"));
            f.setCodeSnippet((String) r.get("snippet"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("sast-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Dev Team");
            return f;
        }).toList();
    }

    @Override
    public Finding normalize(Finding raw, Map<String, String> options) {
        if (raw.getCweId() == null && raw.getCwe() != null) raw.setCweId(raw.getCwe());
        if (raw.getFilePath() != null && raw.getFilePath().contains("/")) {
            raw.setFilePath(raw.getFilePath().replace("\\", "/"));
        }
        return raw;
    }

    @Override
    public ValidationResult validate(Finding finding) {
        if (finding.getTitle() == null || finding.getTitle().isBlank())
            return new ValidationResult(false, "Missing title");
        if (finding.getSeverity() == null)
            return new ValidationResult(false, "Missing severity");
        if (finding.getCwe() == null)
            return new ValidationResult(false, "Missing CWE");
        return new ValidationResult(true, "Valid");
    }
}
