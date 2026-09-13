package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.SecretAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class SecretPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "secret-plugin"; }
    @Override public String getName() { return "Secret Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "code"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("secret-1", "PATTERN_MATCH", "Secret detection", options)),
            Map.of("engine", "regex", "rules", "API keys, passwords, private keys")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String content = options.getOrDefault("fileContent", targetUrl);
        String fileName = options.getOrDefault("fileName", "unknown");
        List<Map<String, Object>> results = SecretAnalyzer.analyze(content, fileName);

        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription("Hardcoded secret detected: " + r.get("rule"));
            f.setType("SECRET");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setLineNumber((Integer) r.get("line"));
            f.setCodeSnippet("match: " + r.get("match"));
            f.setRecommendation("Rotate secret, purge history, move to Vault");
            f.setSource("secret-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Security Team");
            return f;
        }).toList();
    }

    @Override
    public Finding normalize(Finding raw, Map<String, String> options) { return raw; }

    @Override
    public ValidationResult validate(Finding finding) {
        if (finding.getTitle() == null) return new ValidationResult(false, "Missing title");
        return new ValidationResult(true, "Valid");
    }
}
