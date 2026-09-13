package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.DastAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class DastPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "dast-plugin"; }
    @Override public String getName() { return "DAST Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or"); }
    @Override public String getSecurityLevel() { return "AGGRESSIVE"; }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        List<ScanStep> steps = List.of(
            new ScanStep("dast-headers", "HEADER_CHECK", "Check security headers", options),
            new ScanStep("dast-inject", "INJECTION", "XSS/SQLi/SSRF tests", options),
            new ScanStep("dast-auth", "AUTH_CHECK", "Authentication bypass tests", options)
        );
        return new ScanPlan(steps, Map.of("engine", "http-client", "timeout", "10s"));
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        List<Map<String, Object>> results = DastAnalyzer.analyze(targetUrl, null);

        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription((String) r.get("snippet"));
            f.setType("DAST");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe((String) r.get("cwe"));
            f.setFilePath((String) r.get("file"));
            f.setRecommendation((String) r.get("recommendation"));
            f.setSource("dast-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Security Team");
            f.setInternetExposed(true);
            f.setEvidenceJson(buildEvidenceJson(r, targetUrl));
            return f;
        }).toList();
    }

    @Override
    public Finding normalize(Finding raw, Map<String, String> options) {
        if (raw.getFilePath() != null && raw.getFilePath().startsWith("http")) {
            raw.setAssetName(raw.getFilePath());
        }
        return raw;
    }

    @Override
    public ValidationResult validate(Finding finding) {
        if (finding.getTitle() == null) return new ValidationResult(false, "Missing title");
        if (finding.getFilePath() == null) return new ValidationResult(false, "Missing target URL");
        return new ValidationResult(true, "Valid");
    }

    private String buildEvidenceJson(Map<String, Object> r, String target) {
        try {
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("type", r.get("rule"));
            ev.put("target", target);
            ev.put("statusCode", r.get("statusCode"));
            ev.put("responseHeaders", r.get("responseHeaders"));
            ev.put("payload", r.get("payload"));
            ev.put("testUrl", r.get("testUrl"));
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(ev);
        } catch (Exception e) {
            return "{\"type\":\"DAST_RESULT\"}";
        }
    }
}
