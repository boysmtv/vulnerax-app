package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.analyzers.ScaAnalyzer;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class ScaPlugin implements SecurityScannerPlugin {

    @Override public String getId() { return "sca-plugin"; }
    @Override public String getName() { return "SCA Analyzer"; }
    @Override public String getVersion() { return "1.0.0"; }
    @Override public String getProvider() { return "VulneraX"; }
    @Override public List<String> getSupportedTargetTypes() { return List.of("url", "or", "code"); }

    @Override
    public ScanPlan plan(String targetUrl, Map<String, String> options) {
        return new ScanPlan(
            List.of(new ScanStep("sca-1", "DEPENDENCY_CHECK", "Analyze dependencies", options)),
            Map.of("engine", "regex", "focus", "CVE")
        );
    }

    @Override
    public List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options) {
        String content = options.getOrDefault("fileContent", targetUrl);
        String fileName = options.getOrDefault("fileName", "unknown");
        List<Map<String, Object>> results = ScaAnalyzer.analyze(content, fileName);

        return results.stream().map(r -> {
            Finding f = new Finding();
            f.setTitle((String) r.get("title"));
            f.setDescription("Vulnerable dependency " + r.get("component") + " " + r.get("installedVersion"));
            f.setType("SCA");
            f.setSeverity((String) r.get("severity"));
            f.setConfidence("HIGH");
            f.setCwe("CWE-1104");
            f.setCveId(r.get("cve") != null ? r.get("cve").toString() : null);
            f.setFilePath((String) r.get("file"));
            f.setCvss((Double) r.get("cvss"));
            f.setEpss((Double) r.get("epss"));
            f.setKev((Boolean) r.get("kev"));
            f.setRecommendation("Update to " + r.get("fixedVersion"));
            f.setSource("sca-analyzer");
            f.setBusinessCriticality("HIGH");
            f.setOwner("Platform Team");
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
