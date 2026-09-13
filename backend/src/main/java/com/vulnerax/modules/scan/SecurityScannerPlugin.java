package com.vulnerax.modules.scan;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingType;
import java.util.List;
import java.util.Map;

public interface SecurityScannerPlugin {
    String getId();
    String getName();
    String getVersion();
    String getProvider();
    List<String> getSupportedTargetTypes();

    ScanPlan plan(String targetUrl, Map<String, String> options);
    List<Finding> execute(String targetUrl, ScanPlan plan, Map<String, String> options);
    Finding normalize(Finding raw, Map<String, String> options);
    ValidationResult validate(Finding finding);

    record ScanPlan(List<ScanStep> steps, Map<String, Object> metadata) {}
    record ScanStep(String id, String type, String description, Map<String, String> config) {}
    record ValidationResult(boolean valid, String reason) {}

    default boolean supports(String targetType) {
        return getSupportedTargetTypes().contains(targetType) || getSupportedTargetTypes().contains("*");
    }

    default String getSecurityLevel() { return "SAFE"; }
}
