package com.vulnerax.modules.finding;

import com.vulnerax.modules.correlation.CorrelationEngine;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class NextBestActionService {
    private final CorrelationEngine correlationEngine;

    public List<NextBestAction> getActions(UUID projectId) {
        List<CorrelationEngine.CorrelatedFinding> correlated = correlationEngine.correlate(projectId);
        List<NextBestAction> actions = new ArrayList<>();

        for (CorrelationEngine.CorrelatedFinding cf : correlated) {
            if ("VULNERABILITY".equals(cf.findingType()) && "HIGH".equals(cf.severity())) {
                actions.add(new NextBestAction(
                        cf.findingId(), "TRIAGE", "HIGH",
                        "Critical vulnerability: " + cf.title(),
                        "Manual triage required for high-severity finding"
                ));
            }
            if ("SCAN_ERROR".equals(cf.findingType())) {
                actions.add(new NextBestAction(
                        cf.findingId(), "RETEST", "MEDIUM",
                        "Retest scan issue: " + cf.title(),
                        "Scan connectivity issue - manual verification needed"
                ));
            }
            if (cf.correlationStrength().equals("HIGH")) {
                actions.add(new NextBestAction(
                        cf.findingId(), "INVESTIGATE", "MEDIUM",
                        "Multiple related findings detected for " + cf.title(),
                        "Correlated findings suggest systemic issue"
                ));
            }
        }

        // Add coverage gap actions
        actions.add(new NextBestAction(
                UUID.randomUUID(), "EXPAND_COVERAGE", "MEDIUM",
                "Add more endpoints to scan scope",
                "Increase test coverage to detect hidden vulnerabilities"
        ));

        return actions;
    }

    public record NextBestAction(UUID findingId, String action, String priority, String description, String reason) {}
}
