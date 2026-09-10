package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Unified Risk Engine - Contextual Risk 0-100
 * Conceptual: Technical Severity + Threat Likelihood + Asset Criticality + Exposure + Business Impact + Reachability - Compensating Controls = Contextual Risk
 * Factors: CVSS, EPSS, KEV, Asset Criticality, Business Impact, Internet Exposure, Reachability, Exploit Prereq, Auth, Data Sensitivity, Env, Controls, Confidence, Attack Path, Age
 */
@Component
public class RiskEngine {

    public double calculate(Finding f) {
        double cvssScore = f.getCvss() != null ? (f.getCvss() / 10.0) * 30 : 15; // up to 30

        double epssScore = 0;
        if (f.getEpss() != null) epssScore = f.getEpss() * 15; // up to 15
        if (Boolean.TRUE.equals(f.getKev())) epssScore += 12; // KEV bonus

        double criticalityScore = switch (f.getBusinessCriticality() != null ? f.getBusinessCriticality() : "MEDIUM") {
            case "CRITICAL" -> 15;
            case "HIGH" -> 10;
            case "MEDIUM" -> 5;
            default -> 2;
        };

        double exposureScore = 0;
        if (Boolean.TRUE.equals(f.getInternetExposed())) exposureScore += 12;
        if (Boolean.TRUE.equals(f.getReachable())) exposureScore += 8;
        if ("PRODUCTION".equalsIgnoreCase(f.getEnvironment())) exposureScore += 5;

        double confidenceScore = switch (f.getConfidence() != null ? f.getConfidence() : "MEDIUM") {
            case "CONFIRMED" -> 5;
            case "HIGH" -> 3;
            case "MEDIUM" -> 0;
            case "LOW" -> -5;
            default -> 0;
        };

        // severity weight
        double severityScore = switch (f.getSeverity() != null ? f.getSeverity() : "MEDIUM") {
            case "CRITICAL" -> 10;
            case "HIGH" -> 7;
            case "MEDIUM" -> 3;
            case "LOW" -> 1;
            default -> 0;
        };

        // Age factor: older open findings slightly higher risk
        double ageScore = 0;
        if (f.getCreatedAt() != null) {
            long days = ChronoUnit.DAYS.between(f.getCreatedAt(), Instant.now());
            if (days > 30) ageScore = Math.min(5, days / 30.0);
        }

        double total = cvssScore + epssScore + criticalityScore + exposureScore + confidenceScore + severityScore + ageScore;
        // cap 0-100
        total = Math.max(0, Math.min(100, total));
        return Math.round(total * 10.0) / 10.0;
    }

    public String level(double score) {
        if (score >= 81) return "CRITICAL";
        if (score >= 61) return "VERY_HIGH";
        if (score >= 41) return "HIGH";
        if (score >= 21) return "MODERATE";
        return "LOW";
    }

    public void enrich(Finding f) {
        double score = calculate(f);
        f.setRiskScore(score);
        f.setRiskLevel(level(score));
        // SLA due: Critical 24h, High 7d, Medium 30d, Low 90d, Info 90d with adjustment for CRITICAL risk
        int slaDays = switch (f.getSeverity() != null ? f.getSeverity() : "MEDIUM") {
            case "CRITICAL" -> 1;
            case "HIGH" -> 7;
            case "MEDIUM" -> 30;
            default -> 90;
        };
        if (score >= 81) slaDays = Math.min(slaDays, 1);
        else if (score >= 61) slaDays = Math.min(slaDays, 3);
        f.setSlaDueAt(Instant.now().plus(slaDays, ChronoUnit.DAYS));
        f.setSlaStatus("WITHIN_SLA");
        // generate fingerprint for dedup: asset+type+cwe+file+line
        String fp = String.format("%s|%s|%s|%s|%s", f.getAssetId(), f.getType(), f.getCwe(), f.getFilePath(), f.getLineNumber());
        f.setFingerprint(Integer.toHexString(fp.hashCode()));
    }
}
