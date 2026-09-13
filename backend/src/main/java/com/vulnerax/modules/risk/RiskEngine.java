package com.vulnerax.modules.risk;

import com.vulnerax.modules.finding.Finding;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * Unified Risk Engine - Contextual Risk 0-100
 * Multiplicative interactions: threat * asset_criticality * exposure * confidence + modifiers
 */
@Component
public class RiskEngine {

    private static final Map<String, Double> SEVERITY_WEIGHT = Map.of(
            "CRITICAL", 10.0, "HIGH", 7.0, "MEDIUM", 3.0, "LOW", 1.0, "INFO", 0.0);

    private static final Map<String, Double> CRITICALITY_WEIGHT = Map.of(
            "CRITICAL", 15.0, "HIGH", 10.0, "MEDIUM", 5.0, "LOW", 2.0);

    private static final Map<String, Double> CONFIDENCE_WEIGHT = Map.of(
            "CONFIRMED", 5.0, "HIGH", 3.0, "MEDIUM", 0.0, "LOW", -5.0);

    private static final Map<String, Double> DATA_CLASSIFICATION_BONUS = Map.of(
            "PUBLIC", 0.0, "INTERNAL", 2.0, "CONFIDENTIAL", 5.0, "RESTRICTED", 10.0);

    public double calculate(Finding f) {
        double cvssScore = f.getCvss() != null ? (f.getCvss() / 10.0) * 30 : 15;

        double epssScore = 0;
        if (f.getEpss() != null) epssScore = f.getEpss() * 15;
        if (Boolean.TRUE.equals(f.getKev())) epssScore += 12;

        double criticalityScore = CRITICALITY_WEIGHT.getOrDefault(
                f.getBusinessCriticality() != null ? f.getBusinessCriticality() : "MEDIUM", 5.0);

        double exposureScore = 0;
        if (Boolean.TRUE.equals(f.getInternetExposed())) exposureScore += 12;
        if (Boolean.TRUE.equals(f.getReachable())) exposureScore += 8;
        if ("PRODUCTION".equalsIgnoreCase(f.getEnvironment())) exposureScore += 5;

        double confidenceScore = CONFIDENCE_WEIGHT.getOrDefault(
                f.getConfidence() != null ? f.getConfidence() : "MEDIUM", 0.0);

        double severityScore = SEVERITY_WEIGHT.getOrDefault(
                f.getSeverity() != null ? f.getSeverity() : "MEDIUM", 3.0);

        // Data classification modifier
        double classificationBonus = DATA_CLASSIFICATION_BONUS.getOrDefault(
                f.getBusinessCriticality() != null ? f.getBusinessCriticality() : "MEDIUM", 2.0);

        // Compensating control deduction
        double compensatingDeduction = 0;
        if (f.getCompensatingControl() != null && !f.getCompensatingControl().isBlank()) {
            compensatingDeduction = 5.0; // WAF, IPS, or other compensating controls
        }

        // Age factor: older open findings slightly higher risk
        double ageScore = 0;
        if (f.getCreatedAt() != null) {
            long days = ChronoUnit.DAYS.between(f.getCreatedAt(), Instant.now());
            if (days > 30) ageScore = Math.min(5, days / 30.0);
        }

        // Multiplicative interaction: (threat * asset * exposure) with modifiers
        double threatComponent = cvssScore + epssScore + severityScore;
        double assetComponent = criticalityScore + confidenceScore + classificationBonus;
        double exposureComponent = exposureScore + ageScore;

        // Interaction: high threat + high asset + high exposure = exponential
        double multiplicative = (threatComponent * assetComponent * exposureComponent) / 100.0;

        double total = multiplicative + threatComponent + assetComponent + exposureComponent
                - compensatingDeduction;
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

        String sev = f.getSeverity() != null ? f.getSeverity() : "MEDIUM";
        int slaDays;
        switch (sev) {
            case "CRITICAL": slaDays = 1; break;
            case "HIGH": slaDays = 7; break;
            case "MEDIUM": slaDays = 30; break;
            default: slaDays = 90; break;
        }
        if (score >= 81) slaDays = Math.min(slaDays, 1);
        else if (score >= 61) slaDays = Math.min(slaDays, 3);
        f.setSlaDueAt(Instant.now().plus(slaDays, ChronoUnit.DAYS));
        f.setSlaStatus("WITHIN_SLA");

        // SHA-256 fingerprint to eliminate collision risk
        String fp = String.format("%s|%s|%s|%s|%s|%s",
                f.getAssetId(), f.getType(), f.getCwe(), f.getCweId(), f.getFilePath(), f.getLineNumber());
        f.setFingerprint(sha256(fp));
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(input.hashCode());
        }
    }
}
