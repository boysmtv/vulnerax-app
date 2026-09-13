package com.vulnerax.modules.finding;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class FindingCorrelationEngine {

    private static final double MAX_WEIGHT = 1.05;
    private static final long TEMPORAL_WINDOW_DAYS = 90;

    public CorrelationResult correlate(Finding newFinding, List<Finding> existingFindings) {
        List<Finding> matches = new ArrayList<>();
        String reason = "NO_MATCH";

        for (Finding existing : existingFindings) {
            if (existing.getId() != null && existing.getId().equals(newFinding.getId())) continue;
            if ("RESOLVED".equals(existing.getStatus()) || "FALSE_POSITIVE".equals(existing.getStatus())) continue;

            double similarity = calculateSimilarity(newFinding, existing);

            if (similarity > 0.90) {
                matches.add(existing);
                reason = "EXACT_MATCH";
            } else if (similarity > 0.70) {
                matches.add(existing);
                reason = "SIMILAR".equals(reason) || "EXACT_MATCH".equals(reason) ? reason : "SIMILAR";
            } else if (similarity > 0.50) {
                matches.add(existing);
                if (!"EXACT_MATCH".equals(reason) && !"SIMILAR".equals(reason)) reason = "RELATED";
            }
        }

        boolean isDuplicate = "EXACT_MATCH".equals(reason);
        String mergeRecommendation = isDuplicate ? "MERGE_EVIDENCE" :
                "SIMILAR".equals(reason) ? "LINK_RELATIONSHIPS" : "INDEPENDENT";

        return new CorrelationResult(matches, reason, isDuplicate, mergeRecommendation);
    }

    private double calculateSimilarity(Finding a, Finding b) {
        double score = 0;

        // Same type = 0.25
        if (Objects.equals(a.getType(), b.getType())) score += 0.25;

        // Same title fuzzy = 0.25
        if (a.getTitle() != null && b.getTitle() != null) {
            score += 0.25 * jaroWinkler(a.getTitle(), b.getTitle());
        }

        // Same severity = 0.10
        if (Objects.equals(a.getSeverity(), b.getSeverity())) score += 0.10;

        // Same file path (fuzzy for URLs) = 0.15
        if (a.getFilePath() != null && b.getFilePath() != null) {
            if (a.getFilePath().equals(b.getFilePath())) {
                score += 0.15;
            } else {
                score += 0.15 * jaroWinkler(a.getFilePath(), b.getFilePath()) * 0.5;
            }
        } else if (a.getAssetId() != null && a.getAssetId().equals(b.getAssetId())) {
            score += 0.10;
        }

        // Same CWE (use cweId with fallback to cwe) = 0.15
        String aCwe = a.getCweId() != null ? a.getCweId() : a.getCwe();
        String bCwe = b.getCweId() != null ? b.getCweId() : b.getCwe();
        if (Objects.equals(aCwe, bCwe) && aCwe != null) score += 0.15;

        // Same source = 0.05
        if (Objects.equals(a.getSource(), b.getSource())) score += 0.05;

        // Same scan = 0.05
        if (Objects.equals(a.getScanId(), b.getScanId())) score += 0.05;

        // Temporal decay: findings within 90 days get bonus, older ones penalized
        if (a.getCreatedAt() != null && b.getCreatedAt() != null) {
            long daysBetween = Math.abs(ChronoUnit.DAYS.between(a.getCreatedAt(), b.getCreatedAt()));
            if (daysBetween <= 7) score += 0.05;
            else if (daysBetween <= 30) score += 0.03;
            else if (daysBetween <= TEMPORAL_WINDOW_DAYS) score += 0.01;
            else score -= 0.02; // penalize old correlations
        }

        // Normalize to 0-1 range
        return Math.max(0, Math.min(1.0, score / MAX_WEIGHT));
    }

    private double jaroWinkler(String s1, String s2) {
        if (s1.equals(s2)) return 1.0;
        int len1 = s1.length(), len2 = s2.length();
        if (len1 == 0 || len2 == 0) return 0.0;

        int matchDistance = Math.max(len1, len2) / 2 - 1;
        boolean[] s1Matches = new boolean[len1];
        boolean[] s2Matches = new boolean[len2];

        int matches = 0, transpositions = 0;
        for (int i = 0; i < len1; i++) {
            int start = Math.max(0, i - matchDistance);
            int end = Math.min(i + matchDistance + 1, len2);
            for (int j = start; j < end; j++) {
                if (s2Matches[j] || s1.charAt(i) != s2.charAt(j)) continue;
                s1Matches[i] = true;
                s2Matches[j] = true;
                matches++;
                break;
            }
        }
        if (matches == 0) return 0.0;

        int k = 0;
        for (int i = 0; i < len1; i++) {
            if (!s1Matches[i]) continue;
            while (!s2Matches[k]) k++;
            if (s1.charAt(i) != s2.charAt(k)) transpositions++;
            k++;
        }

        double jaro = (double) matches / len1 + (double) matches / len2 +
                ((double) matches - transpositions / 2.0) / matches;
        int prefix = 0;
        for (int i = 0; i < Math.min(4, Math.min(len1, len2)); i++) {
            if (s1.charAt(i) == s2.charAt(i)) prefix++;
            else break;
        }
        return jaro + prefix * 0.1 * (1 - jaro);
    }

    public record CorrelationResult(List<Finding> matches, String reason, boolean isDuplicate, String mergeRecommendation) {}
}
