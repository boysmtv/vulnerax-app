package com.vulnerax.modules.finding;

import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

public class FindingCorrelationEngine {

    public static CorrelationResult correlate(Finding newFinding, List<Finding> existingFindings) {
        List<Finding> matches = new ArrayList<>();
        String reason = "NO_MATCH";

        for (Finding existing : existingFindings) {
            if (existing.getId() != null && existing.getId().equals(newFinding.getId())) continue;
            if ("RESOLVED".equals(existing.getStatus()) || "FALSE_POSITIVE".equals(existing.getStatus())) continue;

            double similarity = calculateSimilarity(newFinding, existing);

            if (similarity > 0.95) {
                matches.add(existing);
                reason = "EXACT_MATCH";
                break;
            } else if (similarity > 0.75) {
                matches.add(existing);
                reason = "SIMILAR";
            } else if (similarity > 0.5) {
                matches.add(existing);
                reason = "RELATED";
            }
        }

        boolean isDuplicate = "EXACT_MATCH".equals(reason);
        String mergeRecommendation = isDuplicate ? "MERGE_EVIDENCE" :
                "SIMILAR".equals(reason) ? "LINK_RELATIONSHIPS" : "INDEPENDENT";

        return new CorrelationResult(matches, reason, isDuplicate, mergeRecommendation);
    }

    private static double calculateSimilarity(Finding a, Finding b) {
        double score = 0;

        // Same type = 0.3
        if (a.getType() == b.getType()) score += 0.3;

        // Same title fuzzy = 0.25
        if (a.getTitle() != null && b.getTitle() != null) {
            score += 0.25 * jaroWinkler(a.getTitle(), b.getTitle());
        }

        // Same severity = 0.15
        if (a.getSeverity() == b.getSeverity()) score += 0.15;

        // Same affected URL / asset = 0.2
        if (a.getFilePath() != null && a.getFilePath().equals(b.getFilePath())) score += 0.2;
        else if (a.getAssetId() != null && a.getAssetId().equals(b.getAssetId())) score += 0.15;

        // Same CWE = 0.1
        if (Objects.equals(a.getCweId(), b.getCweId())) score += 0.1;

        // Same source = 0.05
        if (a.getSource() != null && a.getSource().equals(b.getSource())) score += 0.05;

        return score;
    }

    private static double jaroWinkler(String s1, String s2) {
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

        double jaro = (double) matches / len1 + (double) matches / len2 + ((double) matches - transpositions / 2.0) / matches;
        int prefix = 0;
        for (int i = 0; i < Math.min(4, Math.min(len1, len2)); i++) {
            if (s1.charAt(i) == s2.charAt(i)) prefix++;
            else break;
        }
        return jaro + prefix * 0.1 * (1 - jaro);
    }

    public record CorrelationResult(List<Finding> matches, String reason, boolean isDuplicate, String mergeRecommendation) {}
}
