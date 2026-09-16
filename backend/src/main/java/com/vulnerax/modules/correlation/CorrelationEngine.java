package com.vulnerax.modules.correlation;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class CorrelationEngine {
    private final FindingRepository findingRepo;

    public List<CorrelatedFinding> correlate(UUID projectId) {
        List<Finding> allFindings = projectId != null ? findingRepo.findByProjectId(projectId) : findingRepo.findAll();
        List<CorrelatedFinding> correlated = new ArrayList<>();

        for (Finding f : allFindings) {
            List<CorrelatedFinding.Related> related = findRelated(f, allFindings);
            correlated.add(new CorrelatedFinding(
                    f.getId(), f.getTitle(), f.getFindingType(), f.getCwe(), f.getSeverity(),
                    f.getAssetName(), f.getSource(),
                    related,
                    calculateCorrelationStrength(related.size()),
                    generateCorrelationInsight(f, related)
            ));
        }
        return correlated;
    }

    private List<CorrelatedFinding.Related> findRelated(Finding target, List<Finding> all) {
        List<CorrelatedFinding.Related> related = new ArrayList<>();
        for (Finding f : all) {
            if (f.getId().equals(target.getId())) continue;
            if (!isRelated(target, f)) continue;

            String reason = determineRelationReason(target, f);
            related.add(new CorrelatedFinding.Related(f.getId(), f.getTitle(), f.getFindingType(), f.getSeverity(), reason));
        }
        return related;
    }

    private boolean isRelated(Finding a, Finding b) {
        // Same CWE
        if (a.getCwe() != null && a.getCwe().equals(b.getCwe())) return true;
        // Same asset
        if (a.getAssetName() != null && a.getAssetName().equals(b.getAssetName())) return true;
        // Same endpoint
        if (a.getFilePath() != null && a.getFilePath().equals(b.getFilePath())) return true;
        // DAST + SAST correlation: same path, different evidence
        if ("DAST".equals(a.getSource()) && "SAST".equals(b.getSource())) {
            if (a.getFilePath() != null && b.getFilePath() != null &&
                b.getFilePath().contains(a.getFilePath())) return true;
        }
        return false;
    }

    private String determineRelationReason(Finding a, Finding b) {
        if (a.getCwe() != null && a.getCwe().equals(b.getCwe())) return "Same vulnerability type (CWE)";
        if (a.getAssetName() != null && a.getAssetName().equals(b.getAssetName())) return "Same asset";
        if (a.getFilePath() != null && a.getFilePath().equals(b.getFilePath())) return "Same endpoint";
        return "Related finding";
    }

    private String calculateCorrelationStrength(int relatedCount) {
        if (relatedCount >= 5) return "HIGH";
        if (relatedCount >= 2) return "MODERATE";
        return "LOW";
    }

    private String generateCorrelationInsight(Finding target, List<CorrelatedFinding.Related> related) {
        if (related.isEmpty()) return "No related findings";
        long sameCwe = related.stream().filter(r -> "Same vulnerability type (CWE)".equals(r.reason())).count();
        long sameAsset = related.stream().filter(r -> "Same asset".equals(r.reason())).count();
        if (sameCwe > 0) return "Multiple instances of " + target.getCwe() + " detected";
        if (sameAsset > 0) return "Multiple findings on same asset";
        return "Cross-scanner correlation detected";
    }

    public record CorrelatedFinding(
            UUID findingId, String title, String findingType, String cwe, String severity,
            String assetName, String source,
            List<Related> related, String correlationStrength, String insight
    ) {
        public record Related(UUID findingId, String title, String findingType, String severity, String reason) {}
    }
}
