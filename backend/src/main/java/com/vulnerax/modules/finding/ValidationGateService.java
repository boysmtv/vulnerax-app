package com.vulnerax.modules.finding;

import com.vulnerax.modules.evidence.EvidenceChain;
import com.vulnerax.modules.evidence.EvidenceChainRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class ValidationGateService {
    private final EvidenceChainRepository evidenceRepo;

    public ValidationReport validate(UUID findingId, Finding finding) {
        List<String> passed = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // Rule 1: Evidence required for CONFIRMED status
        long confirmedEvidence = evidenceRepo.countByFindingIdAndStatus(findingId, "CONFIRMED");
        if (confirmedEvidence > 0) {
            passed.add("Has confirmed evidence (" + confirmedEvidence + " items)");
        } else if (finding.getVulnerabilityConfirmed() != null && finding.getVulnerabilityConfirmed()) {
            failed.add("Claimed CONFIRMED but no confirmed evidence");
        } else {
            warnings.add("No confirmed evidence yet");
        }

        // Rule 2: CWE must be validated
        if (finding.getCwe() != null && finding.getCwe().matches("CWE-\\d+")) {
            passed.add("CWE formatted correctly: " + finding.getCwe());
        } else if (finding.getVulnerabilityConfirmed() != null && finding.getVulnerabilityConfirmed()) {
            warnings.add("Confirmed vulnerability without CWE assignment");
        }

        // Rule 3: Evidence strength check
        long strongEvidence = evidenceRepo.countByFindingIdAndStatus(findingId, "CONFIRMED");
        if (strongEvidence >= 2) {
            passed.add("Strong evidence (2+ confirmed items)");
        } else if (strongEvidence == 1) {
            warnings.add("Only 1 confirmed evidence item");
        } else if (finding.getVulnerabilityConfirmed() != null && finding.getVulnerabilityConfirmed()) {
            failed.add("No confirmed evidence for vulnerability");
        }

        // Rule 4: Scan issues must not be misclassified
        if ("SCAN_ERROR".equals(finding.getFindingType())) {
            if (finding.getCwe() == null) {
                passed.add("Scan issue correctly without CWE");
            } else {
                failed.add("Scan issue should not have CWE: " + finding.getCwe());
            }
        }

        boolean ready = failed.isEmpty() && confirmedEvidence > 0;
        return new ValidationReport(findingId, ready, passed, failed, warnings);
    }

    public record ValidationReport(UUID findingId, boolean readyForPublish, List<String> passed, List<String> failed, List<String> warnings) {}
}
