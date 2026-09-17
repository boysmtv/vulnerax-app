package com.vulnerax.modules.finding;

import com.vulnerax.modules.evidence.EvidenceChainService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/v1/findings/retest") @RequiredArgsConstructor
public class FindingRetestController {
    private final FindingService findingService;
    private final EvidenceChainService evidenceService;
    private final ValidationGateService validationGateService;

    @PostMapping("/{findingId}")
    public ResponseEntity<Map<String, Object>> retest(
            @PathVariable UUID findingId,
            @RequestBody Map<String, Object> request) {
        Finding f = findingService.get(findingId);
        int successes = (int) request.getOrDefault("successes", 0);
        int attempts = (int) request.getOrDefault("attempts", 1);

        // Record retest evidence
        evidenceService.recordReproduction(findingId, f.getScanId(), successes, attempts);

        // Update finding status
        double confidence = attempts > 0 ? (double) successes / attempts : 0;
        if (successes > 0 && confidence >= 0.5) {
            f.setVulnerabilityConfirmed(true);
            f.setStatus("CONFIRMED");
            f.setFindingType("VULNERABILITY");
        } else if (successes == 0) {
            f.setVulnerabilityConfirmed(false);
            f.setStatus("FALSE_POSITIVE");
        }

        // Validate gate
        ValidationGateService.ValidationReport validation = validationGateService.validate(findingId, f);

        findingService.update(f);

        return ResponseEntity.ok(Map.of(
                "findingId", findingId,
                "newStatus", f.getStatus(),
                "confidence", confidence,
                "validation", validation
        ));
    }
}
