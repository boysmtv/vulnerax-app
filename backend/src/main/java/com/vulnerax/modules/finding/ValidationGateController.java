package com.vulnerax.modules.finding;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/v1/findings/validation") @RequiredArgsConstructor
public class ValidationGateController {
    private final ValidationGateService validationGateService;
    private final FindingService findingService;

    @GetMapping("/{findingId}")
    public ResponseEntity<ValidationGateService.ValidationReport> validate(@PathVariable UUID findingId) {
        Finding f = findingService.get(findingId);
        return ResponseEntity.ok(validationGateService.validate(findingId, f));
    }

    @PostMapping("/{findingId}/publish")
    public ResponseEntity<Map<String, Object>> publish(@PathVariable UUID findingId) {
        Finding f = findingService.get(findingId);
        ValidationGateService.ValidationReport report = validationGateService.validate(findingId, f);
        if (!report.readyForPublish()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Finding not ready for publish",
                    "failed", report.failed(),
                    "warnings", report.warnings()
            ));
        }
        f.setValidated(true);
        f.setReadyForPublish(true);
        findingService.updateStatus(findingId, f.getStatus(), "Validated and published");
        return ResponseEntity.ok(Map.of("status", "PUBLISHED", "findingId", findingId));
    }
}
