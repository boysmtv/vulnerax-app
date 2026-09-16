package com.vulnerax.modules.evidence;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/evidence") @RequiredArgsConstructor
public class EvidenceController {
    private final EvidenceChainService evidenceService;

    @GetMapping("/{findingId}/summary")
    public ResponseEntity<Map<String, Object>> getSummary(@PathVariable UUID findingId) {
        return ResponseEntity.ok(evidenceService.getEvidenceSummary(findingId));
    }

    @PostMapping("/{findingId}/dns")
    public ResponseEntity<EvidenceChain> recordDns(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID scanId,
            @RequestParam boolean resolved,
            @RequestParam String addresses) {
        return ResponseEntity.ok(evidenceService.recordDns(findingId, scanId, resolved, addresses));
    }

    @PostMapping("/{findingId}/tcp")
    public ResponseEntity<EvidenceChain> recordTcp(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID scanId,
            @RequestParam boolean connected,
            @RequestParam int port,
            @RequestParam(required = false) String error) {
        return ResponseEntity.ok(evidenceService.recordTcp(findingId, scanId, connected, port, error));
    }

    @PostMapping("/{findingId}/http")
    public ResponseEntity<EvidenceChain> recordHttp(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID scanId,
            @RequestParam int statusCode,
            @RequestParam(required = false) String headers,
            @RequestParam(required = false) String bodySnippet) {
        return ResponseEntity.ok(evidenceService.recordHttp(findingId, scanId, statusCode, headers, bodySnippet));
    }

    @PostMapping("/{findingId}/payload")
    public ResponseEntity<EvidenceChain> recordPayload(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID scanId,
            @RequestParam String payload,
            @RequestParam int responseCode,
            @RequestParam(required = false) String responseSnippet,
            @RequestParam boolean matched) {
        return ResponseEntity.ok(evidenceService.recordPayload(findingId, scanId, payload, responseCode, responseSnippet, matched));
    }

    @PostMapping("/{findingId}/retest")
    public ResponseEntity<EvidenceChain> recordReproduction(
            @PathVariable UUID findingId,
            @RequestParam(required = false) UUID scanId,
            @RequestParam int successes,
            @RequestParam int attempts) {
        return ResponseEntity.ok(evidenceService.recordReproduction(findingId, scanId, successes, attempts));
    }
}
