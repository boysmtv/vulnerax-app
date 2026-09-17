package com.vulnerax.modules.risk;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/v1/risk") @RequiredArgsConstructor
public class RiskController {
    private final EnrichmentService enrichmentService;

    @PostMapping("/enrich")
    public ResponseEntity<Map<String, Object>> enrich(@RequestBody Map<String, Object> request) {
        // This would be called with a Finding object in production
        // For now, return a basic risk calculation
        double cvss = request.containsKey("cvss") ? ((Number) request.get("cvss")).doubleValue() : 0;
        String severity = Cvss4Calculator.getSeverity(cvss);
        return ResponseEntity.ok(Map.of("severity", severity, "score", cvss));
    }
}
