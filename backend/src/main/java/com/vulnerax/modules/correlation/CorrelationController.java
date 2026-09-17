package com.vulnerax.modules.correlation;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/v1/correlation") @RequiredArgsConstructor
public class CorrelationController {
    private final CorrelationEngine correlationEngine;

    @GetMapping
    public ResponseEntity<List<CorrelationEngine.CorrelatedFinding>> correlate(@RequestParam(required = false) UUID projectId) {
        return ResponseEntity.ok(correlationEngine.correlate(projectId));
    }
}
