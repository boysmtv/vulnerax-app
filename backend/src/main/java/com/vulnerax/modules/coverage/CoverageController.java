package com.vulnerax.modules.coverage;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/coverage") @RequiredArgsConstructor
public class CoverageController {
    private final CoverageEngine coverageEngine;

    @GetMapping
    public ResponseEntity<CoverageEngine.CoverageReport> getCoverage(@RequestParam(required = false) UUID projectId) {
        return ResponseEntity.ok(coverageEngine.calculate(projectId));
    }
}
