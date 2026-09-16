package com.vulnerax.modules.classification;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/classification") @RequiredArgsConstructor
public class ClassificationController {
    private final ClassificationEngine engine;

    @PostMapping("/classify")
    public ResponseEntity<ClassificationEngine.Classification> classify(@RequestBody Map<String, Object> observation) {
        return ResponseEntity.ok(engine.classify(observation));
    }
}
