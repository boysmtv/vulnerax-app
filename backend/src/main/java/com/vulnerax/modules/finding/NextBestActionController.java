package com.vulnerax.modules.finding;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/findings/actions") @RequiredArgsConstructor
public class NextBestActionController {
    private final NextBestActionService nextBestActionService;

    @GetMapping
    public ResponseEntity<List<NextBestActionService.NextBestAction>> getActions(@RequestParam(required = false) UUID projectId) {
        return ResponseEntity.ok(nextBestActionService.getActions(projectId));
    }
}
