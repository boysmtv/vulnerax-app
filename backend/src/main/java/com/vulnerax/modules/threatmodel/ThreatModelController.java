package com.vulnerax.modules.threatmodel;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/threat-models") @RequiredArgsConstructor
public class ThreatModelController {
    private final ThreatModelService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody ThreatModel m){ return ApiResponse.ok(svc.create(m)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
