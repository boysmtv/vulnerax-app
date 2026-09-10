package com.vulnerax.modules.compliance;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/compliance") @RequiredArgsConstructor
public class ComplianceController {
    private final ComplianceService svc;
    @GetMapping("/frameworks") public ApiResponse<?> fw(){ return ApiResponse.ok(svc.frameworks()); }
    @GetMapping("/frameworks/{id}") public ApiResponse<?> getFw(@PathVariable UUID id){ return ApiResponse.ok(svc.getFramework(id)); }
    @PostMapping("/assess") public ApiResponse<?> assess(@RequestParam UUID projectId, @RequestParam UUID frameworkId){ return ApiResponse.ok(svc.assess(projectId, frameworkId)); }
    @GetMapping("/assessments") public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/assessments/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
