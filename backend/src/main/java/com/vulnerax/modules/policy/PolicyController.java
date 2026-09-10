package com.vulnerax.modules.policy;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/policies") @RequiredArgsConstructor
public class PolicyController {
    private final PolicyService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody SecurityPolicy p){ return ApiResponse.ok(svc.create(p)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID organizationId){ return ApiResponse.ok(svc.list(organizationId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
    @GetMapping("/defaults") public ApiResponse<?> defaults(@RequestParam(required=false) UUID organizationId){ return ApiResponse.ok(svc.defaults(organizationId)); }
    @PostMapping("/{id}/evaluate") public ApiResponse<?> evaluate(@PathVariable UUID id, @RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.evaluate(id, projectId)); }
    @PostMapping("/exceptions") public ApiResponse<?> createEx(@RequestBody PolicyException e){ return ApiResponse.ok(svc.createException(e)); }
    @GetMapping("/{id}/exceptions") public ApiResponse<?> listEx(@PathVariable UUID id){ return ApiResponse.ok(svc.listExceptions(id)); }
}
