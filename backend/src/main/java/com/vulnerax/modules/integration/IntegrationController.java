package com.vulnerax.modules.integration;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/integrations") @RequiredArgsConstructor
public class IntegrationController {
    private final IntegrationService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody Integration e){ return ApiResponse.ok(svc.create(e)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID organizationId){ return ApiResponse.ok(svc.list(organizationId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
    @PostMapping("/{id}/test") public ApiResponse<?> test(@PathVariable UUID id){ return ApiResponse.ok(svc.testConnection(id)); }
}
