package com.vulnerax.modules.cloud;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/cloud") @RequiredArgsConstructor
public class CloudController {
    private final CloudService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody CloudResource c){ return ApiResponse.ok(svc.create(c)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
    @PostMapping("/scan") public ApiResponse<?> scan(@RequestParam UUID projectId){ return ApiResponse.ok(svc.scanMock(projectId)); }
}
