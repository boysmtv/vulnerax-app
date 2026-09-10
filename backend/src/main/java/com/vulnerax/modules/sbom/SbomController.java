package com.vulnerax.modules.sbom;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/sboms") @RequiredArgsConstructor
public class SbomController {
    private final SbomService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody Sbom s) { return ApiResponse.ok(svc.create(s)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(svc.get(id)); }
    @GetMapping("/diff") public ApiResponse<?> diff(@RequestParam UUID a, @RequestParam UUID b) { return ApiResponse.ok(svc.diff(a,b)); }
}
