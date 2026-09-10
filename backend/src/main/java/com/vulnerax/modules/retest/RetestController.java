package com.vulnerax.modules.retest;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/retests") @RequiredArgsConstructor
public class RetestController {
    private final RetestService svc;
    @PostMapping public ApiResponse<?> request(@RequestBody Retest r){ return ApiResponse.ok(svc.request(r)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
