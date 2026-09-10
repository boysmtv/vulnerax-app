package com.vulnerax.modules.coverage;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/coverage") @RequiredArgsConstructor
public class CoverageController {
    private final CoverageService svc;
    @PostMapping public ApiResponse<?> upsert(@RequestBody SecurityCoverage c){ return ApiResponse.ok(svc.upsert(c)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/summary") public ApiResponse<?> summary(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.summary(projectId)); }
}
