package com.vulnerax.modules.cicd;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/cicd") @RequiredArgsConstructor
public class CicdController {
    private final CicdService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody CicdPipeline e){ return ApiResponse.ok(svc.create(e)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
