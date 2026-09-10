package com.vulnerax.modules.container;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/containers") @RequiredArgsConstructor
public class ContainerController {
    private final ContainerService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody ContainerImage c){ return ApiResponse.ok(svc.create(c)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
    @PostMapping("/scan") public ApiResponse<?> scan(@RequestParam UUID projectId){ return ApiResponse.ok(svc.scanMock(projectId)); }
}
