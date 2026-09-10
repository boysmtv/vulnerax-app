package com.vulnerax.modules.network;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/network") @RequiredArgsConstructor
public class NetworkController {
    private final NetworkService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody NetworkAsset e){ return ApiResponse.ok(svc.create(e)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
}
