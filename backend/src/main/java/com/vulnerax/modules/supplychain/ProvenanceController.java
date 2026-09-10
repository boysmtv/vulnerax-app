package com.vulnerax.modules.supplychain;
import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;
@RestController @RequestMapping("/api/v1/provenance") @RequiredArgsConstructor
public class ProvenanceController {
    private final ProvenanceService svc;
    @PostMapping public ApiResponse<?> create(@RequestBody ArtifactProvenance e){ return ApiResponse.ok(svc.create(e)); }
    @GetMapping public ApiResponse<?> list(@RequestParam(required=false) UUID projectId){ return ApiResponse.ok(svc.list(projectId)); }
    @GetMapping("/{id}") public ApiResponse<?> get(@PathVariable UUID id){ return ApiResponse.ok(svc.get(id)); }
    @PostMapping("/{id}/verify") public ApiResponse<?> verify(@PathVariable UUID id){ return ApiResponse.ok(svc.verify(id)); }
}
