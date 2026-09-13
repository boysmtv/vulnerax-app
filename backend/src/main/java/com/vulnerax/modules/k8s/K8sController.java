package com.vulnerax.modules.k8s;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController @RequestMapping("/api/v1/k8s") @RequiredArgsConstructor
public class K8sController {
    private final K8sRepository repo;

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required=false) UUID projectId) {
        var items = projectId != null ? repo.findByProjectId(projectId) : repo.findAll();
        return ApiResponse.ok(items);
    }

    @PostMapping
    public ApiResponse<?> create(@RequestBody K8sResource r) {
        return ApiResponse.ok(repo.save(r));
    }

    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) {
        return ApiResponse.ok(repo.findById(id));
    }
}
