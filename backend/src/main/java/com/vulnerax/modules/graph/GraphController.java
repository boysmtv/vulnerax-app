package com.vulnerax.modules.graph;

import com.vulnerax.common.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/graph")
@RequiredArgsConstructor
public class GraphController {
    private final SecurityGraphService svc;
    @GetMapping
    public ApiResponse<?> graph(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(svc.graphForProject(projectId)); }
    @GetMapping("/attack-paths")
    public ApiResponse<?> attackPaths(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(svc.attackPaths(projectId)); }
}
