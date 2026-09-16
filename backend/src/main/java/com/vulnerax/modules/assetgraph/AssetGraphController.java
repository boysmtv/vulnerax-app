package com.vulnerax.modules.assetgraph;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController @RequestMapping("/api/asset-graph") @RequiredArgsConstructor
public class AssetGraphController {
    private final AssetGraphEngine assetGraphEngine;

    @GetMapping
    public ResponseEntity<AssetGraphEngine.AssetGraph> getGraph(@RequestParam(required = false) UUID projectId) {
        return ResponseEntity.ok(assetGraphEngine.buildGraph(projectId));
    }
}
