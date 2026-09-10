package com.vulnerax.modules.asset;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/assets")
@RequiredArgsConstructor
public class AssetController {
    private final AssetService service;

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId,
                               @RequestParam(required = false) UUID organizationId,
                               @RequestParam(required = false) String type,
                               @RequestParam(required = false) String search,
                               Pageable pageable) {
        return ApiResponse.ok(PageResponse.from(service.list(projectId, organizationId, type, search, pageable)));
    }

    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(service.get(id)); }

    @PostMapping
    public ApiResponse<?> create(@RequestBody Asset a) { return ApiResponse.ok(service.create(a)); }

    @PutMapping("/{id}")
    public ApiResponse<?> update(@PathVariable UUID id, @RequestBody Asset a) { return ApiResponse.ok(service.update(id, a)); }

    @DeleteMapping("/{id}")
    public ApiResponse<?> delete(@PathVariable UUID id) { service.delete(id); return ApiResponse.ok(null, "Deleted"); }

    @GetMapping("/stats")
    public ApiResponse<?> stats(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(service.stats(projectId)); }

    @PostMapping("/discover")
    public ApiResponse<?> discover(@RequestParam UUID projectId, @RequestParam(defaultValue = "MANUAL") String source) {
        return ApiResponse.ok(service.discoverMock(projectId, source));
    }
}
