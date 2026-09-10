package com.vulnerax.modules.finding;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/findings")
@RequiredArgsConstructor
public class FindingController {
    private final FindingService service;

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId,
                               @RequestParam(required = false) UUID assetId,
                               @RequestParam(required = false) String severity,
                               @RequestParam(required = false) String status,
                               @RequestParam(required = false) String riskLevel,
                               @RequestParam(required = false) String search,
                               Pageable pageable) {
        return ApiResponse.ok(PageResponse.from(service.list(projectId, assetId, severity, status, riskLevel, search, pageable)));
    }

    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(service.get(id)); }

    @PostMapping
    public ApiResponse<?> create(@RequestBody Finding f) { return ApiResponse.ok(service.create(f)); }

    @PutMapping("/{id}/status")
    public ApiResponse<?> updateStatus(@PathVariable UUID id, @RequestBody StatusReq req) {
        return ApiResponse.ok(service.updateStatus(id, req.getStatus(), req.getComment()));
    }

    @GetMapping("/{id}/evidence")
    public ApiResponse<?> evidences(@PathVariable UUID id) { return ApiResponse.ok(service.evidences(id)); }

    @GetMapping("/{id}/instances")
    public ApiResponse<?> instances(@PathVariable UUID id) { return ApiResponse.ok(service.instances(id)); }

    @GetMapping("/stats")
    public ApiResponse<?> stats(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(service.stats(projectId)); }

    @GetMapping("/{id}/correlation")
    public ApiResponse<?> correlation(@PathVariable UUID id) { return ApiResponse.ok(service.correlation(id)); }

    @Data public static class StatusReq { private String status; private String comment; }
}
