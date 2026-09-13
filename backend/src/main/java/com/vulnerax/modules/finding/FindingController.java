package com.vulnerax.modules.finding;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.common.PageResponse;
import com.vulnerax.modules.rbac.RequirePermission;
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
    @RequirePermission("FINDINGS_READ")
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
    @RequirePermission("FINDINGS_READ")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(service.get(id)); }

    @PostMapping
    @RequirePermission("FINDINGS_WRITE")
    public ApiResponse<?> create(@RequestBody Finding f) { return ApiResponse.ok(service.create(f)); }

    @PutMapping("/{id}/status")
    @RequirePermission("FINDINGS_APPROVE")
    public ApiResponse<?> updateStatus(@PathVariable UUID id, @RequestBody StatusReq req) {
        return ApiResponse.ok(service.updateStatus(id, req.getStatus(), req.getComment()));
    }

    @GetMapping("/{id}/evidence")
    @RequirePermission("FINDINGS_READ")
    public ApiResponse<?> evidences(@PathVariable UUID id) { return ApiResponse.ok(service.evidences(id)); }

    @GetMapping("/{id}/instances")
    @RequirePermission("FINDINGS_READ")
    public ApiResponse<?> instances(@PathVariable UUID id) { return ApiResponse.ok(service.instances(id)); }

    @GetMapping("/stats")
    @RequirePermission("FINDINGS_READ")
    public ApiResponse<?> stats(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(service.stats(projectId)); }

    @GetMapping("/{id}/correlation")
    @RequirePermission("FINDINGS_READ")
    public ApiResponse<?> correlation(@PathVariable UUID id) { return ApiResponse.ok(service.correlation(id)); }

    @Data public static class StatusReq { private String status; private String comment; }
}
