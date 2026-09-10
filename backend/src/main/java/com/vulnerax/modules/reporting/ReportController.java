package com.vulnerax.modules.reporting;

import com.vulnerax.common.ApiResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/reports")
@RequiredArgsConstructor
public class ReportController {
    private final ReportService service;

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(service.list(projectId)); }

    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(service.get(id)); }

    @PostMapping("/generate")
    public ApiResponse<?> generate(@RequestBody GenReq req) { return ApiResponse.ok(service.generate(req.getProjectId(), req.getType(), req.getTitle(), req.getFormat())); }

    @GetMapping("/{id}/export")
    public ApiResponse<?> export(@PathVariable UUID id, @RequestParam(required = false) String format) { return ApiResponse.ok(service.export(id, format)); }

    @Data public static class GenReq { private UUID projectId; private String type; private String title; private String format; }
}
