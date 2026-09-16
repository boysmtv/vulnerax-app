package com.vulnerax.modules.reporting;

import com.vulnerax.common.ApiResponse;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity<byte[]> export(@PathVariable UUID id, @RequestParam(required = false, defaultValue = "JSON") String format) {
        Report r = service.get(id);
        String content = r.getContentJson() != null ? r.getContentJson() : "{}";
        String filename = (r.getTitle() != null ? r.getTitle().replaceAll("[^a-zA-Z0-9]", "_") : id.toString()) + "." + format.toLowerCase();
        byte[] bytes = content.getBytes();

        String contentType = switch (format.toUpperCase()) {
            case "PDF" -> "application/pdf";
            case "HTML" -> "text/html";
            case "CSV" -> "text/csv";
            case "SARIF" -> "application/sarif+json";
            default -> "application/json";
        };

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.parseMediaType(contentType))
                .body(bytes);
    }

    @Data public static class GenReq { private UUID projectId; private String type; private String title; private String format; }
}
