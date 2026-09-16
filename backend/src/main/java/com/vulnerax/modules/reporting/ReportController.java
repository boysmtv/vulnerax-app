package com.vulnerax.modules.reporting;

import com.vulnerax.common.ApiResponse;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.report.ReportService;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanRepository;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/reports")
@RequiredArgsConstructor
public class ReportController {
    private final ReportService service;
    private final com.vulnerax.modules.reporting.ReportService reportingService;
    private final ScanRepository scanRepo;
    private final FindingRepository findingRepo;
    private final com.vulnerax.modules.finding.FindingService findingService;

    @GetMapping
    public ApiResponse<?> list(@RequestParam(required = false) UUID projectId) { return ApiResponse.ok(reportingService.list(projectId)); }

    @GetMapping("/{id}")
    public ApiResponse<?> get(@PathVariable UUID id) { return ApiResponse.ok(reportingService.get(id)); }

    @PostMapping("/generate")
    public ApiResponse<?> generate(@RequestBody GenReq req) { return ApiResponse.ok(reportingService.generate(req.getProjectId(), req.getType(), req.getTitle(), req.getFormat())); }

    @GetMapping("/{id}/export")
    public ResponseEntity<byte[]> export(@PathVariable UUID id, @RequestParam(required = false, defaultValue = "JSON") String format) {
        com.vulnerax.modules.reporting.Report r = reportingService.get(id);
        String filename = (r.getTitle() != null ? r.getTitle().replaceAll("[^a-zA-Z0-9]", "_") : id.toString());

        if ("PDF".equalsIgnoreCase(format)) {
            List<Scan> scans = scanRepo.findAll();
            Scan scan = scans.isEmpty() ? Scan.builder().target(filename).build() : scans.get(0);
            List<Finding> findings = findingRepo.findAll().stream().limit(100).toList();
            try {
                byte[] pdf = service.generatePdf(scan, findings, "pdf");
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + ".pdf\"")
                        .contentType(MediaType.APPLICATION_PDF)
                        .body(pdf);
            } catch (Exception e) {
                return ResponseEntity.internalServerError().build();
            }
        }

        String content = r.getContentJson() != null ? r.getContentJson() : "{}";
        String contentType = switch (format.toUpperCase()) {
            case "HTML" -> "text/html";
            case "CSV" -> "text/csv";
            case "SARIF" -> "application/sarif+json";
            default -> "application/json";
        };

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "." + format.toLowerCase() + "\"")
                .contentType(MediaType.parseMediaType(contentType))
                .body(content.getBytes());
    }

    @Data public static class GenReq { private UUID projectId; private String type; private String title; private String format; }
}
