package com.vulnerax.modules.report;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.Scan;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ReportService {

    public byte[] generatePdf(Scan scan, List<Finding> findings, String format) throws IOException {
        if ("html".equalsIgnoreCase(format)) {
            return generateHtml(scan, findings).getBytes();
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("title", "VulneraX Security Report");
        data.put("scanId", scan.getId());
        data.put("targetUrl", scan.getTarget());
        data.put("scanDate", Instant.now().toString());
        data.put("totalFindings", findings.size());
        data.put("criticalCount", findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count());
        data.put("highCount", findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count());
        data.put("mediumCount", findings.stream().filter(f -> "MEDIUM".equals(f.getSeverity())).count());
        data.put("lowCount", findings.stream().filter(f -> "LOW".equals(f.getSeverity())).count());
        data.put("infoCount", findings.stream().filter(f -> "INFO".equals(f.getSeverity())).count());
        data.put("findings", findings.stream().map(f -> Map.of(
                "title", f.getTitle(),
                "severity", f.getSeverity(),
                "type", f.getType(),
                "cweId", Optional.ofNullable(f.getCweId()).orElse("N/A"),
                "filePath", Optional.ofNullable(f.getFilePath()).orElse("N/A"),
                "evidence", Optional.ofNullable(f.getEvidenceJson()).orElse("No evidence"),
                "remediation", Optional.ofNullable(f.getRecommendation()).orElse("No remediation provided"),
                "riskScore", f.getRiskScore() != null ? f.getRiskScore() : 0
        )).toList());

        StringBuilder sb = new StringBuilder();
        sb.append("{\"report\":").append(toJson(data)).append("}");
        return sb.toString().getBytes();
    }

    public String generateHtml(Scan scan, List<Finding> findings) {
        Map<String, Long> severityCounts = findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>VulneraX Report</title>");
        html.append("<style>body{font-family:sans-serif;margin:40px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f4f4f4}.CRITICAL{color:#dc2626}.HIGH{color:#ea580c}.MEDIUM{color:#d97706}.LOW{color:#2563eb}.INFO{color:#6b7280}</style>");
        html.append("</head><body>");
        html.append("<h1>VulneraX Security Report</h1>");
        html.append("<p><strong>Scan ID:</strong> ").append(scan.getId()).append("</p>");
        html.append("<p><strong>Target:</strong> ").append(scan.getTarget()).append("</p>");
        html.append("<p><strong>Date:</strong> ").append(Instant.now()).append("</p>");
        html.append("<h2>Summary</h2>");
        html.append("<table><tr><th>Severity</th><th>Count</th></tr>");
        for (var entry : severityCounts.entrySet()) {
            html.append("<tr><td class='").append(entry.getKey()).append("'><strong>")
                .append(entry.getKey()).append("</strong></td><td>").append(entry.getValue()).append("</td></tr>");
        }
        html.append("</table>");
        html.append("<h2>Findings</h2>");
        html.append("<table><tr><th>Title</th><th>Severity</th><th>Type</th><th>CWE</th><th>Path</th><th>Evidence</th></tr>");
        for (Finding f : findings) {
            html.append("<tr><td>").append(f.getTitle()).append("</td>")
                .append("<td class='").append(f.getSeverity()).append("'>").append(f.getSeverity()).append("</td>")
                .append("<td>").append(f.getType()).append("</td>")
                .append("<td>").append(Optional.ofNullable(f.getCweId()).orElse("N/A")).append("</td>")
                .append("<td>").append(Optional.ofNullable(f.getFilePath()).orElse("N/A")).append("</td>")
                .append("<td>").append(Optional.ofNullable(f.getEvidenceJson()).orElse("")).append("</td></tr>");
        }
        html.append("</table></body></html>");
        return html.toString();
    }

    public Map<String, Object> generateReportData(Scan scan, List<Finding> findings) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("title", "VulneraX Security Report");
        data.put("scanId", scan.getId());
        data.put("targetUrl", scan.getTarget());
        data.put("scanDate", Instant.now().toString());
        data.put("totalFindings", findings.size());
        data.put("severityBreakdown", Map.of(
                "critical", findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count(),
                "high", findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count(),
                "medium", findings.stream().filter(f -> "MEDIUM".equals(f.getSeverity())).count(),
                "low", findings.stream().filter(f -> "LOW".equals(f.getSeverity())).count(),
                "info", findings.stream().filter(f -> "INFO".equals(f.getSeverity())).count()
        ));
        data.put("findings", findings);
        return data;
    }

    private String toJson(Object obj) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
            return mapper.writeValueAsString(obj);
        } catch (Exception e) {
            return "{}";
        }
    }
}
