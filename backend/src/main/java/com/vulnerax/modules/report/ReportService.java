package com.vulnerax.modules.report;

import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import java.awt.Color;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.Scan;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service("pdfReportService")
@RequiredArgsConstructor
public class ReportService {

    public byte[] generatePdf(Scan scan, List<Finding> findings, String format) throws IOException {
        if ("html".equalsIgnoreCase(format)) {
            return generateHtml(scan, findings).getBytes();
        }
        if ("json".equalsIgnoreCase(format)) {
            return generateJson(scan, findings).getBytes();
        }
        return generateOpenPdf(scan, findings);
    }

    private byte[] generateOpenPdf(Scan scan, List<Finding> findings) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 40, 40, 40, 40);
        PdfWriter.getInstance(document, baos);
        document.open();

        // Title
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, Color.DARK_GRAY);
        document.add(new Paragraph("VulneraX Security Report", titleFont));
        document.add(new Paragraph(" "));

        // Scan info
        Font infoFont = FontFactory.getFont(FontFactory.HELVETICA, 10);
        document.add(new Paragraph("Scan ID: " + scan.getId(), infoFont));
        document.add(new Paragraph("Target: " + scan.getTarget(), infoFont));
        document.add(new Paragraph("Date: " + Instant.now(), infoFont));
        document.add(new Paragraph("Total Findings: " + findings.size(), infoFont));
        document.add(new Paragraph(" "));

        // Executive Summary
        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.DARK_GRAY);
        document.add(new Paragraph("Executive Summary", headerFont));
        document.add(new Paragraph(" "));

        long critical = findings.stream().filter(f -> "CRITICAL".equals(f.getSeverity())).count();
        long high = findings.stream().filter(f -> "HIGH".equals(f.getSeverity())).count();
        long medium = findings.stream().filter(f -> "MEDIUM".equals(f.getSeverity())).count();
        long low = findings.stream().filter(f -> "LOW".equals(f.getSeverity())).count();
        long info = findings.stream().filter(f -> "INFO".equals(f.getSeverity())).count();

        String riskLevel;
        if (critical > 0) riskLevel = "CRITICAL - Immediate action required";
        else if (high > 2) riskLevel = "HIGH - Urgent remediation needed";
        else if (high > 0) riskLevel = "MODERATE - Remediation planned";
        else riskLevel = "LOW - Acceptable risk posture";

        document.add(new Paragraph("Overall Risk Level: " + riskLevel, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11)));
        document.add(new Paragraph(" "));

        // Severity Breakdown Table
        document.add(new Paragraph("Severity Breakdown", headerFont));
        document.add(new Paragraph(" "));
        PdfPTable summaryTable = new PdfPTable(4);
        summaryTable.setWidthPercentage(100);
        summaryTable.setWidths(new float[]{25, 25, 25, 25});

        addHeaderCell(summaryTable, "Severity");
        addHeaderCell(summaryTable, "Count");
        addHeaderCell(summaryTable, "%");
        addHeaderCell(summaryTable, "SLA");

        addSeverityRow(summaryTable, "CRITICAL", critical, findings.size(), "1 day");
        addSeverityRow(summaryTable, "HIGH", high, findings.size(), "7 days");
        addSeverityRow(summaryTable, "MEDIUM", medium, findings.size(), "30 days");
        addSeverityRow(summaryTable, "LOW", low, findings.size(), "90 days");
        addSeverityRow(summaryTable, "INFO", info, findings.size(), "N/A");
        document.add(summaryTable);
        document.add(new Paragraph(" "));

        // Findings Table
        document.add(new Paragraph("Remediation Priority", headerFont));
        document.add(new Paragraph(" "));
        PdfPTable findingsTable = new PdfPTable(6);
        findingsTable.setWidthPercentage(100);
        findingsTable.setWidths(new float[]{5, 30, 10, 10, 15, 30});

        addHeaderCell(findingsTable, "#");
        addHeaderCell(findingsTable, "Title");
        addHeaderCell(findingsTable, "Severity");
        addHeaderCell(findingsTable, "Type");
        addHeaderCell(findingsTable, "CWE");
        addHeaderCell(findingsTable, "Remediation");

        List<Finding> prioritized = findings.stream()
                .sorted(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())).reversed())
                .toList();

        int idx = 1;
        for (Finding f : prioritized) {
            if ("INFO".equals(f.getSeverity())) continue;
            addCell(findingsTable, String.valueOf(idx++));
            addCell(findingsTable, truncate(f.getTitle(), 50));
            addCell(findingsTable, f.getSeverity());
            addCell(findingsTable, f.getType());
            addCell(findingsTable, f.getCweId() != null ? f.getCweId() : "N/A");
            addCell(findingsTable, truncate(f.getRecommendation(), 60));
        }
        document.add(findingsTable);
        document.add(new Paragraph(" "));

        // Remediation Guide
        Font guideHeaderFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, Color.DARK_GRAY);
        document.add(new Paragraph("Remediation Guide", guideHeaderFont));
        document.add(new Paragraph(" "));
        Font guideFont = FontFactory.getFont(FontFactory.HELVETICA, 9);

        Map<String, String> remediationGuide = Map.of(
            "CWE-732", "1. Set readOnlyRootFilesystem: true in container securityContext\n2. Use emptyDir volumes for writable paths (/tmp, /var/run)\n3. Remove USER root from Dockerfile\n4. Scan: trivy image <image> --severity HIGH,CRITICAL",
            "CWE-693", "1. Implement Content-Security-Policy header\n2. Add X-Frame-Options: DENY or SAMEORIGIN\n3. Enable HSTS: Strict-Transport-Security: max-age=31536000\n4. Use helmet.js or Spring Security headers",
            "CWE-942", "1. Set Access-Control-Allow-Origin to specific domains only\n2. Never use wildcard (*) with credentials\n3. Validate Origin header server-side\n4. Example: Access-Control-Allow-Origin: https://yourdomain.com",
            "CWE-770", "1. Implement rate limiting (e.g., 100 req/min per IP)\n2. Use Redis sliding window or token bucket\n3. Return 429 Too Many Requests with Retry-After header",
            "CWE-200", "1. Remove robots.txt that exposes sensitive paths\n2. Disable server version headers (Server, X-Powered-By)\n3. Remove debug/stack traces in production\n4. Set: Referrer-Policy: strict-origin-when-cross-origin",
            "CWE-346", "1. Validate Origin header against whitelist\n2. Implement Cross-Origin-Opener-Policy: same-origin\n3. Add Cross-Origin-Resource-Policy: same-site\n4. Use SameSite=Strict cookies",
            "CWE-1021", "1. Add X-Frame-Options: DENY header\n2. Implement CSP frame-ancestors 'none'\n3. Prevent clickjacking on sensitive pages",
            "CWE-79", "1. Sanitize all user input server-side\n2. Use Content-Security-Policy: default-src 'self'\n3. Encode output: escape HTML entities\n4. Use framework auto-escaping (React JSX, Thymeleaf)"
        );

        for (Finding f : prioritized) {
            if ("INFO".equals(f.getSeverity())) continue;
            String cwe = f.getCweId() != null ? f.getCweId() : "";
            String guide = remediationGuide.getOrDefault(cwe, 
                "General: Review " + cwe + " documentation at https://cwe.mitre.org/data/definitions/" + cwe.replaceAll("\\D","") + ".html");

            document.add(new Paragraph(idx + ". " + f.getTitle() + " [" + f.getSeverity() + "]", 
                FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10)));
            document.add(new Paragraph("CWE: " + cwe + " | Risk Score: " + (f.getRiskScore() != null ? f.getRiskScore() : "N/A"), guideFont));
            document.add(new Paragraph("How to fix:", FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9)));
            document.add(new Paragraph(guide, guideFont));
            document.add(new Paragraph(" "));
        }

        // Footer
        document.add(new Paragraph(" "));
        Font footerFont = FontFactory.getFont(FontFactory.HELVETICA, 8, Color.GRAY);
        document.add(new Paragraph("Generated by VulneraX Security Platform | " + Instant.now(), footerFont));
        document.add(new Paragraph("For questions, contact your security team", footerFont));

        document.close();
        return baos.toByteArray();
    }

    private void addHeaderCell(PdfPTable table, String text) {
        PdfPCell cell = new PdfPCell(new Phrase(text, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9)));
        cell.setBackgroundColor(new Color(241, 245, 249));
        cell.setPadding(6);
        cell.setBorderWidth(0.5f);
        table.addCell(cell);
    }

    private void addCell(PdfPTable table, String text) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", FontFactory.getFont(FontFactory.HELVETICA, 8)));
        cell.setPadding(4);
        cell.setBorderWidth(0.3f);
        table.addCell(cell);
    }

    private void addSeverityRow(PdfPTable table, String severity, long count, long total, String sla) {
        double pct = total > 0 ? (count * 100.0 / total) : 0;
        Color color = switch (severity) {
            case "CRITICAL" -> new Color(220, 38, 38);
            case "HIGH" -> new Color(234, 88, 12);
            case "MEDIUM" -> new Color(217, 119, 6);
            case "LOW" -> new Color(37, 99, 235);
            default -> new Color(107, 114, 128);
        };
        PdfPCell sevCell = new PdfPCell(new Phrase(severity, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, color)));
        sevCell.setPadding(4);
        table.addCell(sevCell);
        addCell(table, String.valueOf(count));
        addCell(table, String.format("%.1f%%", pct));
        addCell(table, sla);
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private String generateJson(Scan scan, List<Finding> findings) {
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
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
            return mapper.writeValueAsString(data);
        } catch (Exception e) {
            return "{}";
        }
    }

    public String generateHtml(Scan scan, List<Finding> findings) {
        Map<String, Long> severityCounts = findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));

        long critical = severityCounts.getOrDefault("CRITICAL", 0L);
        long high = severityCounts.getOrDefault("HIGH", 0L);
        long medium = severityCounts.getOrDefault("MEDIUM", 0L);
        long low = severityCounts.getOrDefault("LOW", 0L);
        long info = severityCounts.getOrDefault("INFO", 0L);

        String riskLevel;
        if (critical > 0) riskLevel = "CRITICAL - Immediate action required";
        else if (high > 2) riskLevel = "HIGH - Urgent remediation needed";
        else if (high > 0) riskLevel = "MODERATE - Remediation planned";
        else riskLevel = "LOW - Acceptable risk posture";

        List<Finding> prioritized = findings.stream()
                .sorted(Comparator.comparing(Finding::getRiskScore, Comparator.nullsLast(Comparator.reverseOrder())).reversed())
                .toList();

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>VulneraX Security Report</title>");
        html.append("<style>");
        html.append("body{font-family:'Segoe UI',Arial,sans-serif;margin:40px;color:#1f2937;line-height:1.6}");
        html.append("h1{color:#111827;border-bottom:3px solid #2563eb;padding-bottom:8px}");
        html.append("h2{color:#1e40af;margin-top:32px}");
        html.append(".summary-box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px;margin:16px 0}");
        html.append(".CRITICAL{color:#dc2626;font-weight:bold}.HIGH{color:#ea580c;font-weight:bold}");
        html.append(".MEDIUM{color:#d97706}.LOW{color:#2563eb}.INFO{color:#6b7280}");
        html.append("table{border-collapse:collapse;width:100%;margin:16px 0}");
        html.append("th,td{border:1px solid #e5e7eb;padding:10px 12px;text-align:left}");
        html.append("th{background:#f1f5f9;font-weight:600}");
        html.append(".finding-card{border:1px solid #e5e7eb;border-radius:6px;padding:16px;margin:12px 0}");
        html.append(".remediation{background:#f0fdf4;border-left:3px solid #22c55e;padding:8px 12px;margin-top:8px}");
        html.append(".compliance{background:#faf5ff;border-left:3px solid #a855f7;padding:8px 12px;margin-top:8px;font-size:12px}");
        html.append("@media print{.finding-card{break-inside:avoid}}");
        html.append("</style></head><body>");

        html.append("<h1>VulneraX Security Report</h1>");
        html.append("<div class='summary-box'>");
        html.append("<p><strong>Scan ID:</strong> ").append(scan.getId()).append("</p>");
        html.append("<p><strong>Target:</strong> ").append(scan.getTarget()).append("</p>");
        html.append("<p><strong>Date:</strong> ").append(Instant.now()).append("</p>");
        html.append("<p><strong>Overall Risk:</strong> <span class='").append(riskLevel.startsWith("CRITICAL") ? "CRITICAL" : riskLevel.startsWith("HIGH") ? "HIGH" : "LOW").append("'>").append(riskLevel).append("</span></p>");
        html.append("</div>");

        html.append("<h2>Severity Breakdown</h2>");
        html.append("<table><tr><th>Severity</th><th>Count</th><th>%</th><th>SLA</th></tr>");
        appendSeverityRow(html, "CRITICAL", critical, findings.size(), "1 day");
        appendSeverityRow(html, "HIGH", high, findings.size(), "7 days");
        appendSeverityRow(html, "MEDIUM", medium, findings.size(), "30 days");
        appendSeverityRow(html, "LOW", low, findings.size(), "90 days");
        appendSeverityRow(html, "INFO", info, findings.size(), "N/A");
        html.append("</table>");

        html.append("<h2>Remediation Priority</h2>");
        int priority = 1;
        for (Finding f : prioritized) {
            if ("INFO".equals(f.getSeverity())) continue;
            html.append("<div class='finding-card'>");
            html.append("<strong>").append(priority++).append(". ").append(escapeHtml(f.getTitle())).append("</strong> ");
            html.append("<span class='").append(f.getSeverity()).append("'>").append(f.getSeverity()).append("</span> ");
            html.append("(Risk: ").append(f.getRiskScore() != null ? f.getRiskScore() : "N/A").append(")");
            html.append("<br><em>").append(f.getType()).append(" | CWE: ").append(Optional.ofNullable(f.getCweId()).orElse("N/A")).append("</em>");
            if (f.getRecommendation() != null) {
                html.append("<div class='remediation'><strong>Fix:</strong> ").append(escapeHtml(f.getRecommendation())).append("</div>");
            }
            html.append("<div class='compliance'>OWASP: ").append(mapCweToOwasp(f.getCweId())).append("</div>");
            html.append("</div>");
        }

        html.append("<h2>Remediation Guide</h2>");
        html.append("<p>Follow these steps to fix each vulnerability:</p>");
        for (Finding f : prioritized) {
            if ("INFO".equals(f.getSeverity())) continue;
            String cwe = f.getCweId() != null ? f.getCweId() : "";
            String guide = getRemediationGuide(cwe);
            html.append("<div class='finding-card'>");
            html.append("<strong>").append(escapeHtml(f.getTitle())).append("</strong> ");
            html.append("<span class='").append(f.getSeverity()).append("'>").append(f.getSeverity()).append("</span>");
            html.append("<br><em>CWE: ").append(cwe).append("</em>");
            html.append("<div class='remediation'><strong>How to fix:</strong><br>").append(guide.replace("\n", "<br>")).append("</div>");
            html.append("</div>");
        }

        html.append("</body></html>");
        return html.toString();
    }

    private void appendSeverityRow(StringBuilder html, String severity, long count, long total, String sla) {
        double pct = total > 0 ? (count * 100.0 / total) : 0;
        html.append("<tr><td class='").append(severity).append("'><strong>").append(severity).append("</strong></td>")
            .append("<td>").append(count).append("</td>")
            .append("<td>").append(String.format("%.1f%%", pct)).append("</td>")
            .append("<td>").append(sla).append("</td></tr>");
    }

    private String mapCweToOwasp(String cwe) {
        if (cwe == null) return "N/A";
        return switch (cwe) {
            case "CWE-79" -> "A03:2021 Injection";
            case "CWE-89" -> "A03:2021 Injection";
            case "CWE-22" -> "A01:2021 Broken Access Control";
            case "CWE-287" -> "A07:2021 Identification and Authentication Failures";
            case "CWE-352" -> "A01:2021 Broken Access Control";
            case "CWE-502" -> "A08:2021 Software and Data Integrity Failures";
            case "CWE-611" -> "A05:2021 Security Misconfiguration";
            case "CWE-798" -> "A07:2021 Identification and Authentication Failures";
            case "CWE-918" -> "A10:2021 Server-Side Request Forgery";
            default -> "See CWE mapping";
        };
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private String getRemediationGuide(String cwe) {
        if (cwe == null) return "Review CWE documentation for remediation steps.";
        return switch (cwe) {
            case "CWE-732" -> "1. Set readOnlyRootFilesystem: true in container securityContext\n2. Use emptyDir volumes for writable paths (/tmp, /var/run)\n3. Remove USER root from Dockerfile\n4. Scan: trivy image <image> --severity HIGH,CRITICAL";
            case "CWE-693" -> "1. Implement Content-Security-Policy header\n2. Add X-Frame-Options: DENY or SAMEORIGIN\n3. Enable HSTS: Strict-Transport-Security: max-age=31536000\n4. Use helmet.js or Spring Security headers";
            case "CWE-942" -> "1. Set Access-Control-Allow-Origin to specific domains only\n2. Never use wildcard (*) with credentials\n3. Validate Origin header server-side\n4. Example: Access-Control-Allow-Origin: https://yourdomain.com";
            case "CWE-770" -> "1. Implement rate limiting (e.g., 100 req/min per IP)\n2. Use Redis sliding window or token bucket\n3. Return 429 Too Many Requests with Retry-After header";
            case "CWE-200" -> "1. Remove robots.txt that exposes sensitive paths\n2. Disable server version headers (Server, X-Powered-By)\n3. Remove debug/stack traces in production\n4. Set: Referrer-Policy: strict-origin-when-cross-origin";
            case "CWE-346" -> "1. Validate Origin header against whitelist\n2. Implement Cross-Origin-Opener-Policy: same-origin\n3. Add Cross-Origin-Resource-Policy: same-site\n4. Use SameSite=Strict cookies";
            case "CWE-1021" -> "1. Add X-Frame-Options: DENY header\n2. Implement CSP frame-ancestors 'none'\n3. Prevent clickjacking on sensitive pages";
            case "CWE-79" -> "1. Sanitize all user input server-side\n2. Use Content-Security-Policy: default-src 'self'\n3. Encode output: escape HTML entities\n4. Use framework auto-escaping (React JSX, Thymeleaf)";
            default -> "1. Review " + cwe + " at https://cwe.mitre.org/data/definitions/" + cwe.replaceAll("\\D","") + ".html\n2. Apply OWASP guidelines\n3. Conduct peer code review";
        };
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
}
