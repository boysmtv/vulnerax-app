package com.vulnerax.modules.report;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.Scan;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class ReportServiceAdditionalTest {

    private ReportService service;
    private Scan scan;

    @BeforeEach
    void setUp() {
        service = new ReportService();
        scan = new Scan();
        scan.setId(UUID.randomUUID());
        scan.setTarget("https://example.com");
        scan.setStatus("COMPLETED");
        scan.setScannerType("DAST");
    }

    @Test
    void generatePdf_allSeverities_returnsPdf() throws IOException {
        List<Finding> findings = List.of(
                createFinding("Critical", "CRITICAL", 9.0),
                createFinding("High", "HIGH", 7.0),
                createFinding("Medium", "MEDIUM", 5.0),
                createFinding("Low", "LOW", 2.0),
                createFinding("Info", "INFO", 0.5)
        );
        byte[] result = service.generatePdf(scan, findings, null);
        assertThat(result).isNotNull();
        assertThat(result.length).isGreaterThan(0);
    }

    @Test
    void generateHtml_criticalOnly() {
        List<Finding> findings = List.of(createFinding("Critical Only", "CRITICAL", 9.5));
        String html = service.generateHtml(scan, findings);
        assertThat(html).contains("CRITICAL");
        assertThat(html).contains("CRITICAL - Immediate action required");
    }

    @Test
    void generateHtml_highOnlyOneItem() {
        Finding f = createFinding("Single High", "HIGH", 7.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("MODERATE");
    }

    @Test
    void generateHtml_mediumOnly() {
        Finding f = createFinding("Medium Only", "MEDIUM", 5.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("LOW - Acceptable risk posture");
    }

    @Test
    void generateHtml_lowOnly() {
        Finding f = createFinding("Low Only", "LOW", 2.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("LOW - Acceptable risk posture");
    }

    @Test
    void generateHtml_infoOnly_noFindings() {
        Finding f = createFinding("Info Only", "INFO", 0.1);
        f.setType("INFO");
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).doesNotContain("Info Only");
    }

    @Test
    void generatePdf_htmlFormat_containsHtml() throws IOException {
        List<Finding> findings = List.of(createFinding("Test", "HIGH", 7.0));
        byte[] result = service.generatePdf(scan, findings, "html");
        String html = new String(result);
        assertThat(html).contains("<!DOCTYPE html>");
        assertThat(html).contains("VulneraX Security Report");
    }

    @Test
    void generatePdf_jsonFormat_containsJson() throws IOException {
        List<Finding> findings = List.of(createFinding("Test", "HIGH", 7.0));
        byte[] result = service.generatePdf(scan, findings, "json");
        String json = new String(result);
        assertThat(json).contains("VulneraX Security Report");
        assertThat(json).contains("Test");
    }

    @Test
    void generateReportData_severityBreakdown() {
        List<Finding> findings = List.of(
                createFinding("C1", "CRITICAL", 9.0),
                createFinding("C2", "CRITICAL", 8.5),
                createFinding("H1", "HIGH", 7.0),
                createFinding("M1", "MEDIUM", 5.0)
        );
        Map<String, Object> data = service.generateReportData(scan, findings);
        assertThat(data.get("totalFindings")).isEqualTo(4);
        assertThat(data).containsKey("severityBreakdown");
    }

    @Test
    void generateHtml_xssEscaped() {
        Finding f = createFinding("<script>alert(1)</script>", "HIGH", 7.0);
        f.setRecommendation("<b>Bold</b> recommendation");
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("&lt;script&gt;");
        assertThat(html).doesNotContain("<script>");
    }

    @Test
    void generateHtml_cweMapping_coverage() {
        Finding f1 = createFinding("XSS", "HIGH", 7.0);
        f1.setCweId("CWE-79");
        Finding f2 = createFinding("SQLi", "CRITICAL", 9.0);
        f2.setCweId("CWE-89");
        Finding f3 = createFinding("Path Traversal", "HIGH", 7.0);
        f3.setCweId("CWE-22");
        Finding f4 = createFinding("Hardcoded Pass", "HIGH", 7.0);
        f4.setCweId("CWE-798");
        Finding f5 = createFinding("SSRF", "HIGH", 7.0);
        f5.setCweId("CWE-918");
        Finding f6 = createFinding("Weak Crypto", "HIGH", 7.0);
        f6.setCweId("CWE-327");
        Finding f7 = createFinding("Open Redirect", "HIGH", 7.0);
        f7.setCweId("CWE-601");

        String html = service.generateHtml(scan, List.of(f1, f2, f3, f4, f5, f6, f7));
        assertThat(html).contains("A07:2021 Identification and Authentication Failures");
        assertThat(html).contains("A03:2021 Injection");
        assertThat(html).contains("A01:2021 Broken Access Control");
        assertThat(html).contains("A10:2021 Server-Side Request Forgery");
    }

    @Test
    void generatePdf_jsonFormat_severityBreakdown() throws IOException {
        List<Finding> findings = List.of(
                createFinding("Critical", "CRITICAL", 9.0),
                createFinding("High", "HIGH", 7.0)
        );
        byte[] result = service.generatePdf(scan, findings, "json");
        String json = new String(result);
        assertThat(json).contains("criticalCount");
        assertThat(json).contains("findings");
    }

    @Test
    void generateHtml_emptyFindings() {
        String html = service.generateHtml(scan, List.of());
        assertThat(html).contains("VulneraX Security Report");
    }

    @Test
    void generateReportData_hasAllFields() {
        List<Finding> findings = List.of(createFinding("Test", "HIGH", 7.0));
        Map<String, Object> data = service.generateReportData(scan, findings);
        assertThat(data).containsKey("title");
        assertThat(data).containsKey("scanId");
        assertThat(data).containsKey("totalFindings");
        assertThat(data).containsKey("severityBreakdown");
        assertThat(data).containsKey("findings");
    }

    private Finding createFinding(String title, String severity, double riskScore) {
        Finding f = new Finding();
        f.setTitle(title);
        f.setSeverity(severity);
        f.setType("DAST");
        f.setRiskScore(riskScore);
        f.setRecommendation("Fix the issue");
        return f;
    }
}
