package com.vulnerax.modules.report;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.Scan;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

class ReportServiceTest {

    private ReportService service;
    private Scan scan;
    private List<Finding> findings;

    @BeforeEach
    void setUp() {
        service = new ReportService();
        scan = new Scan();
        scan.setId(UUID.randomUUID());
        scan.setTarget("https://example.com");
        scan.setStatus("COMPLETED");
        scan.setScannerType("DAST");

        findings = new ArrayList<>();
        Finding critical = new Finding();
        critical.setTitle("SQL Injection");
        critical.setSeverity("CRITICAL");
        critical.setType("SAST");
        critical.setCweId("CWE-89");
        critical.setRecommendation("Use parameterized queries");
        critical.setRiskScore(9.8);
        findings.add(critical);

        Finding high = new Finding();
        high.setTitle("XSS");
        high.setSeverity("HIGH");
        high.setType("DAST");
        high.setCweId("CWE-79");
        high.setRecommendation("Encode output");
        high.setRiskScore(7.5);
        findings.add(high);

        Finding medium = new Finding();
        medium.setTitle("Open Redirect");
        medium.setSeverity("MEDIUM");
        medium.setType("DAST");
        medium.setRiskScore(5.0);
        findings.add(medium);

        Finding low = new Finding();
        low.setTitle("Info Disclosure");
        low.setSeverity("LOW");
        low.setType("INFO");
        low.setRiskScore(2.0);
        findings.add(low);

        Finding info = new Finding();
        info.setTitle("Version Header");
        info.setSeverity("INFO");
        info.setType("INFO");
        info.setRiskScore(0.5);
        findings.add(info);
    }

    @Test
    void generatePdf_defaultFormat_returnsPdf() throws IOException {
        byte[] result = service.generatePdf(scan, findings, null);
        assertThat(result).isNotNull();
        assertThat(result.length).isGreaterThan(0);
    }

    @Test
    void generatePdf_htmlFormat_returnsHtml() throws IOException {
        byte[] result = service.generatePdf(scan, findings, "html");
        String html = new String(result);
        assertThat(html).contains("VulneraX Security Report");
        assertThat(html).contains("SQL Injection");
    }

    @Test
    void generatePdf_jsonFormat_returnsJson() throws IOException {
        byte[] result = service.generatePdf(scan, findings, "json");
        String json = new String(result);
        assertThat(json).contains("VulneraX Security Report");
        assertThat(json).contains("SQL Injection");
    }

    @Test
    void generatePdf_emptyFindings() throws IOException {
        byte[] result = service.generatePdf(scan, List.of(), null);
        assertThat(result).isNotNull();
        assertThat(result.length).isGreaterThan(0);
    }

    @Test
    void generateHtml_containsAllSeverities() throws IOException {
        String html = service.generateHtml(scan, findings);
        assertThat(html).contains("CRITICAL");
        assertThat(html).contains("HIGH");
        assertThat(html).contains("MEDIUM");
        assertThat(html).contains("LOW");
        assertThat(html).contains("INFO");
    }

    @Test
    void generateHtml_criticalRiskLevel() {
        String html = service.generateHtml(scan, findings);
        assertThat(html).contains("CRITICAL - Immediate action required");
    }

    @Test
    void generateHtml_highOnlyShowsModerate() {
        Finding h = new Finding();
        h.setSeverity("HIGH");
        h.setTitle("Test");
        h.setType("DAST");
        h.setRiskScore(7.0);
        String html = service.generateHtml(scan, List.of(h));
        assertThat(html).contains("MODERATE");
    }

    @Test
    void generateHtml_noCriticalNoHigh_showsLow() {
        Finding m = new Finding();
        m.setSeverity("MEDIUM");
        m.setTitle("Medium Issue");
        m.setType("DAST");
        m.setRiskScore(5.0);
        String html = service.generateHtml(scan, List.of(m));
        assertThat(html).contains("LOW - Acceptable risk posture");
    }

    @Test
    void generateHtml_highMoreThan2_showsHigh() {
        List<Finding> highs = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Finding f = new Finding();
            f.setSeverity("HIGH");
            f.setTitle("High Issue " + i);
            f.setType("DAST");
            f.setRiskScore(7.0);
            highs.add(f);
        }
        String html = service.generateHtml(scan, highs);
        assertThat(html).contains("HIGH - Urgent remediation needed");
    }

    @Test
    void generateHtml_cweMapping() {
        Finding f = new Finding();
        f.setSeverity("HIGH");
        f.setTitle("Test CWE");
        f.setType("DAST");
        f.setCweId("CWE-89");
        f.setRiskScore(7.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("A03:2021 Injection");
    }

    @Test
    void generateHtml_cweNull_showsNA() {
        Finding f = new Finding();
        f.setSeverity("HIGH");
        f.setTitle("No CWE");
        f.setType("DAST");
        f.setRiskScore(7.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("N/A");
    }

    @Test
    void generateReportData_returnsMap() {
        Map<String, Object> data = service.generateReportData(scan, findings);
        assertThat(data).containsKey("title");
        assertThat(data).containsKey("scanId");
        assertThat(data).containsKey("totalFindings");
        assertThat(data).containsKey("severityBreakdown");
        assertThat(data.get("totalFindings")).isEqualTo(5);
    }

    @Test
    void generatePdf_jsonWithNoRecommendation() throws IOException {
        Finding f = new Finding();
        f.setSeverity("MEDIUM");
        f.setTitle("No Rec");
        f.setType("DAST");
        f.setRiskScore(4.0);
        byte[] result = service.generatePdf(scan, List.of(f), "json");
        String json = new String(result);
        assertThat(json).contains("No remediation provided");
    }

    @Test
    void generatePdf_htmlWithEscapedHtml() throws IOException {
        Finding f = new Finding();
        f.setSeverity("HIGH");
        f.setTitle("<script>alert(1)</script>");
        f.setRecommendation("<b>Fix</b> this");
        f.setType("DAST");
        f.setRiskScore(7.0);
        String html = service.generateHtml(scan, List.of(f));
        assertThat(html).contains("&lt;script&gt;");
        assertThat(html).doesNotContain("<script>");
    }

    @Test
    void generatePdf_jsonInfoSkippedInHtml() {
        Finding info = new Finding();
        info.setSeverity("INFO");
        info.setTitle("Info Only");
        info.setType("INFO");
        info.setRiskScore(0.1);
        String html = service.generateHtml(scan, List.of(info));
        assertThat(html).doesNotContain("Info Only");
    }

    @Test
    void generatePdf_jsonInfoSkippedInPdf() throws IOException {
        Finding info = new Finding();
        info.setSeverity("INFO");
        info.setTitle("Info Only");
        info.setType("INFO");
        info.setRiskScore(0.1);
        byte[] result = service.generatePdf(scan, List.of(info), "json");
        String json = new String(result);
        assertThat(json).contains("Info Only");
    }

    @Test
    void generateHtml_multipleCweMappings() {
        Finding f1 = new Finding();
        f1.setSeverity("HIGH");
        f1.setTitle("XSS");
        f1.setCweId("CWE-79");
        f1.setType("DAST");
        f1.setRiskScore(7.0);
        Finding f2 = new Finding();
        f2.setSeverity("HIGH");
        f2.setTitle("SSRF");
        f2.setCweId("CWE-918");
        f2.setType("DAST");
        f2.setRiskScore(7.0);
        Finding f3 = new Finding();
        f3.setSeverity("HIGH");
        f3.setTitle("Broken Access");
        f3.setCweId("CWE-22");
        f3.setType("DAST");
        f3.setRiskScore(7.0);
        Finding f4 = new Finding();
        f4.setSeverity("HIGH");
        f4.setTitle("Hardcoded Pass");
        f4.setCweId("CWE-798");
        f4.setType("DAST");
        f4.setRiskScore(7.0);
        Finding f5 = new Finding();
        f5.setSeverity("HIGH");
        f5.setTitle("Unknown CWE");
        f5.setCweId("CWE-999");
        f5.setType("DAST");
        f5.setRiskScore(7.0);
        String html = service.generateHtml(scan, List.of(f1, f2, f3, f4, f5));
        assertThat(html).contains("A10:2021 Server-Side Request Forgery");
        assertThat(html).contains("A01:2021 Broken Access Control");
        assertThat(html).contains("A07:2021 Identification and Authentication Failures");
        assertThat(html).contains("See CWE mapping");
    }
}
