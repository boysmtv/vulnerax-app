package com.vulnerax.integration;

import com.vulnerax.VulneraxApplication;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.SlaBreachScheduler;
import com.vulnerax.modules.report.ReportService;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = VulneraxApplication.class)
@ActiveProfiles("test")
@Transactional
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class EvidenceIntegrationTest {

    @Autowired FindingRepository findingRepo;
    @Autowired SlaBreachScheduler slaBreachScheduler;
    @Autowired @Qualifier("pdfReportService") ReportService reportService;

    @Test @Order(1)
    void slaBreachScheduler_runsWithoutException() {
        assertDoesNotThrow(() -> slaBreachScheduler.checkSlaBreaches());
    }

    @Test @Order(2)
    void slaBreachScheduler_weeklyReport_runs() {
        assertDoesNotThrow(() -> slaBreachScheduler.weeklySlaReport());
    }

    @Test @Order(3)
    void reportService_generateHtml_returnsValidHtml() {
        Scan scan = new Scan(); scan.setId(UUID.randomUUID());
        scan.setTarget("http://example.com"); scan.setStatus("COMPLETED");
        Finding f = createFinding("CRITICAL", "SAST");
        String html = reportService.generateHtml(scan, List.of(f));
        assertTrue(html.contains("VulneraX Security Report"));
        assertTrue(html.contains("CRITICAL"));
        assertTrue(html.contains("CWE-79"));
    }

    @Test @Order(4)
    void reportService_generatePdf_returnsBytes() throws Exception {
        Scan scan = new Scan(); scan.setId(UUID.randomUUID());
        scan.setTarget("http://example.com"); scan.setStatus("COMPLETED");
        Finding f = createFinding("HIGH", "DAST");
        byte[] pdf = reportService.generatePdf(scan, List.of(f), "pdf");
        assertTrue(pdf.length > 100);
    }

    @Test @Order(5)
    void reportService_generateJson_returnsValidJson() throws Exception {
        Scan scan = new Scan(); scan.setId(UUID.randomUUID());
        scan.setTarget("http://example.com"); scan.setStatus("COMPLETED");
        Finding f = createFinding("MEDIUM", "SCA");
        byte[] json = reportService.generatePdf(scan, List.of(f), "json");
        String jsonStr = new String(json);
        assertTrue(jsonStr.contains("VulneraX Security Report"));
        assertTrue(jsonStr.contains("MEDIUM"));
    }

    @Test @Order(6)
    void reportService_generateReportData_hasAllFields() {
        Scan scan = new Scan(); scan.setId(UUID.randomUUID()); scan.setTarget("http://example.com");
        Finding f = createFinding("LOW", "CONTAINER");
        Map<String, Object> data = reportService.generateReportData(scan, List.of(f));
        assertEquals(7, data.size());
        assertTrue(data.containsKey("severityBreakdown"));
        @SuppressWarnings("unchecked")
        Map<String, Long> sb = (Map<String, Long>) data.get("severityBreakdown");
        assertEquals(1L, sb.get("low"));
    }

    private Finding createFinding(String severity, String type) {
        Finding f = new Finding();
        f.setFindingId("FND-TEST-" + UUID.randomUUID().toString().substring(0, 8));
        f.setTitle("Test " + type);
        f.setSeverity(severity);
        f.setType(type);
        f.setCwe("CWE-79");
        f.setCweId("CWE-79");
        f.setRiskScore(7.5);
        f.setStatus("OPEN");
        f.setProjectId(UUID.randomUUID());
        f.setRiskLevel(severity);
        return f;
    }
}
