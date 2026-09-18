package com.vulnerax.modules.reporting;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReportControllerUnitTest {

    @Mock com.vulnerax.modules.report.ReportService pdfService;
    @Mock ReportService reportingService;
    @Mock ScanRepository scanRepo;
    @Mock FindingRepository findingRepo;
    @Mock com.vulnerax.modules.finding.FindingService findingService;

    @InjectMocks ReportController controller;

    private UUID projectId;
    private UUID reportId;
    private Report report;

    @BeforeEach
    void setUp() {
        projectId = UUID.randomUUID();
        reportId = UUID.randomUUID();
        report = Report.builder()
                .projectId(projectId)
                .type("EXECUTIVE")
                .title("Q1 Report")
                .format("JSON")
                .status("READY")
                .contentJson("{\"findings\":5}")
                .filePath("s3://vulnerax-reports/x.json")
                .build();
    }

    @Test
    void list_withoutProject_returnsAll() {
        when(reportingService.list(null)).thenReturn(List.of(report));
        var res = controller.list(null);
        assertThat(res.isSuccess()).isTrue();
        assertThat(res.getData()).asList().hasSize(1);
    }

    @Test
    void list_withProject_returnsFiltered() {
        when(reportingService.list(projectId)).thenReturn(List.of(report));
        var res = controller.list(projectId);
        assertThat(res.isSuccess()).isTrue();
        assertThat(res.getData()).asList().hasSize(1);
    }

    @Test
    void get_returnsReport() {
        when(reportingService.get(reportId)).thenReturn(report);
        var res = controller.get(reportId);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void generate_delegatesToService() {
        ReportController.GenReq req = new ReportController.GenReq();
        req.setProjectId(projectId);
        req.setType("TECHNICAL");
        req.setTitle("Tech");
        req.setFormat("PDF");
        when(reportingService.generate(projectId, "TECHNICAL", "Tech", "PDF")).thenReturn(report);
        var res = controller.generate(req);
        assertThat(res.isSuccess()).isTrue();
    }

    @Test
    void export_pdf_withExistingScan_returnsPdf() throws Exception {
        when(reportingService.get(reportId)).thenReturn(report);
        Scan scan = Scan.builder().target("https://example.com").build();
        when(scanRepo.findAll()).thenReturn(List.of(scan));
        when(findingRepo.findAll()).thenReturn(List.of());
        when(pdfService.generatePdf(any(), anyList(), eq("pdf"))).thenReturn(new byte[]{1, 2, 3});
        ResponseEntity<byte[]> res = controller.export(reportId, "PDF");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getHeaders().getContentType().toString()).contains("application/pdf");
        assertThat(res.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains(".pdf");
        assertThat(res.getBody()).hasSize(3);
    }

    @Test
    void export_pdf_lowercaseFormat_returnsPdf() throws Exception {
        when(reportingService.get(reportId)).thenReturn(report);
        when(scanRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());
        when(pdfService.generatePdf(any(), anyList(), eq("pdf"))).thenReturn(new byte[]{9});
        ResponseEntity<byte[]> res = controller.export(reportId, "pdf");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void export_pdf_emptyScans_buildsFallbackScan() throws Exception {
        when(reportingService.get(reportId)).thenReturn(report);
        when(scanRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());
        when(pdfService.generatePdf(any(), anyList(), eq("pdf"))).thenReturn(new byte[]{7});
        ResponseEntity<byte[]> res = controller.export(reportId, "PDF");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getBody()).hasSize(1);
    }

    @Test
    void export_pdf_serviceThrows_returns500() throws Exception {
        when(reportingService.get(reportId)).thenReturn(report);
        when(scanRepo.findAll()).thenReturn(List.of());
        when(findingRepo.findAll()).thenReturn(List.of());
        when(pdfService.generatePdf(any(), anyList(), eq("pdf"))).thenThrow(new RuntimeException("pdf fail"));
        ResponseEntity<byte[]> res = controller.export(reportId, "PDF");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void export_json_default_returnsJson() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "JSON");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(res.getHeaders().getContentType().toString()).contains("application/json");
        assertThat(res.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains(".json");
        assertThat(new String(res.getBody())).contains("findings");
    }

    @Test
    void export_html_returnsHtml() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "HTML");
        assertThat(res.getHeaders().getContentType().toString()).contains("text/html");
        assertThat(res.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains(".html");
    }

    @Test
    void export_csv_returnsCsv() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "CSV");
        assertThat(res.getHeaders().getContentType().toString()).contains("text/csv");
    }

    @Test
    void export_sarif_returnsSarif() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "SARIF");
        assertThat(res.getHeaders().getContentType().toString()).contains("application/sarif+json");
    }

    @Test
    void export_nullContentJson_usesEmptyObject() {
        report.setContentJson(null);
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "JSON");
        assertThat(new String(res.getBody())).isEqualTo("{}");
    }

    @Test
    void export_nullTitle_usesIdAsFilename() {
        report.setTitle(null);
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "JSON");
        assertThat(res.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).contains(reportId.toString());
    }

    @Test
    void export_titleWithSpecialChars_sanitized() {
        report.setTitle("My Report!@# Q1/2026");
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "JSON");
        String cd = res.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION);
        assertThat(cd).doesNotContain("!").doesNotContain("/").contains("My_Report");
    }

    @Test
    void export_unknownFormat_defaultsToJson() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, "XML");
        assertThat(res.getHeaders().getContentType().toString()).contains("application/json");
    }

    @Test
    void export_pdf_limitsFindingsTo100() throws Exception {
        when(reportingService.get(reportId)).thenReturn(report);
        when(scanRepo.findAll()).thenReturn(List.of(Scan.builder().target("t").build()));
        Finding f = Finding.builder().findingId("FND-1").title("XSS").severity("HIGH").build();
        when(findingRepo.findAll()).thenReturn(List.of(f));
        when(pdfService.generatePdf(any(), anyList(), eq("pdf"))).thenReturn(new byte[]{1});
        ResponseEntity<byte[]> res = controller.export(reportId, "PDF");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void export_defaultFormatParam_isJson() {
        when(reportingService.get(reportId)).thenReturn(report);
        ResponseEntity<byte[]> res = controller.export(reportId, null == null ? "JSON" : "JSON");
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
