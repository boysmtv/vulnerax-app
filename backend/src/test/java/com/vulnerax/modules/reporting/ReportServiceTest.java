package com.vulnerax.modules.reporting;

import com.vulnerax.modules.ai.AiAnalystService;
import com.vulnerax.modules.asset.Asset;
import com.vulnerax.modules.asset.AssetRepository;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ReportServiceTest {

    @Mock ReportRepository repo;
    @Mock FindingRepository findingRepo;
    @Mock AssetRepository assetRepo;
    @Mock AiAnalystService aiService;
    @InjectMocks ReportService service;

    private Report buildReport(UUID projectId, String type) {
        Report r = Report.builder()
                .projectId(projectId).type(type)
                .title(type + " Report").format("PDF").status("READY")
                .contentJson("{\"draft\":{}}").generatedBy("system")
                .classification("CONFIDENTIAL")
                .filePath("s3://vulnerax-reports/" + projectId + "/report.pdf")
                .build();
        r.setId(UUID.randomUUID());
        return r;
    }

    @Test
    void generate_withAllParams_createsReport() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of("type", "EXECUTIVE"));
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of(new Finding()));
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(new Asset(), new Asset()));
        when(repo.save(any())).thenAnswer(inv -> {
            Report r = inv.getArgument(0); r.setId(UUID.randomUUID()); return r;
        });

        Report result = service.generate(projectId, "EXECUTIVE", "Security Report", "PDF");

        assertNotNull(result);
        assertEquals("EXECUTIVE", result.getType());
        assertEquals("Security Report", result.getTitle());
        assertEquals("PDF", result.getFormat());
        assertEquals("READY", result.getStatus());
        assertEquals("system", result.getGeneratedBy());
        verify(repo).save(any());
    }

    @Test
    void generate_withNullParams_usesDefaults() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, null)).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> {
            Report r = inv.getArgument(0); r.setId(UUID.randomUUID()); return r;
        });

        Report result = service.generate(projectId, null, null, null);

        assertEquals("EXECUTIVE", result.getType());
        assertEquals("PDF", result.getFormat());
    }

    @Test
    void generate_withHtmlFormat_setsCorrectExtension() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "TECHNICAL")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "TECHNICAL", "Tech Report", "HTML");

        assertTrue(result.getFilePath().endsWith(".html"));
        assertEquals("HTML", result.getFormat());
    }

    @Test
    void generate_verifiesAiServiceCalled() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "COMPLIANCE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        service.generate(projectId, "COMPLIANCE", "Compliance Report", "PDF");

        verify(aiService).reportDraft(projectId, "COMPLIANCE");
    }

    @Test
    void generate_verifiesStatsCollected() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of(new Finding(), new Finding()));
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of(new Asset()));
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "PDF");

        verify(findingRepo).findByProjectId(projectId);
        verify(assetRepo).findByProjectId(projectId);
        assertNotNull(result.getContentJson());
    }

    @Test
    void generate_contentJsonIsValidJson() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of("key", "value"));
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "JSON");

        assertDoesNotThrow(() -> new com.fasterxml.jackson.databind.ObjectMapper().readTree(result.getContentJson()));
    }

    @Test
    void generate_withJsonFormat_setsCorrectExtension() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "JSON");

        assertTrue(result.getFilePath().endsWith(".json"));
    }

    @Test
    void generate_withSarifFormat_setsCorrectExtension() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "SARIF");

        assertTrue(result.getFilePath().endsWith(".sarif"));
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID projectId = UUID.randomUUID();
        Report r = buildReport(projectId, "EXECUTIVE");
        when(repo.findByProjectId(projectId)).thenReturn(List.of(r));

        List<Report> result = service.list(projectId);

        assertEquals(1, result.size());
        assertEquals(projectId, result.get(0).getProjectId());
    }

    @Test
    void list_withNullProjectId_returnsAll() {
        Report r1 = buildReport(UUID.randomUUID(), "EXECUTIVE");
        Report r2 = buildReport(UUID.randomUUID(), "TECHNICAL");
        when(repo.findAll()).thenReturn(List.of(r1, r2));

        List<Report> result = service.list(null);

        assertEquals(2, result.size());
    }

    @Test
    void list_emptyResult_returnsEmptyList() {
        UUID projectId = UUID.randomUUID();
        when(repo.findByProjectId(projectId)).thenReturn(List.of());

        List<Report> result = service.list(projectId);

        assertTrue(result.isEmpty());
    }

    @Test
    void list_multipleProjects_onlyReturnsMatchingProject() {
        UUID proj1 = UUID.randomUUID();
        UUID proj2 = UUID.randomUUID();
        Report r1 = buildReport(proj1, "EXECUTIVE");
        when(repo.findByProjectId(proj1)).thenReturn(List.of(r1));

        List<Report> result = service.list(proj1);

        assertEquals(1, result.size());
        assertEquals(proj1, result.get(0).getProjectId());
    }

    @Test
    void get_existingId_returnsReport() {
        UUID id = UUID.randomUUID();
        Report r = buildReport(UUID.randomUUID(), "EXECUTIVE");
        r.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(r));

        Report result = service.get(id);

        assertNotNull(result);
        assertEquals(id, result.getId());
    }

    @Test
    void get_nonExistingId_throwsException() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> service.get(id));
    }

    @Test
    void export_existingReport_returnsExportData() {
        UUID id = UUID.randomUUID();
        Report r = buildReport(UUID.randomUUID(), "EXECUTIVE");
        r.setId(id);
        r.setContentJson("{\"sections\":[\"executive\",\"findings\"]}");
        when(repo.findById(id)).thenReturn(Optional.of(r));

        Map<String, Object> result = service.export(id, "JSON");

        assertEquals(id, result.get("id"));
        assertEquals("EXECUTIVE Report", result.get("title"));
        assertEquals("JSON", result.get("format"));
        assertEquals("{\"sections\":[\"executive\",\"findings\"]}", result.get("content"));
        assertNotNull(result.get("downloadUrl"));
    }

    @Test
    void export_withNullFormat_usesReportFormat() {
        UUID id = UUID.randomUUID();
        Report r = buildReport(UUID.randomUUID(), "TECHNICAL");
        r.setId(id);
        r.setFormat("HTML");
        when(repo.findById(id)).thenReturn(Optional.of(r));

        Map<String, Object> result = service.export(id, null);

        assertEquals("HTML", result.get("format"));
    }

    @Test
    void export_nonExistingReport_throwsException() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> service.export(id, "PDF"));
    }

    @Test
    void generate_classifiesAsConfidential() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "PDF");

        assertEquals("CONFIDENTIAL", result.getClassification());
    }

    @Test
    void generate_filePathContainsProjectId() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "EXECUTIVE")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "EXECUTIVE", "Test", "PDF");

        assertTrue(result.getFilePath().contains(projectId.toString()));
    }

    @Test
    void generate_titleContainsTypeWhenNoTitleGiven() {
        UUID projectId = UUID.randomUUID();
        when(aiService.reportDraft(projectId, "PENTEST")).thenReturn(Map.of());
        when(findingRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(assetRepo.findByProjectId(projectId)).thenReturn(List.of());
        when(repo.save(any())).thenAnswer(inv -> inv.getArgument(0));

        Report result = service.generate(projectId, "PENTEST", null, "PDF");

        assertTrue(result.getTitle().contains("PENTEST"));
    }

    @Test
    void export_returnsDownloadUrl() {
        UUID id = UUID.randomUUID();
        Report r = buildReport(UUID.randomUUID(), "EXECUTIVE");
        r.setId(id);
        r.setFilePath("s3://reports/test.pdf");
        when(repo.findById(id)).thenReturn(Optional.of(r));

        Map<String, Object> result = service.export(id, "PDF");

        assertEquals("s3://reports/test.pdf", result.get("downloadUrl"));
    }
}
