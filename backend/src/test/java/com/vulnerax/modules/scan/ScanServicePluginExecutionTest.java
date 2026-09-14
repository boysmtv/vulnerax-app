package com.vulnerax.modules.scan;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ScanServicePluginExecutionTest {

    @Mock private ScanRepository scanRepo;
    @Mock private ScanJobRepository jobRepo;
    @Mock private FindingService findingService;
    @Mock private ApplicationContext ctx;
    @Mock private SecurityCoverageRegistry coverageRegistry;
    @Mock private KafkaTemplate<String, Object> kafkaTemplate;
    @Mock private SecurityScannerPlugin mockPlugin;

    private ScanService scanService;
    private Scan testScan;

    @BeforeEach
    void setUp() {
        when(mockPlugin.getId()).thenReturn("test-plugin");
        when(mockPlugin.getName()).thenReturn("Test Plugin");
        when(mockPlugin.getVersion()).thenReturn("1.0");
        when(mockPlugin.getProvider()).thenReturn("test");
        when(mockPlugin.getSupportedTargetTypes()).thenReturn(List.of("url"));
        when(mockPlugin.getSecurityLevel()).thenReturn("SAFE");

        scanService = new ScanService(scanRepo, jobRepo, findingService, ctx, coverageRegistry,
                List.of(mockPlugin), kafkaTemplate);

        testScan = new Scan();
        testScan.setId(UUID.randomUUID());
        testScan.setProjectId(UUID.randomUUID());
        testScan.setAssetId(UUID.randomUUID());
        testScan.setScannerType("DAST");
        testScan.setProfile("STANDARD");
        testScan.setTarget("https://example.com");
        testScan.setStatus("QUEUED");
        testScan.setStartedAt(java.time.Instant.now());
    }

    @Test
    void executeAsync_pluginFound_usesPlugin() {
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "TEST", "test", Map.of())),
                Map.of());
        when(mockPlugin.plan(anyString(), anyMap())).thenReturn(plan);

        Finding f = new Finding();
        f.setTitle("Test Finding");
        f.setSeverity("HIGH");
        when(mockPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(f));
        when(mockPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mockPlugin.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "Valid"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
        verify(mockPlugin).plan(anyString(), anyMap());
        verify(mockPlugin).execute(anyString(), any(), anyMap());
        verify(mockPlugin).normalize(any(), anyMap());
        verify(mockPlugin).validate(any());
        verify(findingService).create(any(Finding.class));
    }

    @Test
    void executeAsync_pluginValidatesFalse_skipsFinding() {
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "TEST", "test", Map.of())),
                Map.of());
        when(mockPlugin.plan(anyString(), anyMap())).thenReturn(plan);

        Finding f = new Finding();
        f.setTitle("Rejected");
        when(mockPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(f));
        when(mockPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mockPlugin.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(false, "Missing title"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
        verify(findingService, never()).create(any(Finding.class));
    }

    @Test
    void executeAsync_pluginThrows_fallsBackToLegacy() {
        UUID scanId = testScan.getId();
        testScan.setScannerType("SAST");
        testScan.setTarget("Runtime.exec(input);");
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        when(mockPlugin.plan(anyString(), anyMap())).thenThrow(new RuntimeException("Plugin failed"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
    }

    @Test
    void executeAsync_pluginSetsFindingsAttributes() {
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "TEST", "test", Map.of())),
                Map.of());
        when(mockPlugin.plan(anyString(), anyMap())).thenReturn(plan);

        Finding f = new Finding();
        f.setTitle("Test Finding");
        f.setSeverity("HIGH");
        when(mockPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(f));
        when(mockPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mockPlugin.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "Valid"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        verify(findingService).create(argThat(ff ->
                ff.getProjectId() != null &&
                ff.getAssetId() != null &&
                ff.getScanId() != null &&
                "OPEN".equals(ff.getStatus())
        ));
    }

    @Test
    void executeAsync_pluginWithConfigJson_passesToOptions() {
        testScan.setConfigJson("{\"key\": \"value\"}");
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "TEST", "test", Map.of())),
                Map.of());
        when(mockPlugin.plan(anyString(), anyMap())).thenReturn(plan);
        when(mockPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of());
        when(mockPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mockPlugin.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        verify(mockPlugin).plan(eq("https://example.com"), argThat(opts ->
                opts.containsKey("configJson")));
    }

    @Test
    void executeAsync_pluginWithEvidenceJson_doesNotOverride() {
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("test-plugin").status("QUEUED").progress(0).build();
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "TEST", "test", Map.of())),
                Map.of());
        when(mockPlugin.plan(anyString(), anyMap())).thenReturn(plan);

        Finding f = new Finding();
        f.setTitle("With Evidence");
        f.setSeverity("HIGH");
        f.setEvidenceJson("{\"existing\": true}");
        when(mockPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(f));
        when(mockPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mockPlugin.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "Valid"));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        verify(findingService).create(argThat(ff -> "{\"existing\": true}".equals(ff.getEvidenceJson())));
    }

    @Test
    void executeAsync_noJobs_completesImmediately() {
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
        assertEquals(0, testScan.getFindingsCount());
    }

    @Test
    void executeAsync_startScanNull_setsRunningFirst() {
        testScan.setStartedAt(null);
        UUID scanId = testScan.getId();
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        verify(scanRepo, atLeastOnce()).save(any(Scan.class));
    }

    @Test
    void list_nullTenantAndProject_findsAll() {
        TenantContext.clear();
        when(scanRepo.findAll(any(org.springframework.data.domain.Pageable.class))).thenReturn(
                new org.springframework.data.domain.PageImpl<>(List.of(testScan)));

        var result = scanService.list(null, org.springframework.data.domain.PageRequest.of(0, 10));
        assertEquals(1, result.getContent().size());
    }

    @Test
    void list_projectIdFiltersByProject() {
        UUID projectId = UUID.randomUUID();
        TenantContext.clear();
        when(scanRepo.findByProjectId(eq(projectId), any(org.springframework.data.domain.Pageable.class))).thenReturn(
                new org.springframework.data.domain.PageImpl<>(List.of(testScan)));

        var result = scanService.list(projectId, org.springframework.data.domain.PageRequest.of(0, 10));
        assertEquals(1, result.getContent().size());
    }
}
