package com.vulnerax.modules.scan;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ScanServiceAdditionalTest {

    @Mock private ScanRepository scanRepo;
    @Mock private ScanJobRepository jobRepo;
    @Mock private FindingService findingService;
    @Mock private ApplicationContext ctx;
    @Mock private SecurityCoverageRegistry coverageRegistry;
    @Mock private KafkaTemplate<String, Object> kafkaTemplate;

    private ScanService scanService;
    private Scan testScan;

    @BeforeEach
    void setUp() {
        scanService = new ScanService(scanRepo, jobRepo, findingService, ctx, coverageRegistry, List.of(), kafkaTemplate);
        testScan = new Scan();
        testScan.setId(UUID.randomUUID());
        testScan.setProjectId(UUID.randomUUID());
        testScan.setScannerType("SAST");
        testScan.setProfile("STANDARD");
        testScan.setTarget("https://example.com");
        testScan.setStatus("QUEUED");
    }

    @Test
    void list_byOrgId_filtersCorrectly() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "user@test.com");
        Page<Scan> page = new PageImpl<>(List.of(testScan));
        when(scanRepo.findByOrganizationId(eq(orgId), any(PageRequest.class))).thenReturn(page);

        Page<Scan> result = scanService.list(null, PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
        TenantContext.clear();
    }

    @Test
    void createScan_setsDefaultsAndSaves() {
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        Scan result = scanService.createScan("https://target.com", "user@test.com");

        assertNotNull(result);
        assertEquals("QUEUED", result.getStatus());
    }

    @Test
    void startScan_setsStatusAndPublishes() {
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.startScan(testScan, "user@test.com");

        assertEquals("QUEUED", testScan.getStatus());
    }

    @Test
    void create_withDastType_createsMultipleJobs() {
        testScan.setScannerType("DAST");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withAllType_createsManyJobs() {
        testScan.setScannerType("ALL");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(8)).save(any(ScanJob.class));
    }

    @Test
    void create_withSecretType_createsOneJob() {
        testScan.setScannerType("SECRET");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withScaType_createsOneJob() {
        testScan.setScannerType("SCA");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withMobileType_createsOneJob() {
        testScan.setScannerType("MOBILE");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withContainerType_createsOneJob() {
        testScan.setScannerType("CONTAINER");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withIaCType_createsOneJob() {
        testScan.setScannerType("IAC");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withApiType_createsOneJob() {
        testScan.setScannerType("API");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withNullType_createsOneJob() {
        testScan.setScannerType(null);
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void executeAsync_completedSuccessfully() {
        UUID scanId = testScan.getId();
        testScan.setStartedAt(java.time.Instant.now());
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(
                ScanJob.builder().scanId(scanId).scannerPlugin("sast-plugin").status("QUEUED").progress(0).build()
        ));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
    }

    @Test
    void executeAsync_withResultJsonParsing() {
        UUID scanId = testScan.getId();
        testScan.setStartedAt(java.time.Instant.now());
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));

        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("sast-plugin").status("QUEUED").progress(0).build();
        job.setResultJson("{\"findings\": 5, \"plugin\": \"sast-plugin\"}");
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
    }

    @Test
    void executeAsync_scanNotFound_handlesGracefully() {
        UUID scanId = UUID.randomUUID();
        when(scanRepo.findById(scanId)).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> scanService.executeAsync(scanId));
    }

    @Test
    void cancel_publishesEventAndCancelsJobs() {
        testScan.setStatus("RUNNING");
        when(scanRepo.findById(testScan.getId())).thenReturn(Optional.of(testScan));
        ScanJob job = ScanJob.builder().scanId(testScan.getId()).status("RUNNING").build();
        when(jobRepo.findByScanId(testScan.getId())).thenReturn(List.of(job));

        scanService.cancel(testScan.getId());

        assertEquals("CANCELLED", testScan.getStatus());
        assertEquals("CANCELLED", job.getStatus());
        verify(kafkaTemplate).send(eq("scan.cancelled"), anyString(), anyMap());
    }

    @Test
    void create_withUnknownType_defaultsToSastPlugin() {
        testScan.setScannerType("UNKNOWN");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void create_withConfigJson_extractsFileContent() {
        testScan.setScannerType("SAST");
        testScan.setConfigJson("{\"fileContent\": \"public class Test {void eval(String s){Runtime.exec(s);}}\"}");
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(jobRepo).save(any(ScanJob.class));
    }

    @Test
    void executeAsync_withMultipleJobs_parsesResultJson() {
        UUID scanId = testScan.getId();
        testScan.setStartedAt(java.time.Instant.now());
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));

        ScanJob job1 = ScanJob.builder().scanId(scanId).scannerPlugin("sast-plugin").status("QUEUED").progress(0).build();
        job1.setResultJson("{\"findings\": 3, \"plugin\": \"sast-plugin\"}");
        ScanJob job2 = ScanJob.builder().scanId(scanId).scannerPlugin("secret-plugin").status("QUEUED").progress(0).build();
        job2.setResultJson("{\"findings\": 2, \"plugin\": \"secret-plugin\"}");
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job1, job2));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
    }

    @Test
    void executeAsync_invalidJsonInResult_continues() {
        UUID scanId = testScan.getId();
        testScan.setStartedAt(java.time.Instant.now());
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(testScan));

        ScanJob job = ScanJob.builder().scanId(scanId).scannerPlugin("sast-plugin").status("QUEUED").progress(0).build();
        job.setResultJson("invalid json");
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);

        scanService.executeAsync(scanId);

        assertEquals("COMPLETED", testScan.getStatus());
    }

    @Test
    void list_withTenantOrgId_filtersByOrg() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "user@test.com");
        try {
            Page<Scan> page = new PageImpl<>(List.of(testScan));
            when(scanRepo.findByOrganizationId(eq(orgId), any())).thenReturn(page);
            Page<Scan> result = scanService.list(null, PageRequest.of(0, 10));
            assertEquals(1, result.getContent().size());
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void create_eventPublishing() {
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(testScan, "user");

        verify(kafkaTemplate).send(eq("scan.queued"), anyString(), anyMap());
    }
}
