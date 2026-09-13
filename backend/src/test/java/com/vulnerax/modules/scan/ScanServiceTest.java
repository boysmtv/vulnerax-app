package com.vulnerax.modules.scan;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.finding.FindingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ScanServiceTest {

    @Mock private ScanRepository scanRepo;
    @Mock private ScanJobRepository jobRepo;
    @Mock private FindingService findingService;
    @Mock private ApplicationContext ctx;
    @Mock private SecurityCoverageRegistry coverageRegistry;
    @Mock private org.springframework.kafka.core.KafkaTemplate<String, Object> kafkaTemplate;

    private ScanService scanService;
    private Scan testScan;

    @BeforeEach
    void setUp() {
        scanService = new ScanService(scanRepo, jobRepo, findingService, ctx, coverageRegistry, List.of(), kafkaTemplate);
        testScan = Scan.builder()
                .projectId(UUID.randomUUID())
                .scannerType("SAST")
                .profile("STANDARD")
                .target("https://example.com")
                .status("QUEUED")
                .build();
        testScan.setId(UUID.randomUUID());
    }

    @Test
    void list_returnsPage() {
        Page<Scan> page = new PageImpl<>(List.of(testScan));
        when(scanRepo.findAll(any(Pageable.class))).thenReturn(page);

        Page<Scan> result = scanService.list(null, PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
    }

    @Test
    void list_byProjectId_filtersCorrectly() {
        UUID projectId = testScan.getProjectId();
        Page<Scan> page = new PageImpl<>(List.of(testScan));
        when(scanRepo.findByProjectId(eq(projectId), any(Pageable.class))).thenReturn(page);

        Page<Scan> result = scanService.list(projectId, PageRequest.of(0, 10));

        assertEquals(1, result.getContent().size());
        verify(scanRepo).findByProjectId(eq(projectId), any(Pageable.class));
    }

    @Test
    void get_existingId_returnsScan() {
        when(scanRepo.findById(testScan.getId())).thenReturn(Optional.of(testScan));
        Scan result = scanService.get(testScan.getId());
        assertEquals("SAST", result.getScannerType());
    }

    @Test
    void get_nonExistingId_throws() {
        UUID fakeId = UUID.randomUUID();
        when(scanRepo.findById(fakeId)).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> scanService.get(fakeId));
    }

    @Test
    void create_scan_savesAndCreatesJobs() {
        when(scanRepo.save(any(Scan.class))).thenReturn(testScan);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        Scan result = scanService.create(testScan, "test-user");

        assertNotNull(result);
        assertEquals("QUEUED", result.getStatus());
        assertEquals("test-user", result.getInitiatedBy());
        verify(scanRepo).save(any(Scan.class));
        verify(jobRepo, times(1)).save(any(ScanJob.class));
    }

    @Test
    void cancel_setsCancelledStatus() {
        testScan.setStatus("RUNNING");
        when(scanRepo.findById(testScan.getId())).thenReturn(Optional.of(testScan));
        when(jobRepo.findByScanId(testScan.getId())).thenReturn(List.of(
                ScanJob.builder().scanId(testScan.getId()).status("RUNNING").build()
        ));

        scanService.cancel(testScan.getId());

        assertEquals("CANCELLED", testScan.getStatus());
        verify(scanRepo).save(testScan);
    }

    @Test
    void jobs_returnsJobsForScan() {
        List<ScanJob> jobs = List.of(
                ScanJob.builder().scanId(testScan.getId()).scannerPlugin("sast-plugin").build()
        );
        when(jobRepo.findByScanId(testScan.getId())).thenReturn(jobs);

        List<ScanJob> result = scanService.jobs(testScan.getId());

        assertEquals(1, result.size());
        assertEquals("sast-plugin", result.get(0).getScannerPlugin());
    }
}
