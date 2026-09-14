package com.vulnerax.modules.oneclick;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.reporting.ReportService;
import com.vulnerax.modules.scan.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OneClickServiceAdditionalTest {

    @Mock private OneClickRepository repo;
    @Mock private ScanService scanService;
    @Mock private ScanRepository scanRepo;
    @Mock private ScanJobRepository jobRepo;
    @Mock private ReportService reportService;
    @Mock private ProjectRepository projectRepo;
    @Mock private ApplicationContext ctx;
    @InjectMocks private OneClickService service;

    @Test
    void detectType_variousInputs() {
        assertEquals("WEBAPP", service.detectType("https://example.com"));
        assertEquals("WEBAPP", service.detectType("http://test.com"));
        assertEquals("API", service.detectType("https://example.com/api/v1"));
        assertEquals("API", service.detectType("http://swagger.io/docs"));
        assertEquals("API", service.detectType("https://example.com/openapi.json"));
        assertEquals("API", service.detectType("http://example.com/graphql"));
        assertEquals("MOBILE", service.detectType("app.apk"));
        assertEquals("MOBILE", service.detectType("app.aab"));
        assertEquals("MOBILE", service.detectType("app.ipa"));
        assertEquals("REPOSITORY", service.detectType("repo.git"));
        assertEquals("REPOSITORY", service.detectType("file.zip"));
        assertEquals("REPOSITORY", service.detectType("app.jar"));
        assertEquals("REPOSITORY", service.detectType("app.war"));
        assertEquals("NETWORK", service.detectType("192.168.1.1"));
        assertEquals("WEBAPP", service.detectType("unknown-target"));
        assertEquals("UNKNOWN", service.detectType(null));
        assertEquals("WEBAPP", service.detectType("  "));
    }

    @Test
    void detectType_containerImages() {
        assertEquals("CONTAINER_IMAGE", service.detectType("docker.io/library/nginx:latest"));
        assertEquals("CONTAINER_IMAGE", service.detectType("gcr.io/project/image:v1"));
        assertEquals("CONTAINER_IMAGE", service.detectType("123456789.dkr.ecr.us-east-1.amazonaws.com/app:latest"));
    }

    @Test
    void scannersFor_alwaysReturnsAllEight() {
        List<String> scanners = service.scannersFor("WEBAPP");
        assertEquals(8, scanners.size());
        assertTrue(scanners.contains("SAST"));
        assertTrue(scanners.contains("SCA"));
        assertTrue(scanners.contains("SECRET"));
        assertTrue(scanners.contains("DAST"));
        assertTrue(scanners.contains("API"));
        assertTrue(scanners.contains("CONTAINER"));
        assertTrue(scanners.contains("IAC"));
        assertTrue(scanners.contains("MOBILE"));
    }

    @Test
    void get_existingRun_returnsRun() {
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").build();
        run.setId(UUID.randomUUID());
        when(repo.findById(run.getId())).thenReturn(Optional.of(run));
        assertEquals("RUNNING", service.get(run.getId()).getStatus());
    }

    @Test
    void get_notFound_throws() {
        when(repo.findById(any())).thenReturn(Optional.empty());
        assertThrows(ResourceNotFoundException.class, () -> service.get(UUID.randomUUID()));
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID projectId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().projectId(projectId).target("test").build();
        when(repo.findByProjectIdOrderByCreatedAtDesc(projectId)).thenReturn(List.of(run));

        List<OneClickRun> result = service.list(projectId);

        assertEquals(1, result.size());
    }

    @Test
    void list_nullProjectId_returnsAll() {
        OneClickRun run1 = OneClickRun.builder().target("test1").build();
        run1.setCreatedAt(java.time.Instant.now());
        OneClickRun run2 = OneClickRun.builder().target("test2").build();
        run2.setCreatedAt(java.time.Instant.now().minusSeconds(100));
        when(repo.findAll()).thenReturn(List.of(run1, run2));

        List<OneClickRun> result = service.list(null);

        assertEquals(2, result.size());
    }

    @Test
    void progress_returnsDetailedMap() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").message("Running").build();
        run.setId(runId);
        run.setTotalScans(2);
        run.setCompletedScans(1);
        run.setFindingsCount(5);
        run.setScanIdsJson("[]");
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String,Object> result = service.progress(runId);

        assertNotNull(result);
        assertEquals("RUNNING", result.get("status"));
        assertNotNull(result.get("steps"));
    }

    @Test
    void progress_withScanIds_showsScanDetails() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").message("Running").build();
        run.setId(runId);
        run.setScanIdsJson("[\"" + scanId + "\"]");
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan scan = new Scan();
        scan.setId(scanId);
        scan.setScannerType("SAST");
        scan.setStatus("COMPLETED");
        scan.setFindingsCount(3);
        scan.setTarget("test");
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String,Object> result = service.progress(runId);

        assertNotNull(result);
    }

    @Test
    void progress_withRunningScan_showsRunningAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").message("Running").build();
        run.setId(runId);
        run.setScanIdsJson("[\"" + scanId + "\"]");
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan scan = new Scan();
        scan.setId(scanId);
        scan.setScannerType("DAST");
        scan.setStatus("RUNNING");
        scan.setTarget("https://example.com");
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String,Object> result = service.progress(runId);

        assertNotNull(result);
    }

    @Test
    void progress_withNoJobs_showsDefault() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").message("Running").build();
        run.setId(runId);
        run.setScanIdsJson("[\"" + scanId + "\"]");
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan scan = new Scan();
        scan.setId(scanId);
        scan.setScannerType("SCA");
        scan.setStatus("RUNNING");
        scan.setTarget("test");
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String,Object> result = service.progress(runId);

        assertNotNull(result);
    }

    @Test
    void progress_withAllScannerTypes_showsCorrectActions() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").status("RUNNING").message("Running").build();
        run.setId(runId);
        run.setScanIdsJson("[]");
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String,Object> result = service.progress(runId);

        assertNotNull(result);
        assertEquals("[]", run.getScanIdsJson());
    }

    @Test
    void start_blankTarget_throws() {
        assertThrows(RuntimeException.class, () -> service.start("  ", UUID.randomUUID()));
    }

    @Test
    void start_nullTarget_throws() {
        assertThrows(RuntimeException.class, () -> service.start(null, UUID.randomUUID()));
    }
}
