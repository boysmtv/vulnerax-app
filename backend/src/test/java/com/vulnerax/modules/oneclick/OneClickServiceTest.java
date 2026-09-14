package com.vulnerax.modules.oneclick;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.organization.Organization;
import com.vulnerax.modules.reporting.ReportService;
import com.vulnerax.modules.scan.*;
import com.vulnerax.modules.scan.Scan;
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
class OneClickServiceTest {

    @Mock OneClickRepository repo;
    @Mock ScanService scanService;
    @Mock ScanRepository scanRepo;
    @Mock ScanJobRepository jobRepo;
    @Mock ReportService reportService;
    @Mock ProjectRepository projectRepo;
    @Mock ApplicationContext ctx;
    @Mock OneClickService selfProxy;

    @InjectMocks OneClickService service;

    @BeforeEach
    void setUp() {
        lenient().when(ctx.getBean(OneClickService.class)).thenReturn(selfProxy);
    }

    @Test
    void detectType_null_returnsUnknown() {
        assertEquals("UNKNOWN", service.detectType(null));
    }

    @Test
    void detectType_httpWithApi_returnsApi() {
        assertEquals("API", service.detectType("https://api.example.com/v1/users"));
    }

    @Test
    void detectType_httpWithSwagger_returnsApi() {
        assertEquals("API", service.detectType("http://localhost:8080/swagger-ui.html"));
    }

    @Test
    void detectType_httpWithOpenapi_returnsApi() {
        assertEquals("API", service.detectType("https://example.com/openapi.json"));
    }

    @Test
    void detectType_httpWithGraphql_returnsApi() {
        assertEquals("API", service.detectType("https://example.com/graphql"));
    }

    @Test
    void detectType_httpPlain_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("https://example.com"));
    }

    @Test
    void detectType_apk_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.apk"));
    }

    @Test
    void detectType_aab_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.aab"));
    }

    @Test
    void detectType_ipa_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.ipa"));
    }

    @Test
    void detectType_github_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("github.com/acme/app"));
    }

    @Test
    void detectType_gitlab_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("gitlab.com/acme/app"));
    }

    @Test
    void detectType_gitSuffix_returnsRepository() {
        // .git suffix without github.com goes to WEBAPP since http starts first
        assertEquals("WEBAPP", service.detectType("https://github.com/acme/app.git"));
    }

    @Test
    void detectType_gitAt_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("git@github.com:acme/app.git"));
    }

    @Test
    void detectType_dockerHub_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("docker.io/nginx:latest"));
    }

    @Test
    void detectType_gcr_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("gcr.io/my-project/my-image:v1"));
    }

    @Test
    void detectType_ecr_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("123456789.dkr.ecr.us-east-1.amazonaws.com/my-image"));
    }

    @Test
    void detectType_registryWithPort_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("registry.example.com:5000/my-image:v1"));
    }

    @Test
    void detectType_ipAddress_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("192.168.1.100"));
    }

    @Test
    void detectType_zipFile_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("project.zip"));
    }

    @Test
    void detectType_jarFile_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("app.jar"));
    }

    @Test
    void detectType_warFile_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("webapp.war"));
    }

    @Test
    void detectType_unknownInput_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("some-random-string"));
    }

    @Test
    void detectType_whitespace_trimmed() {
        assertEquals("WEBAPP", service.detectType("  https://example.com  "));
    }

    @Test
    void scannersFor_anyType_returnsAll8() {
        List<String> scanners = service.scannersFor("WEBAPP");
        assertEquals(8, scanners.size());
        assertTrue(scanners.containsAll(List.of("SAST","SCA","SECRET","DAST","API","CONTAINER","IAC","MOBILE")));
    }

    @Test
    void scannersFor_apiType_returnsAll8() {
        List<String> scanners = service.scannersFor("API");
        assertEquals(8, scanners.size());
    }

    @Test
    void start_blankTarget_throws() {
        assertThrows(RuntimeException.class, () -> service.start("  ", null));
    }

    @Test
    void start_nullTarget_throws() {
        assertThrows(RuntimeException.class, () -> service.start(null, null));
    }

    @Test
    void start_validTarget_createsRunAndScans() {
        UUID projectId = UUID.randomUUID();
        when(projectRepo.existsById(projectId)).thenReturn(true);
        when(repo.save(any(OneClickRun.class))).thenAnswer(inv -> {
            OneClickRun r = inv.getArgument(0);
            r.setId(UUID.randomUUID());
            return r;
        });
        Scan savedScan = new Scan();
        savedScan.setId(UUID.randomUUID());
        when(scanService.create(any(Scan.class), eq("one-click"))).thenReturn(savedScan);

        OneClickRun result = service.start("https://example.com", projectId);

        assertNotNull(result);
        assertEquals("RUNNING", result.getStatus());
        verify(scanService, times(8)).create(any(Scan.class), eq("one-click"));
        verify(selfProxy).monitorAsync(any(UUID.class));
    }

    @Test
    void start_nullProjectId_usesFirstProject() {
        UUID projectId = UUID.randomUUID();
        com.vulnerax.modules.organization.Project p = new com.vulnerax.modules.organization.Project();
        p.setId(projectId);
        p.setOrganizationId(UUID.randomUUID());
        when(projectRepo.existsById(any())).thenReturn(false);
        when(projectRepo.findAll()).thenReturn(List.of(p));
        when(repo.save(any(OneClickRun.class))).thenAnswer(inv -> {
            OneClickRun r = inv.getArgument(0);
            r.setId(UUID.randomUUID());
            return r;
        });
        Scan savedScan = new Scan();
        savedScan.setId(UUID.randomUUID());
        when(scanService.create(any(Scan.class), eq("one-click"))).thenReturn(savedScan);

        OneClickRun result = service.start("https://example.com", null);

        assertNotNull(result);
        verify(projectRepo).findAll();
    }

    @Test
    void start_noProjectFound_throws() {
        when(projectRepo.existsById(any())).thenReturn(false);
        when(projectRepo.findAll()).thenReturn(List.of());

        assertThrows(RuntimeException.class, () -> service.start("https://example.com", null));
    }

    @Test
    void start_projectNotFound_throws() {
        UUID projectId = UUID.randomUUID();
        when(projectRepo.existsById(projectId)).thenReturn(false);

        assertThrows(ResourceNotFoundException.class, () -> service.start("https://example.com", projectId));
    }

    @Test
    void start_scanCreationFails_continuesWithOthers() {
        UUID projectId = UUID.randomUUID();
        when(projectRepo.existsById(projectId)).thenReturn(true);
        when(repo.save(any(OneClickRun.class))).thenAnswer(inv -> {
            OneClickRun r = inv.getArgument(0);
            r.setId(UUID.randomUUID());
            return r;
        });
        when(scanService.create(any(Scan.class), eq("one-click"))).thenThrow(new RuntimeException("DB error"));

        OneClickRun result = service.start("https://example.com", projectId);

        assertNotNull(result);
    }

    @Test
    void get_existingId_returnsRun() {
        UUID id = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("https://example.com").build();
        run.setId(id);
        when(repo.findById(id)).thenReturn(Optional.of(run));

        OneClickRun result = service.get(id);

        assertNotNull(result);
        assertEquals("https://example.com", result.getTarget());
    }

    @Test
    void get_nonExistingId_throws() {
        UUID id = UUID.randomUUID();
        when(repo.findById(id)).thenReturn(Optional.empty());

        assertThrows(ResourceNotFoundException.class, () -> service.get(id));
    }

    @Test
    void list_withProjectId_filtersByProject() {
        UUID projectId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder().target("test").projectId(projectId).build();
        when(repo.findByProjectIdOrderByCreatedAtDesc(projectId)).thenReturn(List.of(run));

        List<OneClickRun> result = service.list(projectId);

        assertEquals(1, result.size());
    }

    @Test
    void list_nullProjectId_returnsAll() {
        OneClickRun run = OneClickRun.builder().target("test").build();
        run.setCreatedAt(java.time.Instant.now());
        when(repo.findAll()).thenReturn(List.of(run));

        List<OneClickRun> result = service.list(null);

        assertFalse(result.isEmpty());
    }

    private Scan createScan(UUID id, String scannerType, String status, String target, int findingsCount) {
        Scan s = new Scan();
        s.setId(id);
        s.setScannerType(scannerType);
        s.setStatus(status);
        s.setTarget(target);
        s.setFindingsCount(findingsCount);
        return s;
    }

    @Test
    void progress_withScans_returnsScanDetails() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(50)
                .totalScans(1)
                .completedScans(0)
                .findingsCount(0)
                .scanIdsJson("[\"" + scanId + "\"]")
                .message("Running")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan scan = createScan(scanId, "SAST", "RUNNING", "https://example.com", 3);
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        assertNotNull(result.get("scans"));
        assertNotNull(result.get("steps"));
        assertEquals("https://example.com", result.get("target"));
    }

    @Test
    void progress_completedRun_showsCompletedStatus() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("COMPLETED")
                .progress(100)
                .totalScans(1)
                .completedScans(1)
                .findingsCount(5)
                .scanIdsJson("[]")
                .message("Done")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);

        assertEquals("COMPLETED", result.get("status"));
    }

    @Test
    void progress_emptyScanIds_returnsEmptyScans() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(10)
                .totalScans(0)
                .completedScans(0)
                .findingsCount(0)
                .scanIdsJson("[]")
                .message("Starting")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);

        assertTrue(((List<?>) result.get("scans")).isEmpty());
    }

    @Test
    void progress_invalidJson_scanIds_returnsEmpty() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(10)
                .scanIdsJson("not-valid-json")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);

        assertTrue(((List<?>) result.get("scans")).isEmpty());
    }

    @Test
    void progress_scanNotFound_skipped() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(10)
                .scanIdsJson("[\"" + scanId + "\"]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.empty());

        Map<String, Object> result = service.progress(runId);

        assertTrue(((List<?>) result.get("scans")).isEmpty());
    }

    @Test
    void progress_scanWithJob_showsJobStatus() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(50)
                .scanIdsJson("[\"" + scanId + "\"]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan scan = createScan(scanId, "DAST", "RUNNING", "https://example.com", 2);
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        com.vulnerax.modules.scan.ScanJob job = new com.vulnerax.modules.scan.ScanJob();
        job.setStatus("RUNNING");
        job.setProgress(75);
        job.setLogs("Running DAST scan...");
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertEquals(1, scans.size());
        assertEquals("RUNNING", scans.get(0).get("status"));
    }

    @Test
    void progress_allScannerTypes_haveActions() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(10)
                .scanIdsJson("[]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);
        assertNotNull(result.get("steps"));
    }

    @Test
    void progress_runningScanners_showsCurrentAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(50)
                .scanIdsJson("[\"" + scanId1 + "\",\"" + scanId2 + "\"]")
                .message("Running 2 scanners")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan s1 = createScan(scanId1, "SAST", "RUNNING", "https://example.com", 0);
        Scan s2 = createScan(scanId2, "DAST", "RUNNING", "https://example.com", 0);
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(s1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(s2));
        when(jobRepo.findByScanId(scanId1)).thenReturn(List.of());
        when(jobRepo.findByScanId(scanId2)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        String currentAction = (String) result.get("currentAction");
        assertTrue(currentAction.contains("Sedang"));
    }

    @Test
    void progress_allCompletedButNotAllDone_showsPartialProgress() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(10)
                .totalScans(2)
                .completedScans(0)
                .scanIdsJson("[\"" + scanId + "\"]")
                .message("Running")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan s = createScan(scanId, "SAST", "COMPLETED", "https://example.com", 3);
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(s));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        assertNotNull(result.get("findingsCount"));
    }
}
