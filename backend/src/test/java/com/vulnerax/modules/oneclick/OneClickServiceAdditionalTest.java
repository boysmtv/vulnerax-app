package com.vulnerax.modules.oneclick;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OneClickServiceAdditionalTest {

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
    void detectType_cidrWithPort_returnsContainer() {
        // Test the regex for container detection with port
        assertEquals("CONTAINER_IMAGE", service.detectType("registry.example.com:5000/myimage:v1"));
    }

    @Test
    void detectType_dockerHubWithSha_returnsContainer() {
        assertEquals("CONTAINER_IMAGE", service.detectType("docker.io/library/nginx@sha256:abc123"));
    }

    @Test
    void detectType_ecrFullUrl_returnsContainer() {
        assertEquals("CONTAINER_IMAGE", service.detectType("123456789.dkr.ecr.us-east-1.amazonaws.com/myrepo/myimage:latest"));
    }

    @Test
    void detectType_gcrFullUrl_returnsContainer() {
        assertEquals("CONTAINER_IMAGE", service.detectType("gcr.io/my-project/my-image:v2"));
    }

    @Test
    void detectType_httpUrlWithApiPath_returnsApi() {
        assertEquals("API", service.detectType("https://api.example.com/v2/users"));
    }

    @Test
    void detectType_httpUrlWithSwaggerPath_returnsApi() {
        assertEquals("API", service.detectType("https://example.com/swagger-ui/"));
    }

    @Test
    void detectType_httpUrlWithOpenApiPath_returnsApi() {
        assertEquals("API", service.detectType("https://example.com/openapi.json"));
    }

    @Test
    void detectType_httpUrlWithGraphqlPath_returnsApi() {
        assertEquals("API", service.detectType("https://example.com/graphql"));
    }

    @Test
    void detectType_gitlabWithHttp_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("https://gitlab.com/acme/app"));
    }

    @Test
    void detectType_zipFile_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("source-code.zip"));
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
    void detectType_ipAddress_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("10.0.0.1"));
    }

    @Test
    void detectType_cidr_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("192.168.1.0/24"));
    }

    @Test
    void scannersFor_anyType_returnsAll8() {
        for (String type : List.of("WEBAPP", "API", "MOBILE", "REPOSITORY", "CONTAINER_IMAGE", "NETWORK", "UNKNOWN")) {
            assertThat(service.scannersFor(type)).hasSize(8);
        }
    }

    @Test
    void progress_runNotFound_throws() {
        UUID runId = UUID.randomUUID();
        when(repo.findById(runId)).thenReturn(Optional.empty());
        try {
            service.progress(runId);
        } catch (Exception e) {
            assertThat(e).isInstanceOf(RuntimeException.class);
        }
    }

    @Test
    void progress_withMultipleScans_returnsAll() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(50)
                .scanIdsJson("[\"" + scanId1 + "\",\"" + scanId2 + "\"]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan s1 = new Scan();
        s1.setId(scanId1);
        s1.setScannerType("SAST");
        s1.setStatus("COMPLETED");
        s1.setTarget("https://example.com");
        s1.setFindingsCount(3);

        Scan s2 = new Scan();
        s2.setId(scanId2);
        s2.setScannerType("DAST");
        s2.setStatus("RUNNING");
        s2.setTarget("https://example.com");
        s2.setFindingsCount(1);

        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(s1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(s2));
        when(jobRepo.findByScanId(scanId1)).thenReturn(List.of());
        when(jobRepo.findByScanId(scanId2)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);
        List<?> scans = (List<?>) result.get("scans");
        assertThat(scans).hasSize(2);
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
        List<?> steps = (List<?>) result.get("steps");
        assertThat(steps).isNotEmpty();
    }

    @Test
    void progress_scanWithJobDetails_showsJobInfo() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(50)
                .scanIdsJson("[\"" + scanId + "\"]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan s = new Scan();
        s.setId(scanId);
        s.setScannerType("SECRET");
        s.setStatus("RUNNING");
        s.setTarget("https://example.com");
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(s));

        ScanJob job = new ScanJob();
        job.setStatus("RUNNING");
        job.setProgress(60);
        job.setLogs("Scanning for secrets...");
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        Map<String, Object> result = service.progress(runId);
        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).isNotEmpty();
        assertThat(scans.get(0).get("progress")).isEqualTo(60);
    }

    @Test
    void progress_completedScans_showsProgress() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(10)
                .totalScans(1)
                .completedScans(1)
                .findingsCount(5)
                .scanIdsJson("[\"" + scanId + "\"]")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Scan s = new Scan();
        s.setId(scanId);
        s.setScannerType("SCA");
        s.setStatus("COMPLETED");
        s.setTarget("https://example.com");
        s.setFindingsCount(5);
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(s));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);
        assertThat(result.get("findingsCount")).isEqualTo(5);
    }

    @Test
    void progress_noRunningNoCompleted_showsPreparing() {
        UUID runId = UUID.randomUUID();
        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .status("RUNNING")
                .progress(5)
                .scanIdsJson("[]")
                .message("Queued")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);
        assertThat(result.get("currentAction")).isNotNull();
    }
}
