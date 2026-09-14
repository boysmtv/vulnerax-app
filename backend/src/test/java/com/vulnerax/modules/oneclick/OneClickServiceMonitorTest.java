package com.vulnerax.modules.oneclick;

import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.reporting.Report;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OneClickServiceMonitorTest {

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

    private Scan buildScan(UUID id, String scannerType, String status, String target, Integer findingsCount) {
        Scan s = new Scan();
        s.setId(id);
        s.setScannerType(scannerType);
        s.setStatus(status);
        s.setTarget(target);
        s.setFindingsCount(findingsCount);
        return s;
    }

    private OneClickRun buildRun(UUID id, String status, Integer progress, String scanIdsJson,
                                 Integer totalScans, Integer completedScans, Integer findingsCount,
                                 String target, String message) {
        OneClickRun run = OneClickRun.builder()
                .projectId(UUID.randomUUID())
                .target(target)
                .detectedType("WEBAPP")
                .status(status)
                .progress(progress)
                .totalScans(totalScans)
                .completedScans(completedScans)
                .findingsCount(findingsCount)
                .scanIdsJson(scanIdsJson)
                .message(message)
                .build();
        run.setId(id);
        return run;
    }

    private ScanJob buildJob(UUID scanId, String status, Integer progress, String logs) {
        return ScanJob.builder()
                .scanId(scanId)
                .status(status)
                .progress(progress)
                .logs(logs)
                .build();
    }

    private Report buildReport() {
        Report r = Report.builder()
                .projectId(UUID.randomUUID())
                .type("EXECUTIVE")
                .title("One-Click Report")
                .format("PDF")
                .status("READY")
                .build();
        r.setId(UUID.randomUUID());
        return r;
    }

    // ═════════════════════════════════════════════════════════════════════════
    // monitorAsync tests
    // Each test takes ~2s due to Thread.sleep(2000) in the monitor loop.
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void monitorAsync_allScansCompleted_generatesReport() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 1, 3, "https://example.com", "Running 2 scanners");

        Scan completedScan1 = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 5);
        Scan completedScan2 = buildScan(scanId2, "DAST", "COMPLETED", "https://example.com", 3);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(completedScan1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(completedScan2));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(reportService).generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF"));
        verify(repo, atLeastOnce()).save(argThat(r ->
                "COMPLETED".equals(r.getStatus()) && r.getReportId() != null
        ));
    }

    @Test
    void monitorAsync_allScansFailed_treatsAsCompleteAndGeneratesReport() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");

        Scan failedScan1 = buildScan(scanId1, "SAST", "FAILED", "https://example.com", 0);
        Scan failedScan2 = buildScan(scanId2, "DAST", "FAILED", "https://example.com", 0);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(failedScan1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(failedScan2));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(reportService).generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF"));
        verify(repo, atLeastOnce()).save(argThat(r -> "COMPLETED".equals(r.getStatus())));
    }

    @Test
    void monitorAsync_scanCancelled_countsAsComplete() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");

        Scan completedScan = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 2);
        Scan cancelledScan = buildScan(scanId2, "DAST", "CANCELLED", "https://example.com", 0);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(completedScan));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(cancelledScan));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(reportService).generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF"));
        verify(repo, atLeastOnce()).save(argThat(r -> "COMPLETED".equals(r.getStatus())));
    }

    @Test
    void monitorAsync_reportGenerationFailsStillCompletes() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running 1 scanner");

        Scan completedScan = buildScan(scanId, "SAST", "COMPLETED", "https://example.com", 3);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(completedScan));
        when(reportService.generate(any(UUID.class), any(), any(), any()))
                .thenThrow(new RuntimeException("Report generation failed: DB timeout"));

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r ->
                "COMPLETED".equals(r.getStatus()) &&
                        r.getMessage() != null &&
                        r.getMessage().contains("report gagal")
        ));
    }

    @Test
    void monitorAsync_runNotFound_exits() {
        UUID runId = UUID.randomUUID();

        when(repo.findById(runId)).thenReturn(Optional.empty());

        service.monitorAsync(runId);

        verify(scanRepo, never()).findById(any());
        verify(reportService, never()).generate(any(), any(), any(), any());
    }

    @Test
    void monitorAsync_timeoutViaInterrupt_setsFailed() throws InterruptedException {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running 1 scanner");
        Scan runningScan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(runningRun));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(runningScan));

        CountDownLatch started = new CountDownLatch(1);
        Thread monitorThread = new Thread(() -> {
            started.countDown();
            service.monitorAsync(runId);
        });
        monitorThread.setDaemon(true);
        monitorThread.start();

        assertTrue(started.await(5, TimeUnit.SECONDS));
        Thread.sleep(500);
        monitorThread.interrupt();
        monitorThread.join(5000);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            return "FAILED".equals(r.getStatus());
        }));
    }

    @Test
    void monitorAsync_mixedStatuses_savesProgressWhileRunning() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");

        OneClickRun completedRun = buildRun(runId, "COMPLETED", 80,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 1, 3, "https://example.com", "1/2 done");

        Scan completedScan = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 3);
        Scan runningScan = buildScan(scanId2, "DAST", "RUNNING", "https://example.com", 2);

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(completedScan));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(runningScan));

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            if (r.getProgress() != null && r.getProgress() > 0) return true;
            return false;
        }));
    }

    @Test
    void monitorAsync_scanNotFoundInRepo_countsAsNotComplete() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");

        OneClickRun completedRun = buildRun(runId, "COMPLETED", 80,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 1, 3, "https://example.com", "1/2 done");

        Scan completedScan = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 3);

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(completedScan));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.empty());

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            if ("RUNNING".equals(r.getStatus()) && r.getCompletedScans() != null && r.getCompletedScans() == 1) {
                return true;
            }
            return false;
        }));
    }

    @Test
    void monitorAsync_findingsCountAggregated() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");

        Scan scan1 = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 10);
        Scan scan2 = buildScan(scanId2, "DAST", "COMPLETED", "https://example.com", 7);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(scan1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(scan2));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            if (r.getFindingsCount() != null && r.getFindingsCount() == 17) return true;
            return false;
        }));
    }

    @Test
    void monitorAsync_nullFindingsCount_treatedAsZero() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running 1 scanner");

        Scan scan = buildScan(scanId, "SAST", "COMPLETED", "https://example.com", null);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> "COMPLETED".equals(r.getStatus())));
    }

    @Test
    void monitorAsync_alreadyCompleted_exitsImmediately() {
        UUID runId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "COMPLETED", 100,
                "[]", 0, 0, 0, "https://example.com", "Done");

        when(repo.findById(runId)).thenReturn(Optional.of(run));

        service.monitorAsync(runId);

        verify(scanRepo, never()).findById(any());
        verify(reportService, never()).generate(any(), any(), any(), any());
    }

    @Test
    void monitorAsync_alreadyFailed_exitsImmediately() {
        UUID runId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "FAILED", 50,
                "[]", 0, 0, 0, "https://example.com", "Failed");

        when(repo.findById(runId)).thenReturn(Optional.of(run));

        service.monitorAsync(runId);

        verify(scanRepo, never()).findById(any());
    }

    @Test
    void monitorAsync_emptyScanIds_continuesLoop() {
        UUID runId = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 5,
                "[]", 0, 0, 0, "https://example.com", "Queued 0 scanners");
        OneClickRun completedRun = buildRun(runId, "COMPLETED", 100,
                "[]", 0, 0, 0, "https://example.com", "Done");

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });

        service.monitorAsync(runId);

        verify(scanRepo, never()).findById(any());
    }

    @Test
    void monitorAsync_dastRunning_addsDastDetail() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Running 2 scanners");
        OneClickRun completedRun = buildRun(runId, "COMPLETED", 80,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Done");

        Scan sastRunning = buildScan(scanId1, "SAST", "RUNNING", "https://example.com", 0);
        Scan dastRunning = buildScan(scanId2, "DAST", "RUNNING", "https://example.com", 0);

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(sastRunning));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(dastRunning));

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            return r.getMessage() != null && r.getMessage().contains("DAST");
        }));
    }

    @Test
    void monitorAsync_apiRunning_addsDastDetail() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://api.example.com", "Running 1 scanner");
        OneClickRun completedRun = buildRun(runId, "COMPLETED", 80,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://api.example.com", "Done");

        Scan apiRunning = buildScan(scanId, "API", "RUNNING", "https://api.example.com", 0);

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(apiRunning));

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            return r.getMessage() != null && r.getMessage().contains("API");
        }));
    }

    @Test
    void monitorAsync_noRunningNoCompleted_showsPreparing() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun runningRun = buildRun(runId, "RUNNING", 5,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Queued 2 scanners");
        OneClickRun completedRun = buildRun(runId, "COMPLETED", 100,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 0, 0, "https://example.com", "Done");

        Scan queuedScan1 = buildScan(scanId1, "SAST", "QUEUED", "https://example.com", null);
        Scan queuedScan2 = buildScan(scanId2, "DAST", "QUEUED", "https://example.com", null);

        final int[] callCount = {0};
        when(repo.findById(runId)).thenAnswer(inv -> {
            callCount[0]++;
            return callCount[0] == 1 ? Optional.of(runningRun) : Optional.of(completedRun);
        });
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(queuedScan1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(queuedScan2));

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            return r.getMessage() != null && r.getMessage().contains("Menyiapkan");
        }));
    }

    @Test
    void monitorAsync_reportSetsProgress100() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan completedScan = buildScan(scanId, "SAST", "COMPLETED", "https://example.com", 5);
        Report report = buildReport();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(completedScan));
        when(reportService.generate(any(UUID.class), eq("EXECUTIVE"), contains("One-Click Report"), eq("PDF")))
                .thenReturn(report);

        service.monitorAsync(runId);

        verify(repo, atLeastOnce()).save(argThat(r -> {
            if (r == null) return false;
            if ("COMPLETED".equals(r.getStatus()) && r.getProgress() != null && r.getProgress() == 100) {
                return true;
            }
            return false;
        }));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // progress tests — switch statement coverage for all scanner types
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void progress_allScannerTypes_haveActions() {
        UUID runId = UUID.randomUUID();
        String[] scannerTypes = {"SAST", "SCA", "SECRET", "DAST", "API", "CONTAINER", "IAC", "MOBILE"};
        StringBuilder sb = new StringBuilder("[");
        List<UUID> ids = new ArrayList<>();
        for (int i = 0; i < scannerTypes.length; i++) {
            UUID sid = UUID.randomUUID();
            ids.add(sid);
            if (i > 0) sb.append(",");
            sb.append("\"").append(sid).append("\"");
        }
        sb.append("]");

        OneClickRun run = buildRun(runId, "RUNNING", 50, sb.toString(),
                scannerTypes.length, 0, 0, "https://example.com", "Running 8 scanners");

        when(repo.findById(runId)).thenReturn(Optional.of(run));

        for (int i = 0; i < scannerTypes.length; i++) {
            UUID sid = ids.get(i);
            Scan s = buildScan(sid, scannerTypes[i], "COMPLETED", "https://example.com", i);
            when(scanRepo.findById(sid)).thenReturn(Optional.of(s));
            when(jobRepo.findByScanId(sid)).thenReturn(List.of());
        }

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(8);

        for (Map<String, Object> scanMap : scans) {
            assertThat(scanMap.get("action")).isNotNull();
            assertThat(((String) scanMap.get("action"))).isNotBlank();
        }

        assertThat(result.get("steps")).isNotNull();
        assertThat(((List<?>) result.get("steps"))).isNotEmpty();
    }

    @Test
    void progress_withRunningScanner_showsRunningAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan sastRunning = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(sastRunning));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        String currentAction = (String) result.get("currentAction");
        assertThat(currentAction).contains("Sedang");
        assertThat(currentAction).contains("SAST");
    }

    @Test
    void progress_withDastScanner_showsDastDetail() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan dastRunning = buildScan(scanId, "DAST", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(dastRunning));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(1);
        assertThat(scans.get(0).get("action").toString()).contains("Fetch");
        assertThat(scans.get(0).get("action").toString()).contains("headers");
    }

    @Test
    void progress_withNoRunningNoCompleted_showsPreparing() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 5,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Queued");

        Scan queuedScan = buildScan(scanId, "SAST", "QUEUED", "https://example.com", null);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(queuedScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(1);
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("SAST");
        assertThat(action).contains("Analisis");
    }

    @Test
    void progress_withCompletedScans_showsFindingsCount() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 80,
                "[\"" + scanId + "\"]",
                1, 1, 7, "https://example.com", "1/1 selesai");

        Scan completedScan = buildScan(scanId, "SCA", "COMPLETED", "https://example.com", 7);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(completedScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        assertThat(result.get("findingsCount")).isEqualTo(7);
        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(1);
        assertThat(scans.get(0).get("findings")).isEqualTo(7);
    }

    @Test
    void progress_unknownScannerType_defaultAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan customScan = buildScan(scanId, "CUSTOM_SCANNER", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(customScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(1);
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("CUSTOM_SCANNER");
        assertThat(action).startsWith("Scan ");
    }

    @Test
    void progress_sastAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan sastScan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(sastScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("injection");
        assertThat(action).contains("XSS");
        assertThat(action).contains("crypto");
    }

    @Test
    void progress_scaAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scaScan = buildScan(scanId, "SCA", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scaScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("dependency");
        assertThat(action).contains("CVE");
    }

    @Test
    void progress_secretAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan secretScan = buildScan(scanId, "SECRET", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(secretScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("secret");
        assertThat(action).contains("API key");
    }

    @Test
    void progress_apiAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://api.example.com", "Running");

        Scan apiScan = buildScan(scanId, "API", "RUNNING", "https://api.example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(apiScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("API");
        assertThat(action).contains("GraphQL");
    }

    @Test
    void progress_containerAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "docker.io/nginx", "Running");

        Scan containerScan = buildScan(scanId, "CONTAINER", "RUNNING", "docker.io/nginx", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(containerScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("image");
        assertThat(action).contains("secret");
    }

    @Test
    void progress_iacAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "terraform.tf", "Running");

        Scan iacScan = buildScan(scanId, "IAC", "RUNNING", "terraform.tf", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(iacScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("Terraform");
        assertThat(action).contains("Dockerfile");
    }

    @Test
    void progress_mobileAction_containsExpectedKeywords() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "app.apk", "Running");

        Scan mobileScan = buildScan(scanId, "MOBILE", "RUNNING", "app.apk", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(mobileScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        String action = (String) scans.get(0).get("action");
        assertThat(action).contains("APK");
        assertThat(action).contains("MASVS");
    }

    @Test
    void progress_nullScannerType_usesDefaultAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan nullTypeScan = buildScan(scanId, null, "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(nullTypeScan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans).hasSize(1);
        String action = (String) scans.get(0).get("action");
        assertThat(action).startsWith("Scan ");
    }

    @Test
    void progress_scanWithNullFindingsCount_showsZero() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", null);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("findings")).isEqualTo(0);
    }

    @Test
    void progress_scanWithNullTarget_showsEmptyString() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "RUNNING", null, 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("target")).isEqualTo("");
    }

    @Test
    void progress_scanWithNullStatus_usesScanStatus() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "QUEUED", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("status")).isEqualTo("QUEUED");
    }

    @Test
    void progress_scanWithNullScannerType_usesUnknown() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, null, "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("scannerType")).isEqualTo("UNKNOWN");
    }

    @Test
    void progress_scanWithJobDetails_showsJobProgress() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);
        ScanJob job = buildJob(scanId, "RUNNING", 75, "Analyzing source code...");

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("progress")).isEqualTo(75);
        assertThat(scans.get(0).get("logs")).isEqualTo("Analyzing source code...");
        assertThat(scans.get(0).get("status")).isEqualTo("RUNNING");
    }

    @Test
    void progress_multipleRunningScanners_showsAllInCurrentAction() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();
        UUID scanId3 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\",\"" + scanId3 + "\"]",
                3, 0, 0, "https://example.com", "Running 3 scanners");

        Scan sastScan = buildScan(scanId1, "SAST", "RUNNING", "https://example.com", 0);
        Scan scaScan = buildScan(scanId2, "SCA", "RUNNING", "https://example.com", 0);
        Scan secretScan = buildScan(scanId3, "SECRET", "RUNNING", "https://example.com", 0);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(sastScan));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(scaScan));
        when(scanRepo.findById(scanId3)).thenReturn(Optional.of(secretScan));
        when(jobRepo.findByScanId(any())).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        String currentAction = (String) result.get("currentAction");
        assertThat(currentAction).contains("Sedang");
        assertThat(currentAction).contains("SAST");
        assertThat(currentAction).contains("SCA");
        assertThat(currentAction).contains("SECRET");
    }

    @Test
    void progress_completedScansNoRunning_showsFinishedMessage() {
        UUID runId = UUID.randomUUID();
        UUID scanId1 = UUID.randomUUID();
        UUID scanId2 = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 75,
                "[\"" + scanId1 + "\",\"" + scanId2 + "\"]",
                2, 2, 10, "https://example.com", "2/2 selesai");

        Scan scan1 = buildScan(scanId1, "SAST", "COMPLETED", "https://example.com", 5);
        Scan scan2 = buildScan(scanId2, "DAST", "COMPLETED", "https://example.com", 5);

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId1)).thenReturn(Optional.of(scan1));
        when(scanRepo.findById(scanId2)).thenReturn(Optional.of(scan2));
        when(jobRepo.findByScanId(any())).thenReturn(List.of());

        Map<String, Object> result = service.progress(runId);

        String currentAction = (String) result.get("currentAction");
        assertThat(currentAction).contains("2/2");
        assertThat(currentAction).isNotNull();
    }

    @Test
    void progress_jobWithNullProgress_showsZero() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);
        ScanJob job = ScanJob.builder().scanId(scanId).status("RUNNING").progress(null).logs(null).build();

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("progress")).isEqualTo(0);
        assertThat(scans.get(0).get("logs")).isEqualTo("");
    }

    @Test
    void progress_withJobStatusOverridesScanStatus() {
        UUID runId = UUID.randomUUID();
        UUID scanId = UUID.randomUUID();

        OneClickRun run = buildRun(runId, "RUNNING", 50,
                "[\"" + scanId + "\"]",
                1, 0, 0, "https://example.com", "Running");

        Scan scan = buildScan(scanId, "SAST", "RUNNING", "https://example.com", 0);
        ScanJob job = buildJob(scanId, "COMPLETED", 100, "Done");

        when(repo.findById(runId)).thenReturn(Optional.of(run));
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(scan));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(job));

        Map<String, Object> result = service.progress(runId);

        List<Map<String, Object>> scans = (List<Map<String, Object>>) result.get("scans");
        assertThat(scans.get(0).get("status")).isEqualTo("COMPLETED");
    }

    @Test
    void progress_findingsCountNull_showsZero() {
        UUID runId = UUID.randomUUID();

        OneClickRun run = OneClickRun.builder()
                .target("https://example.com")
                .detectedType("WEBAPP")
                .status("RUNNING")
                .progress(50)
                .totalScans(0)
                .completedScans(0)
                .findingsCount(null)
                .scanIdsJson("[]")
                .message("Running")
                .build();
        run.setId(runId);
        when(repo.findById(runId)).thenReturn(Optional.of(run));

        Map<String, Object> result = service.progress(runId);

        assertThat(result.get("findingsCount")).isEqualTo(0);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // detectType tests — all branches
    // ═════════════════════════════════════════════════════════════════════════

    @Test
    void detectType_null_returnsUnknown() {
        assertEquals("UNKNOWN", service.detectType(null));
    }

    @Test
    void detectType_blank_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("   "));
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
    void detectType_httpGeneric_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("https://example.com"));
    }

    @Test
    void detectType_httpWithPort_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("http://localhost:3000"));
    }

    @Test
    void detectType_apk_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.apk"));
    }

    @Test
    void detectType_ipa_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.ipa"));
    }

    @Test
    void detectType_aab_returnsMobile() {
        assertEquals("MOBILE", service.detectType("app-release.aab"));
    }

    @Test
    void detectType_githubUrl_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("github.com/acme/app"));
    }

    @Test
    void detectType_gitlabUrl_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("gitlab.com/acme/app"));
    }

    @Test
    void detectType_gitExtension_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("some-repo.git"));
    }

    @Test
    void detectType_gitAtPrefix_returnsRepository() {
        assertEquals("REPOSITORY", service.detectType("git@github.com:acme/app.git"));
    }

    @Test
    void detectType_gitlabWithHttp_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("https://gitlab.com/acme/app"));
    }

    @Test
    void detectType_dockerHubUrl_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("docker.io/nginx:latest"));
    }

    @Test
    void detectType_dockerHubWithSha_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("docker.io/library/nginx@sha256:abc123"));
    }

    @Test
    void detectType_gcrIoUrl_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("gcr.io/my-project/my-image:v1"));
    }

    @Test
    void detectType_ecrUrl_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("123456789.dkr.ecr.us-east-1.amazonaws.com/my-image"));
    }

    @Test
    void detectType_ecrFullUrl_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("123456789.dkr.ecr.us-east-1.amazonaws.com/myrepo/myimage:latest"));
    }

    @Test
    void detectType_registryWithPort_returnsContainerImage() {
        assertEquals("CONTAINER_IMAGE", service.detectType("registry.example.com:5000/myimage:v1"));
    }

    @Test
    void detectType_ipAddress_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("192.168.1.100"));
    }

    @Test
    void detectType_ipWithCidr_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("10.0.0.0/24"));
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
    void detectType_default_returnsWebapp() {
        assertEquals("WEBAPP", service.detectType("some-random-string"));
    }

    @Test
    void detectType_uppercaseNormalized() {
        assertEquals("MOBILE", service.detectType("APP-RELEASE.APK"));
    }

    @Test
    void detectType_whitespaceTrimmed() {
        assertEquals("WEBAPP", service.detectType("  https://example.com  "));
    }

    @Test
    void detectType_cidrWithPort_returnsNetwork() {
        assertEquals("NETWORK", service.detectType("192.168.1.1:8080"));
    }
}
