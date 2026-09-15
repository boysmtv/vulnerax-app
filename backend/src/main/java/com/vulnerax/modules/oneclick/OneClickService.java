package com.vulnerax.modules.oneclick;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.organization.ProjectRepository;
import com.vulnerax.modules.reporting.ReportService;
import com.vulnerax.modules.scan.Scan;
import com.vulnerax.modules.scan.ScanJobRepository;
import com.vulnerax.modules.scan.ScanRepository;
import com.vulnerax.modules.scan.ScanService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.regex.Pattern;

@Slf4j
@Service
public class OneClickService {
    private final OneClickRepository repo;
    private final ScanService scanService;
    private final ScanRepository scanRepo;
    private final ScanJobRepository jobRepo;
    private final ReportService reportService;
    private final ProjectRepository projectRepo;
    private final ApplicationContext ctx;
    private final ObjectMapper om = new ObjectMapper();

    public OneClickService(OneClickRepository repo, ScanService scanService, ScanRepository scanRepo,
                           ScanJobRepository jobRepo, ReportService reportService, ProjectRepository projectRepo,
                           ApplicationContext ctx) {
        this.repo = repo; this.scanService = scanService; this.scanRepo = scanRepo;
        this.jobRepo = jobRepo; this.reportService = reportService; this.projectRepo = projectRepo;
        this.ctx = ctx;
    }

    public String detectType(String target) {
        if (target == null) return "UNKNOWN";
        String t = target.trim().toLowerCase();
        // Prioritas: http harus dicek sebelum container (karena URL mengandung : dan /)
        if (t.startsWith("http")) {
            if (t.contains("/api") || t.contains("swagger") || t.contains("openapi") || t.contains("graphql")) return "API";
            return "WEBAPP";
        }
        if (t.endsWith(".apk") || t.endsWith(".aab") || t.endsWith(".ipa")) return "MOBILE";
        if (t.contains("github.com") || t.contains("gitlab") || t.endsWith(".git") || t.startsWith("git@")) return "REPOSITORY";
        if (t.matches(".*\\.dkr\\.ecr\\..*|.*gcr\\.io.*|.*docker\\.io.*") || t.matches(".*:[0-9]+.*") && t.contains("/")) {
            // hanya container jika ada registry spesifik, bukan sembarang URL
            if (t.contains("docker.io") || t.contains("gcr.io") || t.contains("ecr") || t.matches(".*:[0-9]+/.*")) return "CONTAINER_IMAGE";
        }
        if (t.matches(".*\\d+\\.\\d+\\.\\d+\\.\\d+.*")) return "NETWORK";
        if (t.endsWith(".zip") || t.endsWith(".jar") || t.endsWith(".war")) return "REPOSITORY";
        return "WEBAPP"; // default web
    }

    public List<String> scannersFor(String detectedType) {
        // User minta semua jenis security & serangan harus real — 1 klik = semua scanner paralel (8 jenis)
        // Tidak lagi pilih subset per type, tapi full suite agar tidak ada web yang lolos sebagai "aman" palsu
        return List.of("SAST", "SCA", "SECRET", "DAST", "API", "CONTAINER", "IAC", "MOBILE");
    }

    @Transactional
    public OneClickRun start(String target, UUID projectId) {
        if (target == null || target.isBlank()) throw new RuntimeException("Target wajib diisi (repo url, domain, image, apk path)");
        // resolve project
        if (projectId == null) {
            projectId = projectRepo.findAll().stream().findFirst().map(p -> p.getId())
                    .orElseThrow(() -> new RuntimeException("No project found — buat project dulu di /projects"));
        } else if (!projectRepo.existsById(projectId)) {
            throw new ResourceNotFoundException("Project not found");
        }
        String detected = detectType(target);
        List<String> scanners = scannersFor(detected);
        OneClickRun run = OneClickRun.builder()
                .projectId(projectId)
                .target(target)
                .detectedType(detected)
                .status("RUNNING")
                .progress(5)
                .totalScans(scanners.size())
                .completedScans(0)
                .scanIdsJson("[]")
                .message("Queued " + scanners.size() + " scanners for " + detected)
                .build();
        run = repo.save(run);

        List<UUID> scanIds = new ArrayList<>();
        for (String scanner : scanners) {
            try {
                Scan s = Scan.builder()
                        .projectId(projectId)
                        .scannerType(scanner)
                        .scanType(detected)
                        .profile("STANDARD")
                        .target(target)
                        .configJson("{\"oneClickRunId\":\"" + run.getId() + "\",\"detectedType\":\"" + detected + "\"}")
                        .build();
                Scan saved = scanService.create(s, "one-click");
                scanIds.add(saved.getId());
            } catch (Exception e) {
                log.warn("Failed to create scan for {} : {}", scanner, e.getMessage());
            }
        }
        try { run.setScanIdsJson(om.writeValueAsString(scanIds)); } catch (Exception e) { run.setScanIdsJson("[]"); }
        run.setMessage("Running " + scanIds.size() + " scanners: " + String.join(",", scanners));
        repo.save(run);
        // async monitor — MUST go through proxy (self-invocation doesn't trigger @Async)
        ctx.getBean(OneClickService.class).monitorAsync(run.getId());
        return run;
    }

    @Async
    public void monitorAsync(UUID runId) {
        try {
            for (int i=0;i<90;i++) { // max 90*2s = 3min
                Thread.sleep(2000);
                Optional<OneClickRun> opt = repo.findById(runId);
                if (opt.isEmpty()) return;
                OneClickRun run = opt.get();
                if ("COMPLETED".equals(run.getStatus()) || "FAILED".equals(run.getStatus())) return;
                List<UUID> scanIds = readScanIds(run);
                if (scanIds.isEmpty()) continue;
                long completed = scanIds.stream().map(id -> scanRepo.findById(id).orElse(null))
                        .filter(s -> s != null && ("COMPLETED".equals(s.getStatus()) || "FAILED".equals(s.getStatus()) || "CANCELLED".equals(s.getStatus())))
                        .count();
                long totalFindings = scanIds.stream().map(id -> scanRepo.findById(id).orElse(null))
                        .filter(Objects::nonNull).mapToLong(s -> s.getFindingsCount()!=null ? s.getFindingsCount() : 0).sum();
                int progress = scanIds.isEmpty() ? 0 : (int) ((completed * 80.0 / scanIds.size()) + 10); // 10-90
                // Detailed current action: list running scanners
                List<String> runningTypes = scanIds.stream().map(id -> scanRepo.findById(id).orElse(null))
                        .filter(s -> s != null && "RUNNING".equals(s.getStatus()))
                        .map(s -> s.getScannerType()).toList();
                String currentAction;
                if (!runningTypes.isEmpty()) {
                    currentAction = "Sedang menjalankan: " + String.join(", ", runningTypes) + " — DAST fetch & header check, SAST pattern, SCA dependency, Secret regex";
                    // Add per-scanner detail if DAST running
                    if (runningTypes.contains("DAST") || runningTypes.contains("API")) {
                        currentAction += " | DAST: fetching " + run.getTarget() + " (CSP/HSTS/X-Frame/SQLi/XSS/CORS)";
                    }
                } else if (completed == 0) {
                    currentAction = "Menyiapkan scanner & antrian Kafka...";
                } else {
                    currentAction = "Progress " + completed + "/" + scanIds.size() + " selesai — " + totalFindings + " temuan";
                }
                run.setCompletedScans((int) completed);
                run.setFindingsCount((int) totalFindings);
                run.setProgress(Math.min(90, progress));
                run.setMessage(currentAction + " — " + totalFindings + " temuan");
                repo.save(run);
                if (completed >= scanIds.size()) {
                    // all done -> generate report
                    try {
                        var report = reportService.generate(run.getProjectId(), "EXECUTIVE", "One-Click Report: " + run.getTarget(), "PDF");
                        run.setReportId(report.getId());
                        run.setProgress(100);
                        run.setStatus("COMPLETED");
                        run.setMessage("Selesai — " + totalFindings + " temuan, report " + report.getId() + " | Semua serangan selesai: SAST/SCA/Secret/DAST/API/Container/IAC/Mobile");
                        repo.save(run);
                        log.info("OneClick {} completed with report {}", runId, report.getId());
                    } catch (Exception e) {
                        log.error("Report generate failed", e);
                        run.setProgress(100);
                        run.setStatus("COMPLETED");
                        run.setMessage("Selesai (report gagal: " + e.getMessage() + ")");
                        repo.save(run);
                    }
                    return;
                }
            }
        } catch (Exception e) {
            log.error("OneClick monitor failed", e);
            repo.findById(runId).ifPresent(r -> { r.setStatus("FAILED"); r.setMessage("Failed: " + e.getMessage()); repo.save(r); });
        }
    }

    private List<UUID> readScanIds(OneClickRun run) {
        try { return om.readValue(run.getScanIdsJson(), new TypeReference<List<UUID>>() {}); } catch (Exception e) { return List.of(); }
    }

    public OneClickRun get(UUID id) { return repo.findById(id).orElseThrow(() -> new ResourceNotFoundException("OneClick run not found")); }

    public Map<String,Object> progress(UUID id) {
        OneClickRun run = get(id);
        List<UUID> scanIds = readScanIds(run);
        List<Map<String,Object>> scans = new ArrayList<>();
        String currentAction = run.getMessage();
        for (UUID sid : scanIds) {
            var s = scanRepo.findById(sid).orElse(null);
            if (s != null) {
                // Get job details for this scan
                var jobs = jobRepo.findByScanId(s.getId());
                String jobStatus = jobs.isEmpty() ? s.getStatus() : jobs.get(0).getStatus();
                String logs = jobs.isEmpty() ? "" : (jobs.get(0).getLogs()!=null?jobs.get(0).getLogs():"");
                int prog = jobs.isEmpty() ? 0 : (jobs.get(0).getProgress()!=null?jobs.get(0).getProgress():0);
                Map<String,Object> m = new HashMap<>();
                m.put("scanId", s.getId());
                m.put("scannerType", s.getScannerType()!=null?s.getScannerType():"UNKNOWN");
                m.put("status", jobStatus!=null?jobStatus:s.getStatus());
                m.put("findings", s.getFindingsCount()!=null?s.getFindingsCount():0);
                m.put("target", s.getTarget()!=null?s.getTarget():"");
                m.put("progress", prog);
                m.put("logs", logs);
                // Human readable action per scanner
                String action = switch (s.getScannerType()!=null?s.getScannerType():"") {
                    case "SAST" -> "Analisis pola SAST: injection, XSS, crypto, auth, serialization";
                    case "SCA" -> "Cek dependency CVE & supply chain (log4j, transitive deps)";
                    case "SECRET" -> "Cari hardcoded secret, API key, credential, signing material";
                    case "DAST" -> "Fetch live site: headers, CORS, XSS/SQLi/SSRF/CSRF, sensitive files";
                    case "API" -> "Inventory API endpoint, GraphQL introspection, auth bypass, rate limit";
                    case "CONTAINER" -> "Scan image: base CVE, secrets in ENV, privilege, network mode";
                    case "IAC" -> "Cek Terraform/K8s YAML/Dockerfile/CloudFormation misconfig";
                    case "MOBILE" -> "Parse APK/IPA: MASVS, WebView, deep link, crypto, storage";
                    default -> "Scan " + s.getScannerType();
                };
                m.put("action", action);
                scans.add(m);
            }
        }
        // Determine current running action
        var running = scans.stream().filter(m -> "RUNNING".equals(m.get("status"))).map(m -> (String)m.get("scannerType")).toList();
        if (!running.isEmpty()) {
            currentAction = "Sedang: " + String.join(" + ", running) + " — " + run.getMessage();
        }
        Map<String,Object> out = new HashMap<>();
        out.put("id", run.getId());
        out.put("target", run.getTarget());
        out.put("detectedType", run.getDetectedType());
        out.put("status", run.getStatus());
        out.put("progress", run.getProgress());
        out.put("totalScans", run.getTotalScans());
        out.put("completedScans", run.getCompletedScans());
        out.put("findingsCount", run.getFindingsCount()!=null?run.getFindingsCount():0);
        out.put("reportId", run.getReportId());
        out.put("message", run.getMessage());
        out.put("currentAction", currentAction);
        out.put("scans", scans);
        List<String> steps = List.of("Queue (Kafka)","SAST (30+ patterns)","SCA (CVE/EPSS)","Secrets (regex)","DAST (live: 25+ checks)","API (inventory/BOLA/CORS)","Container (image/priv/secrets)","IaC (Terraform/K8s/Dockerfile)","Mobile (MASVS/APK)","Risk (CVSS+EPSS+KEV)","Report");
        out.put("steps", steps);
        return out;
    }

    public List<OneClickRun> list(UUID projectId) {
        if (projectId != null) return repo.findByProjectIdOrderByCreatedAtDesc(projectId);
        return repo.findAll().stream().sorted(Comparator.comparing(OneClickRun::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder()))).toList();
    }
}
