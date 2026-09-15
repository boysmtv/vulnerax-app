package com.vulnerax.modules.scan;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.TenantContext;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import com.vulnerax.modules.scan.plugins.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.lang.Nullable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

@Slf4j
@Service
public class ScanService {
    private final ScanRepository scanRepo;
    private final ScanJobRepository jobRepo;
    private final FindingService findingService;
    private final ApplicationContext ctx;
    private final SecurityCoverageRegistry coverageRegistry;
    private final Map<String, SecurityScannerPlugin> pluginRegistry = new LinkedHashMap<>();
    private final KafkaTemplate<String, Object> kafkaTemplate;

    public ScanService(ScanRepository scanRepo, ScanJobRepository jobRepo, FindingService findingService,
                      ApplicationContext ctx, SecurityCoverageRegistry coverageRegistry,
                      List<SecurityScannerPlugin> plugins,
                      @Nullable KafkaTemplate<String, Object> kafkaTemplate) {
        this.scanRepo = scanRepo;
        this.jobRepo = jobRepo;
        this.findingService = findingService;
        this.ctx = ctx;
        this.coverageRegistry = coverageRegistry;
        this.kafkaTemplate = kafkaTemplate;
        if (plugins != null) {
            plugins.forEach(p -> pluginRegistry.put(p.getId(), p));
        }
    }

    public Page<Scan> list(UUID projectId, Pageable p) {
        UUID orgId = TenantContext.getOrganizationId();
        if (projectId != null) return scanRepo.findByProjectId(projectId, p);
        if (orgId != null) return scanRepo.findByOrganizationId(orgId, p);
        return scanRepo.findAll(p);
    }

    public Scan get(UUID id) { return scanRepo.findById(id).orElseThrow(() -> new ResourceNotFoundException("Scan not found")); }
    public List<ScanJob> jobs(UUID scanId) { return jobRepo.findByScanId(scanId); }

    @Transactional
    public Scan createScan(String targetUrl, String user) {
        Scan s = new Scan();
        s.setTarget(targetUrl);
        s.setTargetUrl(targetUrl);
        s.setInitiatedBy(user);
        s.setStatus("QUEUED");
        s.setProfile("STANDARD");
        s.setScannerType("DAST");
        s.setScanType("url");
        return scanRepo.save(s);
    }

    @Transactional
    public Scan create(Scan s, String user) {
        UUID orgId = TenantContext.getOrganizationId();
        if (orgId != null) s.setOrganizationId(orgId);
        s.setInitiatedBy(user);
        s.setStatus("QUEUED");
        Scan saved = scanRepo.save(s);

        List<String> plugins = pluginsFor(s.getScannerType());
        for (String pl : plugins) {
            ScanJob j = ScanJob.builder().scanId(saved.getId()).scannerPlugin(pl).status("QUEUED").progress(0).build();
            jobRepo.save(j);
        }
        publishEvent("scan.queued", saved);
        ctx.getBean(ScanService.class).executeAsync(saved.getId());
        return saved;
    }

    @Transactional
    public void startScan(Scan scan, String user) {
        UUID orgId = TenantContext.getOrganizationId();
        if (orgId != null) scan.setOrganizationId(orgId);
        scan.setStatus("QUEUED");
        scanRepo.save(scan);
        publishEvent("scan.queued", scan);
        ctx.getBean(ScanService.class).executeAsync(scan.getId());
    }

    private List<String> pluginsFor(String type) {
        if (type == null) return List.of("sast-plugin");
        return switch (type.toUpperCase()) {
            case "SAST" -> List.of("sast-plugin");
            case "SCA" -> List.of("sca-plugin");
            case "SECRET" -> List.of("secret-plugin");
            case "DAST" -> List.of("dast-plugin");
            case "MOBILE" -> List.of("mobile-plugin");
            case "CONTAINER" -> List.of("container-plugin");
            case "IAC" -> List.of("iac-plugin");
            case "API" -> List.of("api-plugin");
            case "ALL" -> List.of("sast-plugin", "sca-plugin", "secret-plugin", "dast-plugin",
                    "container-plugin", "iac-plugin", "api-plugin", "mobile-plugin");
            default -> List.of("sast-plugin");
        };
    }

    @Async
    public void executeAsync(UUID scanId) {
        try {
            Thread.sleep(600);
            Scan scan = get(scanId);
            scan.setStatus("RUNNING");
            scan.setStartedAt(Instant.now());
            scanRepo.save(scan);
            publishEvent("scan.running", scan);

            List<ScanJob> jobs = jobs(scanId);
            Random rnd = new Random();
            for (ScanJob j : jobs) {
                j.setStatus("RUNNING");
                j.setProgress(50);
                j.setWorkerId("worker-" + rnd.nextInt(3));
                jobRepo.save(j);

                int created = executePlugin(j.getScannerPlugin(), scan);
                j.setProgress(100);
                j.setStatus("COMPLETED");
                j.setLogs("Plugin " + j.getScannerPlugin() + " completed: " + created + " findings");
                j.setResultJson("{\"findings\": " + created + ", \"plugin\": \"" + j.getScannerPlugin() + "\"}");
                jobRepo.save(j);
            }

            int totalCreated = jobs.stream().mapToInt(j -> {
                try {
                    String json = j.getResultJson();
                    int idx = json.indexOf("\"findings\":");
                    if (idx != -1) {
                        int start = idx + 11;
                        int end = json.indexOf(",", start);
                        if (end == -1) end = json.indexOf("}", start);
                        return Integer.parseInt(json.substring(start, end).trim());
                    }
                } catch (Exception e) {}
                return 0;
            }).sum();

            scan.setStatus("COMPLETED");
            scan.setFinishedAt(Instant.now());
            scan.setDurationMs(scan.getFinishedAt().toEpochMilli() - scan.getStartedAt().toEpochMilli());
            scan.setFindingsCount(totalCreated);
            scanRepo.save(scan);
            publishEvent("scan.completed", scan);
            log.info("Scan {} completed with {} findings via plugin system", scanId, totalCreated);
        } catch (Exception e) {
            log.error("Scan failed", e);
            try {
                Scan s = get(scanId);
                s.setStatus("FAILED");
                scanRepo.save(s);
                publishEvent("scan.failed", s);
            } catch (Exception ex) {}
        }
    }

    private int executePlugin(String pluginId, Scan scan) {
        SecurityScannerPlugin plugin = pluginRegistry.get(pluginId);
        if (plugin == null) {
            log.warn("Plugin {} not found, falling back to legacy analyzers", pluginId);
            return runLegacyAnalyzer(scan);
        }

        try {
            String fileContent = extractFileContent(scan);
            String toAnalyze = fileContent != null ? fileContent : scan.getTarget();
            Map<String, String> options = new LinkedHashMap<>();
            if (fileContent != null) {
                options.put("fileContent", fileContent);
                options.put("fileName", scan.getTarget());
            }
            if (scan.getConfigJson() != null) {
                options.put("configJson", scan.getConfigJson());
            }

            SecurityScannerPlugin.ScanPlan plan = plugin.plan(scan.getTarget(), options);
            List<Finding> findings = plugin.execute(scan.getTarget(), plan, options);

            int created = 0;
            for (Finding f : findings) {
                f = plugin.normalize(f, options);
                SecurityScannerPlugin.ValidationResult v = plugin.validate(f);
                if (!v.valid()) {
                    log.debug("Plugin {} finding rejected: {}", pluginId, v.reason());
                    continue;
                }
                f.setProjectId(scan.getProjectId());
                f.setAssetId(scan.getAssetId());
                f.setAssetName(scan.getTarget());
                f.setScanId(scan.getId());
                f.setStatus("OPEN");
                if (f.getEvidenceJson() == null) {
                    f.setEvidenceJson(buildEvidenceJson(f));
                }
                findingService.create(f);
                created++;
            }
            return created;
        } catch (Exception e) {
            log.error("Plugin {} execution failed, falling back to legacy", pluginId, e);
            return runLegacyAnalyzer(scan);
        }
    }

    private int runLegacyAnalyzer(Scan scan) {
        try {
            String fileContent = extractFileContent(scan);
            String toAnalyze = fileContent != null ? fileContent : scan.getTarget();
            String fileName = scan.getTarget();
            String type = scan.getScannerType() != null ? scan.getScannerType().toUpperCase() : "SAST";
            int total = 0;

            if ("SECRET".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.SecretAnalyzer.analyze(toAnalyze, fileName);
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "SECRET", "secret-analyzer", 7.5);
                    findingService.create(fd);
                    total++;
                }
            }
            if ("SAST".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.SastAnalyzer.analyze(toAnalyze, fileName);
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "SAST", "sast-analyzer", 7.0);
                    fd.setDataFlow("source: user input -> sink: vulnerable function");
                    findingService.create(fd);
                    total++;
                }
            }
            if ("DAST".equals(type) || "API".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.DastAnalyzer.analyze(scan.getTarget(), fileName);
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "DAST", "dast-analyzer", 6.0);
                    fd.setInternetExposed(true);
                    fd.setDataFlow("DAST: live site " + scan.getTarget());
                    fd.setEvidenceJson(buildDastEvidence(f, scan.getTarget()));
                    findingService.create(fd);
                    total++;
                }
            }
            if ("SCA".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.ScaAnalyzer.analyze(toAnalyze, fileName);
                for (var f : results) {
                    Finding fd = Finding.builder()
                            .title((String) f.get("title"))
                            .description("Vulnerable dependency " + f.get("component") + " " + f.get("installedVersion"))
                            .type("SCA").severity((String) f.get("severity")).confidence("HIGH").status("OPEN")
                            .projectId(scan.getProjectId()).assetId(scan.getAssetId()).assetName(scan.getTarget())
                            .source("sca-analyzer").scanId(scan.getId()).cwe("CWE-1104")
                            .cvss((Double) f.get("cvss")).epss((Double) f.get("epss")).kev((Boolean) f.get("kev"))
                            .businessCriticality("HIGH").owner("Platform Team").filePath((String) f.get("file"))
                            .cveId(f.get("cve") != null ? f.get("cve").toString() : null)
                            .recommendation("Update to " + f.get("fixedVersion"))
                            .evidenceJson(buildEvidenceJson(f))
                            .build();
                    findingService.create(fd);
                    total++;
                }
            }
            if ("CONTAINER".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.ContainerAnalyzer.analyze(scan.getTarget(), scan.getConfigJson());
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "CONTAINER", "container-analyzer", 7.0);
                    fd.setOwner("DevOps Team");
                    findingService.create(fd);
                    total++;
                }
            }
            if ("IAC".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.IaCAnalyzer.analyze(toAnalyze, fileName);
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "IAC", "iac-analyzer", 7.0);
                    fd.setOwner("Platform Team");
                    findingService.create(fd);
                    total++;
                }
            }
            if ("API".equals(type) || "ALL".equals(type)) {
                if (scan.getTarget() != null && scan.getTarget().startsWith("http")) {
                    List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.ApiAnalyzer.analyze(scan.getTarget());
                    for (var f : results) {
                        Finding fd = buildFindingFromMap(f, scan, "API", "api-analyzer", 6.5);
                        fd.setOwner("Security Team");
                        findingService.create(fd);
                        total++;
                    }
                }
            }
            if ("MOBILE".equals(type) || "ALL".equals(type)) {
                List<Map<String, Object>> results = com.vulnerax.modules.scan.analyzers.MobileAnalyzer.analyze(scan.getTarget(), scan.getConfigJson());
                for (var f : results) {
                    Finding fd = buildFindingFromMap(f, scan, "MOBILE", "mobile-analyzer", 7.0);
                    fd.setOwner("Mobile Team");
                    findingService.create(fd);
                    total++;
                }
            }
            return total;
        } catch (Exception e) {
            log.error("Legacy analyzer failed", e);
            return 0;
        }
    }

    private Finding buildFindingFromMap(Map<String, Object> f, Scan scan, String type, String source, double defaultCvss) {
        return Finding.builder()
                .title((String) f.get("title"))
                .description((String) f.getOrDefault("snippet", (String) f.get("rule") + " detected"))
                .type(type).severity((String) f.get("severity")).confidence("HIGH").status("OPEN")
                .projectId(scan.getProjectId()).assetId(scan.getAssetId()).assetName(scan.getTarget())
                .source(source).scanId(scan.getId()).cwe((String) f.get("cwe")).cvss(defaultCvss)
                .businessCriticality("HIGH").owner("Security Team")
                .filePath((String) f.get("file")).lineNumber((Integer) f.get("line"))
                .codeSnippet((String) f.get("snippet")).recommendation((String) f.get("recommendation"))
                .evidenceJson(buildEvidenceJson(f))
                .build();
    }

    private String extractFileContent(Scan scan) {
        if (scan.getConfigJson() != null && scan.getConfigJson().contains("fileContent")) {
            try {
                String cfg = scan.getConfigJson();
                int idx = cfg.indexOf("fileContent");
                if (idx != -1) {
                    int start = cfg.indexOf(":", idx) + 1;
                    int firstQuote = cfg.indexOf("\"", start);
                    int lastQuote = cfg.lastIndexOf("\"");
                    if (firstQuote != -1 && lastQuote != -1 && lastQuote > firstQuote) {
                        return cfg.substring(firstQuote + 1, lastQuote).replace("\\n", "\n").replace("\\\"", "\"");
                    }
                }
            } catch (Exception e) { log.warn("parse fileContent failed", e); }
        }
        return null;
    }

    private String buildEvidenceJson(Map<String, Object> f) {
        try {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("type", f.getOrDefault("rule", "SCAN_RESULT"));
            evidence.put("file", f.get("file"));
            evidence.put("line", f.get("line"));
            evidence.put("snippet", f.get("snippet"));
            evidence.put("match", f.get("match"));
            evidence.put("cwe", f.get("cwe"));
            evidence.put("timestamp", Instant.now().toString());
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
            return mapper.writeValueAsString(evidence);
        } catch (Exception e) {
            return "{\"type\":\"SCAN_RESULT\",\"error\":\"serialization_failed\"}";
        }
    }

    private String buildDastEvidence(Map<String, Object> f, String target) {
        try {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("type", f.getOrDefault("rule", "DAST_RESULT"));
            evidence.put("target", target);
            evidence.put("file", f.get("file"));
            evidence.put("testUrl", f.get("testUrl"));
            evidence.put("statusCode", f.get("statusCode"));
            evidence.put("responseHeaders", f.get("responseHeaders"));
            evidence.put("responseBody", f.get("responseBody"));
            evidence.put("payload", f.get("payload"));
            evidence.put("timestamp", Instant.now().toString());
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
            return mapper.writeValueAsString(evidence);
        } catch (Exception e) {
            return "{\"type\":\"DAST_RESULT\",\"error\":\"serialization_failed\"}";
        }
    }

    private String buildEvidenceJson(Finding f) {
        try {
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("type", f.getType());
            evidence.put("file", f.getFilePath());
            evidence.put("line", f.getLineNumber());
            evidence.put("snippet", f.getCodeSnippet());
            evidence.put("cwe", f.getCwe());
            evidence.put("timestamp", Instant.now().toString());
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.setSerializationInclusion(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL);
            return mapper.writeValueAsString(evidence);
        } catch (Exception e) {
            return "{\"type\":\"SCAN_RESULT\",\"error\":\"serialization_failed\"}";
        }
    }

    private void publishEvent(String topic, Scan scan) {
        // Kafka is optional — skip silently if not connected
        if (kafkaTemplate == null) return;
        try {
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("scanId", scan.getId().toString());
            event.put("status", scan.getStatus());
            event.put("target", scan.getTarget());
            event.put("scannerType", scan.getScannerType());
            event.put("timestamp", Instant.now().toString());
            kafkaTemplate.send(topic, scan.getId().toString(), event);
        } catch (Exception e) {
            log.debug("Kafka publish skipped: {}", e.getMessage());
        }
    }

    @Transactional
    public void cancel(UUID id) {
        Scan s = get(id);
        s.setStatus("CANCELLED");
        scanRepo.save(s);
        publishEvent("scan.cancelled", s);
        jobs(id).forEach(j -> { j.setStatus("CANCELLED"); jobRepo.save(j); });
    }
}
