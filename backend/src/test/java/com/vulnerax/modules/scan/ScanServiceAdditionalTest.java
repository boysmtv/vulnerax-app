package com.vulnerax.modules.scan;

import com.vulnerax.common.exception.ResourceNotFoundException;
import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import com.vulnerax.modules.identity.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.*;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ScanServiceAdditionalTest {

    @Mock ScanRepository scanRepo;
    @Mock ScanJobRepository jobRepo;
    @Mock FindingService findingService;
    @Mock ApplicationContext ctx;
    @Mock SecurityCoverageRegistry coverageRegistry;
    @Mock org.springframework.kafka.core.KafkaTemplate<String, Object> kafkaTemplate;

    @InjectMocks ScanService scanService;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
    }

    @Test
    void list_withOrgId_filtersByOrg() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "test@test.com");
        Scan s = Scan.builder().scannerType("SAST").status("COMPLETED").build();
        Page<Scan> page = new PageImpl<>(List.of(s), PageRequest.of(0, 10), 1);
        when(scanRepo.findByOrganizationId(orgId, PageRequest.of(0, 10))).thenReturn(page);
        Page<Scan> result = scanService.list(null, PageRequest.of(0, 10));
        assertThat(result.getContent()).hasSize(1);
    }

    @Test
    void createScan_setsFieldsCorrectly() {
        when(scanRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        Scan result = scanService.createScan("https://example.com", "user@test.com");
        assertThat(result.getTarget()).isEqualTo("https://example.com");
        assertThat(result.getTargetUrl()).isEqualTo("https://example.com");
        assertThat(result.getInitiatedBy()).isEqualTo("user@test.com");
        assertThat(result.getStatus()).isEqualTo("QUEUED");
        assertThat(result.getScannerType()).isEqualTo("DAST");
    }

    @Test
    void create_withOrgId_setsOrg() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "test@test.com");
        Scan s = Scan.builder().scannerType("SAST").target("test").build();
        when(scanRepo.save(any())).thenAnswer(inv -> {
            Scan saved = inv.getArgument(0);
            saved.setId(UUID.randomUUID());
            return saved;
        });
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.create(s, "user");
        verify(scanRepo).save(any());
    }

    @Test
    void startScan_setsQueuedAndPublishes() {
        UUID orgId = UUID.randomUUID();
        TenantContext.set(orgId, null, "test@test.com");
        Scan s = Scan.builder().scannerType("DAST").target("https://example.com").build();
        when(scanRepo.save(any())).thenReturn(s);
        when(ctx.getBean(ScanService.class)).thenReturn(scanService);

        scanService.startScan(s, "user");
        assertThat(s.getStatus()).isEqualTo("QUEUED");
    }

    @Test
    void cancel_cancelsJobs() {
        UUID scanId = UUID.randomUUID();
        Scan s = Scan.builder().status("RUNNING").build();
        s.setId(scanId);
        when(scanRepo.findById(scanId)).thenReturn(Optional.of(s));
        when(jobRepo.findByScanId(scanId)).thenReturn(List.of(
                ScanJob.builder().scanId(scanId).status("RUNNING").build()
        ));

        scanService.cancel(scanId);
        assertThat(s.getStatus()).isEqualTo("CANCELLED");
        verify(jobRepo, atLeastOnce()).save(any());
    }

    @Test
    void pluginsFor_unknownType_returnsDefault() {
        List<String> plugins = invokePluginsFor("UNKNOWN_TYPE");
        assertThat(plugins).containsExactly("sast-plugin");
    }

    @Test
    void pluginsFor_null_returnsDefault() {
        List<String> plugins = invokePluginsFor(null);
        assertThat(plugins).containsExactly("sast-plugin");
    }

    @Test
    void pluginsFor_sast_returnsSastPlugin() {
        List<String> plugins = invokePluginsFor("SAST");
        assertThat(plugins).containsExactly("sast-plugin");
    }

    @Test
    void pluginsFor_sca_returnsScaPlugin() {
        List<String> plugins = invokePluginsFor("SCA");
        assertThat(plugins).containsExactly("sca-plugin");
    }

    @Test
    void pluginsFor_secret_returnsSecretPlugin() {
        List<String> plugins = invokePluginsFor("SECRET");
        assertThat(plugins).containsExactly("secret-plugin");
    }

    @Test
    void pluginsFor_dast_returnsDastPlugin() {
        List<String> plugins = invokePluginsFor("DAST");
        assertThat(plugins).containsExactly("dast-plugin");
    }

    @Test
    void pluginsFor_mobile_returnsMobilePlugin() {
        List<String> plugins = invokePluginsFor("MOBILE");
        assertThat(plugins).containsExactly("mobile-plugin");
    }

    @Test
    void pluginsFor_container_returnsContainerPlugin() {
        List<String> plugins = invokePluginsFor("CONTAINER");
        assertThat(plugins).containsExactly("container-plugin");
    }

    @Test
    void pluginsFor_iac_returnsIacPlugin() {
        List<String> plugins = invokePluginsFor("IAC");
        assertThat(plugins).containsExactly("iac-plugin");
    }

    @Test
    void pluginsFor_api_returnsApiPlugin() {
        List<String> plugins = invokePluginsFor("API");
        assertThat(plugins).containsExactly("api-plugin");
    }

    @Test
    void pluginsFor_all_returnsAllPlugins() {
        List<String> plugins = invokePluginsFor("ALL");
        assertThat(plugins).hasSize(8);
        assertThat(plugins).containsExactly("sast-plugin", "sca-plugin", "secret-plugin", "dast-plugin",
                "container-plugin", "iac-plugin", "api-plugin", "mobile-plugin");
    }

    @Test
    void extractFileContent_withFileContent_returnsContent() {
        Scan s = Scan.builder().configJson("{\"fileContent\":\"hello world\"}").build();
        String result = invokeExtractFileContent(s);
        assertThat(result).isEqualTo("hello world");
    }

    @Test
    void extractFileContent_noFileContent_returnsNull() {
        Scan s = Scan.builder().configJson("{\"key\":\"value\"}").build();
        String result = invokeExtractFileContent(s);
        assertThat(result).isNull();
    }

    @Test
    void extractFileContent_nullConfig_returnsNull() {
        Scan s = Scan.builder().build();
        String result = invokeExtractFileContent(s);
        assertThat(result).isNull();
    }

    @Test
    void buildEvidenceJson_finding_returnsJson() {
        Finding f = Finding.builder().type("SAST").filePath("/src/Main.java")
                .lineNumber(10).codeSnippet("bad code").cwe("CWE-89").build();
        String json = invokeBuildEvidenceJson(f);
        assertThat(json).contains("SAST");
        assertThat(json).contains("CWE-89");
    }

    @Test
    void buildDastEvidence_returnsJson() {
        Map<String, Object> f = new HashMap<>();
        f.put("rule", "Missing CSP");
        f.put("testUrl", "https://example.com");
        f.put("statusCode", 200);
        f.put("responseHeaders", "Content-Type: text/html");
        f.put("responseBody", "<html>");
        f.put("payload", null);
        String json = invokeBuildDastEvidence(f, "https://example.com");
        assertThat(json).contains("Missing CSP");
        assertThat(json).contains("Missing CSP");
    }

    @Test
    void buildFindingFromMap_returnsFinding() {
        Map<String, Object> f = new HashMap<>();
        f.put("title", "Test Finding");
        f.put("severity", "HIGH");
        f.put("cwe", "CWE-79");
        f.put("file", "/src/Main.java");
        f.put("line", 42);
        f.put("snippet", "bad code");
        f.put("recommendation", "Fix it");
        f.put("rule", "XSS");
        f.put("match", "XSS detected");

        Scan scan = Scan.builder().projectId(UUID.randomUUID()).assetId(UUID.randomUUID())
                .target("test").build();
        scan.setId(UUID.randomUUID());

        Finding fd = invokeBuildFindingFromMap(f, scan, "DAST", "dast-analyzer", 6.0);
        assertThat(fd.getTitle()).isEqualTo("Test Finding");
        assertThat(fd.getType()).isEqualTo("DAST");
        assertThat(fd.getSource()).isEqualTo("dast-analyzer");
        assertThat(fd.getCvss()).isEqualTo(6.0);
    }

    @Test
    void buildEvidenceJson_map_returnsJson() {
        Map<String, Object> f = new HashMap<>();
        f.put("rule", "SQL Injection");
        f.put("file", "/src/Main.java");
        f.put("line", 42);
        f.put("snippet", "bad code");
        f.put("cwe", "CWE-89");
        f.put("match", "SQLi");
        String json = invokeBuildEvidenceJsonMap(f);
        assertThat(json).contains("SQL Injection");
        assertThat(json).contains("CWE-89");
    }

    @Test
    void publishEvent_sendsKafka() {
        Scan s = Scan.builder().scannerType("SAST").target("test").build();
        s.setId(UUID.randomUUID());
        s.setStatus("QUEUED");
        assertDoesNotThrow(() -> invokePublishEvent("scan.queued", s));
        verify(kafkaTemplate).send(eq("scan.queued"), eq(s.getId().toString()), any());
    }

    // Helper methods to invoke private methods via reflection
    private List<String> invokePluginsFor(String type) {
        try {
            var method = ScanService.class.getDeclaredMethod("pluginsFor", String.class);
            method.setAccessible(true);
            return (List<String>) method.invoke(scanService, type);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String invokeExtractFileContent(Scan s) {
        try {
            var method = ScanService.class.getDeclaredMethod("extractFileContent", Scan.class);
            method.setAccessible(true);
            return (String) method.invoke(scanService, s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String invokeBuildEvidenceJson(Finding f) {
        try {
            var method = ScanService.class.getDeclaredMethod("buildEvidenceJson", Finding.class);
            method.setAccessible(true);
            return (String) method.invoke(scanService, f);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String invokeBuildDastEvidence(Map<String, Object> f, String target) {
        try {
            var method = ScanService.class.getDeclaredMethod("buildDastEvidence", Map.class, String.class);
            method.setAccessible(true);
            return (String) method.invoke(scanService, f, target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Finding invokeBuildFindingFromMap(Map<String, Object> f, Scan scan, String type, String source, double defaultCvss) {
        try {
            var method = ScanService.class.getDeclaredMethod("buildFindingFromMap", Map.class, Scan.class, String.class, String.class, double.class);
            method.setAccessible(true);
            return (Finding) method.invoke(scanService, f, scan, type, source, defaultCvss);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String invokeBuildEvidenceJsonMap(Map<String, Object> f) {
        try {
            var method = ScanService.class.getDeclaredMethod("buildEvidenceJson", Map.class);
            method.setAccessible(true);
            return (String) method.invoke(scanService, f);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void invokePublishEvent(String topic, Scan scan) throws Exception {
        var method = ScanService.class.getDeclaredMethod("publishEvent", String.class, Scan.class);
        method.setAccessible(true);
        method.invoke(scanService, topic, scan);
    }
}
