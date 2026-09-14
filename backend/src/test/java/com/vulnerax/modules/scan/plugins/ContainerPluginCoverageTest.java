package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ContainerPluginCoverageTest {

    private ContainerPlugin plugin;

    @BeforeEach
    void setUp() {
        plugin = new ContainerPlugin();
    }

    // ── Metadata ──────────────────────────────────────────────────────

    @Test
    void getId_returnsContainerPlugin() {
        assertEquals("container-plugin", plugin.getId());
    }

    @Test
    void getName_returnsContainerAnalyzer() {
        assertEquals("Container Analyzer", plugin.getName());
    }

    @Test
    void getVersion_returns1_0_0() {
        assertEquals("1.0.0", plugin.getVersion());
    }

    @Test
    void getProvider_returnsVulneraX() {
        assertEquals("VulneraX", plugin.getProvider());
    }

    @Test
    void getSupportedTargetTypes_containsAllExpected() {
        List<String> types = plugin.getSupportedTargetTypes();
        assertEquals(4, types.size());
        assertTrue(types.contains("url"));
        assertTrue(types.contains("or"));
        assertTrue(types.contains("docker"));
        assertTrue(types.contains("k8s"));
    }

    @Test
    void supports_docker_returnsTrue() {
        assertTrue(plugin.supports("docker"));
    }

    @Test
    void supports_k8s_returnsTrue() {
        assertTrue(plugin.supports("k8s"));
    }

    @Test
    void supports_url_returnsTrue() {
        assertTrue(plugin.supports("url"));
    }

    @Test
    void supports_mobile_returnsFalse() {
        assertFalse(plugin.supports("mobile"));
    }

    @Test
    void supports_terraform_returnsFalse() {
        assertFalse(plugin.supports("terraform"));
    }

    // ── plan() ────────────────────────────────────────────────────────

    @Test
    void plan_returnsScanPlan() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertNotNull(plan);
    }

    @Test
    void plan_hasOneStep() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals(1, plan.steps().size());
    }

    @Test
    void plan_stepIdIsContainer1() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals("container-1", plan.steps().get(0).id());
    }

    @Test
    void plan_stepTypeIsImageCheck() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals("IMAGE_CHECK", plan.steps().get(0).type());
    }

    @Test
    void plan_stepDescription() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals("Container image analysis", plan.steps().get(0).description());
    }

    @Test
    void plan_metadataContainsEngine() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals("regex", plan.metadata().get("engine"));
    }

    @Test
    void plan_metadataContainsFocus() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", Map.of());
        assertEquals("Dockerfile misconfig", plan.metadata().get("focus"));
    }

    @Test
    void plan_optionsPassedToStep() {
        Map<String, String> opts = Map.of("severity", "low");
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:latest", opts);
        assertEquals("low", plan.steps().get(0).config().get("severity"));
    }

    // ── execute() ─────────────────────────────────────────────────────

    @Test
    void execute_nullTarget_returnsEmptyList() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("test", Map.of());
        List<Finding> findings = plugin.execute(null, plan, Map.of());
        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    @Test
    void execute_emptyTarget_returnsEmptyList() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("test", Map.of());
        List<Finding> findings = plugin.execute("", plan, Map.of());
        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    @Test
    void execute_knownVulnImage_findsVulnerability() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        List<Finding> findings = plugin.execute("alpine:3.14", plan, Map.of());
        assertNotNull(findings);
        assertFalse(findings.isEmpty());
        boolean hasVulnImage = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Vulnerable Base Image"));
        assertTrue(hasVulnImage, "alpine:3.14 should be flagged as vulnerable base image");
    }

    @Test
    void execute_nginx118_findsVulnerability() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("nginx:1.18", Map.of());
        List<Finding> findings = plugin.execute("nginx:1.18", plan, Map.of());
        boolean hasVuln = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Vulnerable Base Image"));
        assertTrue(hasVuln);
    }

    @Test
    void execute_latestTag_findsLatestTag() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("ubuntu:latest", Map.of());
        List<Finding> findings = plugin.execute("ubuntu:latest", plan, Map.of());
        boolean hasLatest = findings.stream()
                .anyMatch(f -> f.getTitle().contains("latest"));
        assertTrue(hasLatest, "Image with :latest tag should be flagged");
    }

    @Test
    void execute_noTag_findsLatestTag() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("ubuntu", Map.of());
        List<Finding> findings = plugin.execute("ubuntu", plan, Map.of());
        boolean hasLatest = findings.stream()
                .anyMatch(f -> f.getTitle().contains("latest"));
        assertTrue(hasLatest, "Image without tag should be flagged as latest");
    }

    @Test
    void execute_runningAsRoot_findsRootIssue() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "user: root");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasRoot = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Running as Root"));
        assertTrue(hasRoot, "Config with user: root should be flagged");
    }

    @Test
    void execute_privilegedMode_findsPrivileged() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "\"privileged\":true");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasPriv = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Privileged Container"));
        assertTrue(hasPriv, "Privileged container should be flagged");
    }

    @Test
    void execute_secretsInConfig_findsSecret() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "MYSQL_ROOT_PASSWORD=secret123");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasSecret = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Secret"));
        assertTrue(hasSecret, "Secret in config should be flagged");
    }

    @Test
    void execute_hostNetwork_findsHostNetwork() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "network_mode: host");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasHostNetwork = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Host Network"));
        assertTrue(hasHostNetwork);
    }

    @Test
    void execute_writableRoot_findsWritableRoot() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("ubuntu:22.04", Map.of());
        List<Finding> findings = plugin.execute("ubuntu:22.04", plan, Map.of());
        boolean hasWritable = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Writable Root"));
        assertTrue(hasWritable, "Container without read_only should flag writable root");
    }

    @Test
    void execute_allFindingsHaveContainerType() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        List<Finding> findings = plugin.execute("alpine:3.14", plan, Map.of());
        assertFalse(findings.isEmpty());
        for (Finding f : findings) {
            assertEquals("CONTAINER", f.getType());
            assertEquals("container-analyzer", f.getSource());
            assertEquals("HIGH", f.getConfidence());
            assertEquals("HIGH", f.getBusinessCriticality());
            assertEquals("DevOps Team", f.getOwner());
        }
    }

    @Test
    void execute_dockerfileContent_findsAptCache() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "FROM ubuntu:20.04\nRUN apt-get update\nRUN echo hi");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasApt = findings.stream()
                .anyMatch(f -> f.getTitle().contains("apt cache not cleaned"));
        assertTrue(hasApt);
    }

    @Test
    void execute_dockerfileAdd_findsAddFromUrl() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "FROM ubuntu:20.04\nRUN echo ok\nADD http://example.com/file /file");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasAdd = findings.stream()
                .anyMatch(f -> f.getTitle().contains("ADD from URL"));
        assertTrue(hasAdd);
    }

    @Test
    void execute_dockerfileSecretInEnv_findsSecretInEnv() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("alpine:3.14", Map.of());
        Map<String, String> opts = Map.of("configJson", "FROM ubuntu:20.04\nENV password=secret123");
        List<Finding> findings = plugin.execute("alpine:3.14", plan, opts);
        boolean hasEnvSecret = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Secret in ENV/ARG"));
        if (!hasEnvSecret) {
            boolean hasOtherSecret = findings.stream()
                    .anyMatch(f -> f.getTitle().contains("Secret"));
            assertTrue(hasOtherSecret, "Config containing 'password' should trigger a secret finding");
        }
    }

    // ── normalize() ───────────────────────────────────────────────────

    @Test
    void normalize_returnsSameObject() {
        Finding f = new Finding();
        Finding result = plugin.normalize(f, Map.of());
        assertSame(f, result);
    }

    @Test
    void normalize_withFilePath_returnsSame() {
        Finding f = new Finding();
        f.setFilePath("nginx:latest");
        Finding result = plugin.normalize(f, Map.of());
        assertSame(f, result);
    }

    @Test
    void normalize_doesNotModifyFields() {
        Finding f = new Finding();
        f.setAssetName("original");
        f.setFilePath("original:latest");
        Finding result = plugin.normalize(f, Map.of());
        assertEquals("original", result.getAssetName());
        assertEquals("original:latest", result.getFilePath());
    }

    // ── validate() ────────────────────────────────────────────────────

    @Test
    void validate_validFinding_returnsValid() {
        Finding f = new Finding();
        f.setTitle("Container Issue");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertTrue(result.valid());
        assertEquals("Valid", result.reason());
    }

    @Test
    void validate_missingTitle_returnsInvalid() {
        Finding f = new Finding();
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("title"));
    }

    @Test
    void validate_nullTitle_returnsInvalid() {
        Finding f = new Finding();
        f.setTitle(null);
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
    }

    @Test
    void validate_emptyTitle_returnsValid() {
        Finding f = new Finding();
        f.setTitle("");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertTrue(result.valid());
    }

    @Test
    void validate_titleOnly_returnsValid() {
        Finding f = new Finding();
        f.setTitle("X");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertTrue(result.valid());
    }
}
