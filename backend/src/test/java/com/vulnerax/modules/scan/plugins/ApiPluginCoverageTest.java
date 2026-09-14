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
class ApiPluginCoverageTest {

    private ApiPlugin plugin;

    @BeforeEach
    void setUp() {
        plugin = new ApiPlugin();
    }

    // ── Metadata ──────────────────────────────────────────────────────

    @Test
    void getId_returnsApiPlugin() {
        assertEquals("api-plugin", plugin.getId());
    }

    @Test
    void getName_returnsApiAnalyzer() {
        assertEquals("API Analyzer", plugin.getName());
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
    void getSupportedTargetTypes_containsUrlOrApi() {
        List<String> types = plugin.getSupportedTargetTypes();
        assertEquals(3, types.size());
        assertTrue(types.contains("url"));
        assertTrue(types.contains("or"));
        assertTrue(types.contains("api"));
    }

    @Test
    void getSecurityLevel_returnsAggressive() {
        assertEquals("AGGRESSIVE", plugin.getSecurityLevel());
    }

    @Test
    void supports_api_returnsTrue() {
        assertTrue(plugin.supports("api"));
    }

    @Test
    void supports_url_returnsTrue() {
        assertTrue(plugin.supports("url"));
    }

    @Test
    void supports_docker_returnsFalse() {
        assertFalse(plugin.supports("docker"));
    }

    // ── plan() ────────────────────────────────────────────────────────

    @Test
    void plan_returnsScanPlan() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertNotNull(plan);
    }

    @Test
    void plan_hasOneStep() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals(1, plan.steps().size());
    }

    @Test
    void plan_stepIdIsApi1() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals("api-1", plan.steps().get(0).id());
    }

    @Test
    void plan_stepTypeIsEndpointCheck() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals("ENDPOINT_CHECK", plan.steps().get(0).type());
    }

    @Test
    void plan_stepDescription() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals("API endpoint analysis", plan.steps().get(0).description());
    }

    @Test
    void plan_metadataContainsEngine() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals("http-client", plan.metadata().get("engine"));
    }

    @Test
    void plan_metadataContainsFocus() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", Map.of());
        assertEquals("auth, rate-limit, input-validation", plan.metadata().get("focus"));
    }

    @Test
    void plan_optionsPassedToStep() {
        Map<String, String> opts = Map.of("custom", "opt");
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://api.example.com", opts);
        assertEquals("opt", plan.steps().get(0).config().get("custom"));
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
    void execute_nonHttpTarget_returnsEmptyList() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("ftp://invalid", Map.of());
        List<Finding> findings = plugin.execute("ftp://invalid", plan, Map.of());
        assertNotNull(findings);
        assertTrue(findings.isEmpty());
    }

    @Test
    void execute_unreachableUrl_returnsAtLeastOneFinding() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertNotNull(findings);
        assertFalse(findings.isEmpty());
    }

    @Test
    void execute_unreachableUrl_findingHasCorrectType() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("API", findings.get(0).getType());
    }

    @Test
    void execute_unreachableUrl_findingHasCorrectSource() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("api-analyzer", findings.get(0).getSource());
    }

    @Test
    void execute_unreachableUrl_findingHasConfidence() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("HIGH", findings.get(0).getConfidence());
    }

    @Test
    void execute_unreachableUrl_findingHasBusinessCriticality() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("HIGH", findings.get(0).getBusinessCriticality());
        assertEquals("Security Team", findings.get(0).getOwner());
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
        f.setFilePath("/some/path");
        Finding result = plugin.normalize(f, Map.of());
        assertSame(f, result);
        assertEquals("/some/path", result.getFilePath());
    }

    @Test
    void normalize_doesNotModifyAssetName() {
        Finding f = new Finding();
        f.setAssetName("original");
        Finding result = plugin.normalize(f, Map.of());
        assertEquals("original", result.getAssetName());
    }

    // ── validate() ────────────────────────────────────────────────────

    @Test
    void validate_validFinding_returnsValid() {
        Finding f = new Finding();
        f.setTitle("API Issue");
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
    void validate_titleWithNoOtherFields_returnsValid() {
        Finding f = new Finding();
        f.setTitle("X");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertTrue(result.valid());
    }
}
