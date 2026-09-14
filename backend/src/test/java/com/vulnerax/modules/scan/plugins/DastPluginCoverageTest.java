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
class DastPluginCoverageTest {

    private DastPlugin plugin;

    @BeforeEach
    void setUp() {
        plugin = new DastPlugin();
    }

    // ── Metadata ──────────────────────────────────────────────────────

    @Test
    void getId_returnsDastPlugin() {
        assertEquals("dast-plugin", plugin.getId());
    }

    @Test
    void getName_returnsDastAnalyzer() {
        assertEquals("DAST Analyzer", plugin.getName());
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
    void getSupportedTargetTypes_containsUrlAndOr() {
        List<String> types = plugin.getSupportedTargetTypes();
        assertEquals(2, types.size());
        assertTrue(types.contains("url"));
        assertTrue(types.contains("or"));
    }

    @Test
    void getSecurityLevel_returnsAggressive() {
        assertEquals("AGGRESSIVE", plugin.getSecurityLevel());
    }

    @Test
    void supports_url_returnsTrue() {
        assertTrue(plugin.supports("url"));
    }

    @Test
    void supports_or_returnsTrue() {
        assertTrue(plugin.supports("or"));
    }

    @Test
    void supports_unknown_returnsFalse() {
        assertFalse(plugin.supports("docker"));
    }

    // ── plan() ────────────────────────────────────────────────────────

    @Test
    void plan_returnsScanPlan() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        assertNotNull(plan);
    }

    @Test
    void plan_hasThreeSteps() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        assertEquals(3, plan.steps().size());
    }

    @Test
    void plan_firstStepIsHeaders() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        SecurityScannerPlugin.ScanStep first = plan.steps().get(0);
        assertEquals("dast-headers", first.id());
        assertEquals("HEADER_CHECK", first.type());
        assertEquals("Check security headers", first.description());
    }

    @Test
    void plan_secondStepIsInjection() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        SecurityScannerPlugin.ScanStep second = plan.steps().get(1);
        assertEquals("dast-inject", second.id());
        assertEquals("INJECTION", second.type());
        assertEquals("XSS/SQLi/SSRF tests", second.description());
    }

    @Test
    void plan_thirdStepIsAuth() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        SecurityScannerPlugin.ScanStep third = plan.steps().get(2);
        assertEquals("dast-auth", third.id());
        assertEquals("AUTH_CHECK", third.type());
        assertEquals("Authentication bypass tests", third.description());
    }

    @Test
    void plan_metadataContainsEngine() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        assertEquals("http-client", plan.metadata().get("engine"));
    }

    @Test
    void plan_metadataContainsTimeout() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", Map.of());
        assertEquals("10s", plan.metadata().get("timeout"));
    }

    @Test
    void plan_optionsPassedToSteps() {
        Map<String, String> opts = Map.of("key", "value");
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("https://example.com", opts);
        assertEquals("value", plan.steps().get(0).config().get("key"));
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
    void execute_unreachableUrl_returnsUnreachableFinding() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertNotNull(findings);
        assertFalse(findings.isEmpty());
        Finding f = findings.get(0);
        assertEquals("DAST", f.getType());
        assertEquals("dast-analyzer", f.getSource());
        assertNotNull(f.getTitle());
    }

    @Test
    void execute_mappingSetsTypeAndSource() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        for (Finding f : findings) {
            assertEquals("DAST", f.getType());
            assertEquals("dast-analyzer", f.getSource());
            assertEquals("HIGH", f.getConfidence());
            assertEquals("HIGH", f.getBusinessCriticality());
            assertEquals("Security Team", f.getOwner());
            assertTrue(f.getInternetExposed());
        }
    }

    @Test
    void execute_unreachableFinding_severityIsMedium() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("MEDIUM", findings.get(0).getSeverity());
    }

    @Test
    void execute_unreachableFinding_hasEvidenceJson() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("http://192.0.2.1:99999", Map.of());
        List<Finding> findings = plugin.execute("http://192.0.2.1:99999", plan, Map.of());
        assertFalse(findings.isEmpty());
        String json = findings.get(0).getEvidenceJson();
        assertNotNull(json);
        assertTrue(json.contains("type"));
        assertTrue(json.contains("target"));
    }

    // ── normalize() ───────────────────────────────────────────────────

    @Test
    void normalize_httpFilePath_setsAssetName() {
        Finding f = new Finding();
        f.setFilePath("https://example.com/page");
        Finding result = plugin.normalize(f, Map.of());
        assertEquals("https://example.com/page", result.getAssetName());
    }

    @Test
    void normalize_httpFilePath_setsAssetNameWithHttpPrefix() {
        Finding f = new Finding();
        f.setFilePath("http://insecure-site.com");
        Finding result = plugin.normalize(f, Map.of());
        assertEquals("http://insecure-site.com", result.getAssetName());
    }

    @Test
    void normalize_nonHttpFilePath_doesNotSetAssetName() {
        Finding f = new Finding();
        f.setFilePath("local-file.txt");
        Finding result = plugin.normalize(f, Map.of());
        assertNull(result.getAssetName());
    }

    @Test
    void normalize_nullFilePath_doesNotSetAssetName() {
        Finding f = new Finding();
        f.setFilePath(null);
        Finding result = plugin.normalize(f, Map.of());
        assertNull(result.getAssetName());
    }

    @Test
    void normalize_returnsSameObject() {
        Finding f = new Finding();
        f.setFilePath("https://example.com");
        Finding result = plugin.normalize(f, Map.of());
        assertSame(f, result);
    }

    // ── validate() ────────────────────────────────────────────────────

    @Test
    void validate_validFinding_returnsValid() {
        Finding f = new Finding();
        f.setTitle("Missing CSP");
        f.setFilePath("https://example.com");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertTrue(result.valid());
        assertEquals("Valid", result.reason());
    }

    @Test
    void validate_missingTitle_returnsInvalid() {
        Finding f = new Finding();
        f.setFilePath("https://example.com");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("title"));
    }

    @Test
    void validate_nullTitle_returnsInvalid() {
        Finding f = new Finding();
        f.setTitle(null);
        f.setFilePath("https://example.com");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("title"));
    }

    @Test
    void validate_missingFilePath_returnsInvalid() {
        Finding f = new Finding();
        f.setTitle("Missing CSP");
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("URL") || result.reason().contains("filePath"));
    }

    @Test
    void validate_nullFilePath_returnsInvalid() {
        Finding f = new Finding();
        f.setTitle("Missing CSP");
        f.setFilePath(null);
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("URL") || result.reason().contains("filePath"));
    }

    @Test
    void validate_bothMissing_returnsInvalid() {
        Finding f = new Finding();
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
    }

    @Test
    void validate_titleFirstMissingIfBothMissing() {
        Finding f = new Finding();
        SecurityScannerPlugin.ValidationResult result = plugin.validate(f);
        assertFalse(result.valid());
        assertTrue(result.reason().contains("title"));
    }
}
