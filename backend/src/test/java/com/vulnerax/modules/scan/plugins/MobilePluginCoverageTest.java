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
class MobilePluginCoverageTest {

    private MobilePlugin plugin;

    @BeforeEach
    void setUp() {
        plugin = new MobilePlugin();
    }

    // ── Metadata ──────────────────────────────────────────────────────

    @Test
    void getId_returnsMobilePlugin() {
        assertEquals("mobile-plugin", plugin.getId());
    }

    @Test
    void getName_returnsMobileAnalyzer() {
        assertEquals("Mobile Analyzer", plugin.getName());
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
        assertEquals(5, types.size());
        assertTrue(types.contains("url"));
        assertTrue(types.contains("or"));
        assertTrue(types.contains("mobile"));
        assertTrue(types.contains("android"));
        assertTrue(types.contains("ios"));
    }

    @Test
    void supports_mobile_returnsTrue() {
        assertTrue(plugin.supports("mobile"));
    }

    @Test
    void supports_android_returnsTrue() {
        assertTrue(plugin.supports("android"));
    }

    @Test
    void supports_ios_returnsTrue() {
        assertTrue(plugin.supports("ios"));
    }

    @Test
    void supports_url_returnsTrue() {
        assertTrue(plugin.supports("url"));
    }

    @Test
    void supports_docker_returnsFalse() {
        assertFalse(plugin.supports("docker"));
    }

    @Test
    void supports_terraform_returnsFalse() {
        assertFalse(plugin.supports("terraform"));
    }

    // ── plan() ────────────────────────────────────────────────────────

    @Test
    void plan_returnsScanPlan() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertNotNull(plan);
    }

    @Test
    void plan_hasOneStep() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals(1, plan.steps().size());
    }

    @Test
    void plan_stepIdIsMobile1() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals("mobile-1", plan.steps().get(0).id());
    }

    @Test
    void plan_stepTypeIsAppCheck() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals("APP_CHECK", plan.steps().get(0).type());
    }

    @Test
    void plan_stepDescription() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals("Mobile app security analysis", plan.steps().get(0).description());
    }

    @Test
    void plan_metadataContainsEngine() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals("regex", plan.metadata().get("engine"));
    }

    @Test
    void plan_metadataContainsFocus() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        assertEquals("MASVS", plan.metadata().get("focus"));
    }

    @Test
    void plan_optionsPassedToStep() {
        Map<String, String> opts = Map.of("level", "deep");
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", opts);
        assertEquals("deep", plan.steps().get(0).config().get("level"));
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
    void execute_nonMobileFile_returnsFinding() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("readme.txt", Map.of());
        List<Finding> findings = plugin.execute("readme.txt", plan, Map.of());
        assertNotNull(findings);
        assertFalse(findings.isEmpty());
        assertEquals("MOBILE", findings.get(0).getType());
        assertEquals("mobile-analyzer", findings.get(0).getSource());
    }

    @Test
    void execute_nonMobileFile_findingTitleContainsNotAMobileArtifact() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("readme.txt", Map.of());
        List<Finding> findings = plugin.execute("readme.txt", plan, Map.of());
        assertFalse(findings.isEmpty());
        assertEquals("Not a Mobile Artifact", findings.get(0).getTitle());
    }

    @Test
    void execute_withApkFile_findsBackupAllowed() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        List<Finding> findings = plugin.execute("app.apk", plan, Map.of());
        assertFalse(findings.isEmpty());
        boolean hasBackup = findings.stream()
                .anyMatch(f -> f.getTitle().contains("allowBackup"));
        assertTrue(hasBackup, "APK without config should flag allowBackup");
    }

    @Test
    void execute_withApkDebuggable_findsDebuggable() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        Map<String, String> opts = Map.of("configJson", "debuggable=true");
        List<Finding> findings = plugin.execute("app.apk", plan, opts);
        boolean hasDebuggable = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Debuggable"));
        assertTrue(hasDebuggable, "APK with debuggable=true should be flagged");
    }

    @Test
    void execute_withApkCleartext_findsCleartext() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        List<Finding> findings = plugin.execute("app.apk", plan, Map.of());
        boolean hasCleartext = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Cleartext"));
        assertTrue(hasCleartext, "APK should flag cleartext traffic");
    }

    @Test
    void execute_withApkAllFindingsHaveMobileType() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        List<Finding> findings = plugin.execute("app.apk", plan, Map.of());
        assertFalse(findings.isEmpty());
        for (Finding f : findings) {
            assertEquals("MOBILE", f.getType());
            assertEquals("mobile-analyzer", f.getSource());
            assertEquals("HIGH", f.getConfidence());
            assertEquals("HIGH", f.getBusinessCriticality());
            assertEquals("Mobile Team", f.getOwner());
        }
    }

    @Test
    void execute_withIpa_findsKeychainMissing() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.ipa", Map.of());
        List<Finding> findings = plugin.execute("app.ipa", plan, Map.of());
        boolean hasKeychain = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Keychain"));
        assertTrue(hasKeychain, "IPA without keychain config should flag it");
    }

    @Test
    void execute_withIpaAts_findsAts() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.ipa", Map.of());
        Map<String, String> opts = Map.of("configJson", "NSAppTransportSecurity NSAllowsArbitraryLoads=YES");
        List<Finding> findings = plugin.execute("app.ipa", plan, opts);
        boolean hasAts = findings.stream()
                .anyMatch(f -> f.getTitle().contains("ATS"));
        assertTrue(hasAts, "IPA with ATS disabled should be flagged");
    }

    @Test
    void execute_withAab_returnsAabFinding() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.aab", Map.of());
        List<Finding> findings = plugin.execute("app.aab", plan, Map.of());
        boolean hasAab = findings.stream()
                .anyMatch(f -> f.getTitle().contains("AAB"));
        assertTrue(hasAab, "AAB should be detected");
    }

    @Test
    void execute_withConfigJson_passedToAnalyzer() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        Map<String, String> opts = Map.of("configJson", "exported=true");
        List<Finding> findings = plugin.execute("app.apk", plan, opts);
        boolean hasExported = findings.stream()
                .anyMatch(f -> f.getTitle().contains("Exported"));
        assertTrue(hasExported, "Config with exported=true should be detected");
    }

    @Test
    void execute_withoutConfigJson_defaultsToNull() {
        SecurityScannerPlugin.ScanPlan plan = plugin.plan("app.apk", Map.of());
        List<Finding> findings = plugin.execute("app.apk", plan, Map.of());
        assertNotNull(findings);
        assertFalse(findings.isEmpty());
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
        f.setFilePath("app.apk");
        Finding result = plugin.normalize(f, Map.of());
        assertSame(f, result);
    }

    @Test
    void normalize_doesNotModifyFields() {
        Finding f = new Finding();
        f.setAssetName("original");
        f.setFilePath("original.apk");
        Finding result = plugin.normalize(f, Map.of());
        assertEquals("original", result.getAssetName());
        assertEquals("original.apk", result.getFilePath());
    }

    // ── validate() ────────────────────────────────────────────────────

    @Test
    void validate_validFinding_returnsValid() {
        Finding f = new Finding();
        f.setTitle("Mobile Issue");
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
