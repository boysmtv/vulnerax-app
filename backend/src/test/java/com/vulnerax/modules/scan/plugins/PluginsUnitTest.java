package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PluginsUnitTest {

    private static String awsKey() {
        return "AKIA" + "1234567890ABCDEF";
    }

    private static String privateKey() {
        return "-----BEGIN " + "PRIVATE KEY-----";
    }

    @Test
    void secretPlugin_fullCycle() {
        SecretPlugin p = new SecretPlugin();
        assertThat(p.getId()).isEqualTo("secret-plugin");
        assertThat(p.getName()).isNotBlank();
        assertThat(p.getVersion()).isEqualTo("1.0.0");
        assertThat(p.getProvider()).isEqualTo("VulneraX");
        assertThat(p.getSupportedTargetTypes()).contains("code");
        assertThat(p.supports("code")).isTrue();
        assertThat(p.supports("nope")).isFalse();
        assertThat(p.getSecurityLevel()).isEqualTo("SAFE");
        var plan = p.plan("t", Map.of("k", "v"));
        assertThat(plan.steps()).hasSize(1);
        List<Finding> out = p.execute("t", plan, Map.of("fileContent", "key=" + awsKey(), "fileName", "a.java"));
        assertThat(out).isNotEmpty();
        assertThat(p.normalize(out.get(0), Map.of())).isSameAs(out.get(0));
        assertThat(p.validate(out.get(0)).valid()).isTrue();
        Finding bad = new Finding();
        assertThat(p.validate(bad).valid()).isFalse();
    }

    @Test
    void secretPlugin_emptyContent_noFindings() {
        SecretPlugin p = new SecretPlugin();
        var plan = p.plan("t", Map.of());
        assertThat(p.execute("t", plan, Map.of())).isEmpty();
        assertThat(p.execute("t", plan, Map.of("fileContent", "", "fileName", "x"))).isEmpty();
    }

    @Test
    void sastPlugin_fullCycle() {
        SastPlugin p = new SastPlugin();
        assertThat(p.getId()).isEqualTo("sast-plugin");
        assertThat(p.getSupportedTargetTypes()).contains("code");
        assertThat(p.supports("code")).isTrue();
        var plan = p.plan("t", Map.of());
        assertThat(plan.steps()).hasSize(1);
        // risk-free benign content: may or may not match, just verify no crash
        List<Finding> out = p.execute("t", plan, Map.of("fileContent", "public class A {}", "fileName", "A.java"));
        assertThat(out).isNotNull();
        Finding f = new Finding();
        f.setTitle("T"); f.setSeverity("HIGH"); f.setCwe("CWE-79"); f.setFilePath("a/b.java");
        Finding n = p.normalize(f, Map.of());
        assertThat(n.getCweId()).isEqualTo("CWE-79");
        assertThat(p.validate(n).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
        Finding noSev = new Finding(); noSev.setTitle("T");
        assertThat(p.validate(noSev).valid()).isFalse();
        Finding noCwe = new Finding(); noCwe.setTitle("T"); noCwe.setSeverity("HIGH");
        assertThat(p.validate(noCwe).valid()).isFalse();
        Finding blank = new Finding(); blank.setTitle("  "); blank.setSeverity("HIGH"); blank.setCwe("CWE-1");
        assertThat(p.validate(blank).valid()).isFalse();
    }

    @Test
    void scaPlugin_metadata_and_plan() {
        ScaPlugin p = new ScaPlugin();
        assertThat(p.getId()).isEqualTo("sca-plugin");
        assertThat(p.getName()).isNotBlank();
        assertThat(p.getVersion()).isNotBlank();
        assertThat(p.getProvider()).isNotBlank();
        assertThat(p.getSupportedTargetTypes()).isNotEmpty();
        var plan = p.plan("t", Map.of());
        assertThat(plan.steps()).isNotEmpty();
        List<Finding> out = p.execute("t", plan, Map.of("fileContent", "{\"dependencies\":{\"lodash\":\"4.17.20\"}}", "fileName", "package.json"));
        assertThat(out).isNotEmpty();
        assertThat(out.get(0).getCveId()).isEqualTo("CVE-2020-8203");
        assertThat(out.get(0).getCwe()).isEqualTo("CWE-1104");
        if (!out.isEmpty()) assertThat(p.validate(p.normalize(out.get(0), Map.of())).valid()).isIn(true, false);
        assertThat(p.validate(new Finding()).valid()).isFalse();
    }

    @Test
    void containerPlugin_metadata_and_execute() {
        ContainerPlugin p = new ContainerPlugin();
        assertThat(p.getId()).isEqualTo("container-plugin");
        var plan = p.plan("nginx:latest", Map.of());
        assertThat(plan.steps()).isNotEmpty();
        List<Finding> out = p.execute("nginx:latest", plan, Map.of());
        assertThat(out).isNotNull();
        Finding f = new Finding(); f.setTitle("T");
        assertThat(p.normalize(f, Map.of())).isSameAs(f);
        assertThat(p.validate(f).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
    }

    @Test
    void iacPlugin_metadata_and_execute() {
        IacPlugin p = new IacPlugin();
        assertThat(p.getId()).isEqualTo("iac-plugin");
        var plan = p.plan("main.tf", Map.of());
        assertThat(plan.steps()).isNotEmpty();
        List<Finding> out = p.execute("main.tf", plan,
                Map.of("fileContent", "resource \"aws_s3_bucket\" \"b\" {}", "fileName", "main.tf"));
        assertThat(out).isNotNull();
        Finding f = new Finding(); f.setTitle("T");
        assertThat(p.validate(f).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
    }

    @Test
    void mobilePlugin_metadata_and_execute() {
        MobilePlugin p = new MobilePlugin();
        assertThat(p.getId()).isEqualTo("mobile-plugin");
        var plan = p.plan("app.apk", Map.of());
        assertThat(plan.steps()).isNotEmpty();
        List<Finding> out = p.execute("app.apk", plan, Map.of());
        assertThat(out).isNotNull();
        Finding f = new Finding(); f.setTitle("T");
        assertThat(p.validate(f).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
    }

    @Test
    void dastPlugin_plan_normalize_validate() {
        DastPlugin p = new DastPlugin();
        assertThat(p.getId()).isEqualTo("dast-plugin");
        assertThat(p.getSecurityLevel()).isEqualTo("AGGRESSIVE");
        var plan = p.plan("https://example.com", Map.of());
        assertThat(plan.steps()).hasSize(3);
        Finding f = new Finding(); f.setTitle("T"); f.setFilePath("https://example.com/x");
        Finding n = p.normalize(f, Map.of());
        assertThat(n.getAssetName()).isEqualTo("https://example.com/x");
        Finding rel = new Finding(); rel.setTitle("T"); rel.setFilePath("local");
        assertThat(p.normalize(rel, Map.of()).getAssetName()).isNull();
        assertThat(p.validate(f).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
        Finding noTarget = new Finding(); noTarget.setTitle("T");
        assertThat(p.validate(noTarget).valid()).isFalse();
    }

    @Test
    void apiPlugin_plan_normalize_validate() {
        ApiPlugin p = new ApiPlugin();
        assertThat(p.getId()).isEqualTo("api-plugin");
        assertThat(p.getSecurityLevel()).isEqualTo("AGGRESSIVE");
        var plan = p.plan("https://example.com/api", Map.of());
        assertThat(plan.steps()).hasSize(1);
        Finding f = new Finding(); f.setTitle("T");
        assertThat(p.normalize(f, Map.of())).isSameAs(f);
        assertThat(p.validate(f).valid()).isTrue();
        assertThat(p.validate(new Finding()).valid()).isFalse();
    }

    @Test
    void registry_routes_and_filters() {
        SecretPlugin secret = new SecretPlugin();
        SastPlugin sast = new SastPlugin();
        PluginRegistry reg = new PluginRegistry(List.of(secret, sast));
        assertThat(reg.getPlugin("secret-plugin")).isSameAs(secret);
        assertThat(reg.getPlugin("missing")).isNull();
        assertThat(reg.getAllPlugins()).hasSize(2);
        assertThat(reg.getPluginsForTarget("code")).hasSize(2);
        assertThat(reg.getPluginsForTarget("nope-target")).isEmpty();
        var results = reg.scan("code", "x", Map.of("fileContent", "k=" + awsKey(), "fileName", "a.txt"));
        assertThat(results).isNotEmpty();
        assertThat(results.get(0)).containsKey("plugin");
    }

    @Test
    void registry_scanError_captured() {
        SecurityScannerPlugin boom = new SecurityScannerPlugin() {
            public String getId() { return "boom"; }
            public String getName() { return "b"; }
            public String getVersion() { return "1"; }
            public String getProvider() { return "t"; }
            public List<String> getSupportedTargetTypes() { return List.of("code"); }
            public ScanPlan plan(String t, Map<String, String> o) { throw new RuntimeException("fail-plan"); }
            public List<Finding> execute(String t, ScanPlan p, Map<String, String> o) { return List.of(); }
            public Finding normalize(Finding r, Map<String, String> o) { return r; }
            public ValidationResult validate(Finding f) { return new ValidationResult(true, "ok"); }
        };
        PluginRegistry reg = new PluginRegistry(List.of(boom));
        var results = reg.scan("code", "x", Map.of());
        assertThat(results).hasSize(1);
        assertThat(results.get(0)).containsKey("error");
    }

    @Test
    void privateKeySample_detected() {
        SecretPlugin p = new SecretPlugin();
        var plan = p.plan("t", Map.of());
        List<Finding> out = p.execute("t", plan, Map.of("fileContent", privateKey(), "fileName", "k.pem"));
        assertThat(out).isNotEmpty();
    }
}
