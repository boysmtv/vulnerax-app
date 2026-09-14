package com.vulnerax.modules.scan.plugins;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.scan.SecurityScannerPlugin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PluginRegistryTest {

    private PluginRegistry registry;

    @Mock
    SecurityScannerPlugin pluginA;

    @Mock
    SecurityScannerPlugin pluginB;

    @Mock
    SecurityScannerPlugin pluginC;

    private void setupMocks() {
        lenient().when(pluginA.getId()).thenReturn("semgrep");
        lenient().when(pluginA.getName()).thenReturn("Semgrep SAST");
        lenient().when(pluginA.getSupportedTargetTypes()).thenReturn(List.of("REPO", "SOURCE_CODE"));
        lenient().when(pluginA.getProvider()).thenReturn("semgrep");

        lenient().when(pluginB.getId()).thenReturn("nuclei");
        lenient().when(pluginB.getName()).thenReturn("Nuclei DAST");
        lenient().when(pluginB.getSupportedTargetTypes()).thenReturn(List.of("URL", "WEBAPP"));
        lenient().when(pluginB.getProvider()).thenReturn("projectdiscovery");

        lenient().when(pluginC.getId()).thenReturn("trivy");
        lenient().when(pluginC.getName()).thenReturn("Trivy SCA");
        lenient().when(pluginC.getSupportedTargetTypes()).thenReturn(List.of("REPO", "CONTAINER_IMAGE", "FS"));
        lenient().when(pluginC.getProvider()).thenReturn("aquasecurity");
    }

    @BeforeEach
    void setUp() {
        setupMocks();
        registry = new PluginRegistry(List.of(pluginA, pluginB, pluginC));
    }

    @Test
    void constructor_registersAllPlugins() {
        List<SecurityScannerPlugin> all = registry.getAllPlugins();
        assertEquals(3, all.size());
    }

    @Test
    void getPlugin_existingId_returnsPlugin() {
        SecurityScannerPlugin result = registry.getPlugin("semgrep");
        assertNotNull(result);
        assertEquals("semgrep", result.getId());
    }

    @Test
    void getPlugin_nonExistingId_returnsNull() {
        SecurityScannerPlugin result = registry.getPlugin("nonexistent");
        assertNull(result);
    }

    @Test
    void getAllPlugins_returnsImmutableCopy() {
        List<SecurityScannerPlugin> all = registry.getAllPlugins();
        assertThrows(UnsupportedOperationException.class, () -> all.add(pluginA));
    }

    @Test
    void getPluginsForTarget_reposReturnsMatchingPlugins() {
        List<SecurityScannerPlugin> result = registry.getPluginsForTarget("REPO");

        assertEquals(2, result.size());
        assertTrue(result.stream().anyMatch(p -> p.getId().equals("semgrep")));
        assertTrue(result.stream().anyMatch(p -> p.getId().equals("trivy")));
    }

    @Test
    void getPluginsForTarget_urlReturnsMatchingPlugins() {
        List<SecurityScannerPlugin> result = registry.getPluginsForTarget("URL");

        assertEquals(1, result.size());
        assertEquals("nuclei", result.get(0).getId());
    }

    @Test
    void getPluginsForTarget_unknownType_returnsEmpty() {
        List<SecurityScannerPlugin> result = registry.getPluginsForTarget("UNKNOWN");

        assertTrue(result.isEmpty());
    }

    @Test
    void getPluginsForTarget_containerImageReturnsTrivy() {
        List<SecurityScannerPlugin> result = registry.getPluginsForTarget("CONTAINER_IMAGE");

        assertEquals(1, result.size());
        assertEquals("trivy", result.get(0).getId());
    }

    @Test
    void scan_matchingPlugin_executesAndReturnsFindings() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(
                List.of(new SecurityScannerPlugin.ScanStep("1", "SAST", "scan", Map.of())),
                Map.of()
        );
        Finding finding = new Finding();
        finding.setTitle("SQL Injection");
        finding.setType("INJECTION");
        finding.setSeverity("HIGH");

        when(pluginA.plan(anyString(), anyMap())).thenReturn(plan);
        when(pluginA.execute(anyString(), eq(plan), anyMap())).thenReturn(List.of(finding));
        when(pluginA.normalize(any(), anyMap())).thenReturn(finding);
        when(pluginA.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        List<Map<String, Object>> results = registry.scan("REPO", "https://github.com/test/repo", Map.of());

        assertFalse(results.isEmpty());
        assertEquals("semgrep", results.get(0).get("plugin"));
        assertNotNull(results.get(0).get("finding"));
    }

    @Test
    void scan_pluginThrowsException_capturesError() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        when(pluginA.plan(anyString(), anyMap())).thenReturn(plan);
        when(pluginA.execute(anyString(), eq(plan), anyMap())).thenThrow(new RuntimeException("Connection timeout"));

        List<Map<String, Object>> results = registry.scan("REPO", "https://github.com/test/repo", Map.of());

        assertEquals(1, results.size());
        assertEquals("semgrep", results.get(0).get("plugin"));
        assertEquals("Connection timeout", results.get(0).get("error"));
    }

    @Test
    void scan_invalidFinding_excludesResult() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        Finding finding = new Finding();
        finding.setTitle("Low confidence");

        when(pluginA.plan(anyString(), anyMap())).thenReturn(plan);
        when(pluginA.execute(anyString(), eq(plan), anyMap())).thenReturn(List.of(finding));
        when(pluginA.normalize(any(), anyMap())).thenReturn(finding);
        when(pluginA.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(false, "low confidence"));

        List<Map<String, Object>> results = registry.scan("REPO", "https://github.com/test/repo", Map.of());

        assertTrue(results.isEmpty());
    }

    @Test
    void scan_multiplePluginsAggregatesResults() {
        SecurityScannerPlugin.ScanPlan planA = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        SecurityScannerPlugin.ScanPlan planB = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());

        Finding f1 = new Finding();
        f1.setTitle("Finding from semgrep");
        Finding f2 = new Finding();
        f2.setTitle("Finding from trivy");

        when(pluginA.plan("https://github.com/test/repo", Map.of())).thenReturn(planA);
        when(pluginA.execute("https://github.com/test/repo", planA, Map.of())).thenReturn(List.of(f1));
        when(pluginA.normalize(any(), anyMap())).thenReturn(f1);
        when(pluginA.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        when(pluginC.plan("https://github.com/test/repo", Map.of())).thenReturn(planB);
        when(pluginC.execute("https://github.com/test/repo", planB, Map.of())).thenReturn(List.of(f2));
        when(pluginC.normalize(any(), anyMap())).thenReturn(f2);
        when(pluginC.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        List<Map<String, Object>> results = registry.scan("REPO", "https://github.com/test/repo", Map.of());

        assertEquals(2, results.size());
    }

    @Test
    void scan_noMatchingPlugins_returnsEmpty() {
        List<Map<String, Object>> results = registry.scan("UNKNOWN_TYPE", "target", Map.of());

        assertTrue(results.isEmpty());
    }

    @Test
    void scan_multipleFindingsFromOnePlugin_allCaptured() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        Finding f1 = new Finding();
        f1.setTitle("Issue 1");
        Finding f2 = new Finding();
        f2.setTitle("Issue 2");
        Finding f3 = new Finding();
        f3.setTitle("Issue 3");

        when(pluginB.plan(anyString(), anyMap())).thenReturn(plan);
        when(pluginB.execute(anyString(), eq(plan), anyMap())).thenReturn(List.of(f1, f2, f3));
        when(pluginB.normalize(any(), anyMap())).thenReturn(f1);
        when(pluginB.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        List<Map<String, Object>> results = registry.scan("URL", "https://example.com", Map.of());

        assertEquals(3, results.size());
    }

    @Test
    void getPluginsForTarget_filesystemReturnsTrivy() {
        List<SecurityScannerPlugin> result = registry.getPluginsForTarget("FS");

        assertEquals(1, result.size());
        assertEquals("trivy", result.get(0).getId());
    }

    @Test
    void scan_planThenExecuteCorrectlyChained() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        Map<String, String> options = Map.of("severity", "HIGH");

        when(pluginA.plan("https://example.com", options)).thenReturn(plan);
        when(pluginA.execute("https://example.com", plan, options)).thenReturn(List.of());
        lenient().when(pluginA.normalize(any(), eq(options))).thenReturn(new Finding());
        lenient().when(pluginA.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        registry.scan("SOURCE_CODE", "https://example.com", options);

        verify(pluginA).plan("https://example.com", options);
        verify(pluginA).execute("https://example.com", plan, options);
    }

    @Test
    void scan_withOptions_passedToPlugin() {
        SecurityScannerPlugin.ScanPlan plan = new SecurityScannerPlugin.ScanPlan(List.of(), Map.of());
        Map<String, String> options = Map.of("severity", "CRITICAL", "depth", "3");

        when(pluginB.plan("https://target.com", options)).thenReturn(plan);
        when(pluginB.execute("https://target.com", plan, options)).thenReturn(List.of());
        lenient().when(pluginB.normalize(any(), eq(options))).thenReturn(new Finding());
        lenient().when(pluginB.validate(any())).thenReturn(new SecurityScannerPlugin.ValidationResult(true, "ok"));

        registry.scan("URL", "https://target.com", options);

        verify(pluginB).plan("https://target.com", options);
    }
}
