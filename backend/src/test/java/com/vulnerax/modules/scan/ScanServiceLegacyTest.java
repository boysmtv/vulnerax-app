package com.vulnerax.modules.scan;

import com.vulnerax.modules.finding.Finding;
import com.vulnerax.modules.finding.FindingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.kafka.core.KafkaTemplate;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ScanServiceLegacyTest {

    @Mock private ScanRepository scanRepo;
    @Mock private ScanJobRepository jobRepo;
    @Mock private FindingService findingService;
    @Mock private ApplicationContext ctx;
    @Mock private SecurityCoverageRegistry coverageRegistry;
    @Mock private KafkaTemplate<String, Object> kafkaTemplate;

    private ScanService scanService;
    private UUID projectId;
    private UUID scanId;
    private UUID assetId;

    @BeforeEach
    void setUp() {
        scanService = new ScanService(scanRepo, jobRepo, findingService, ctx, coverageRegistry, List.of(), kafkaTemplate);
        projectId = UUID.randomUUID();
        scanId = UUID.randomUUID();
        assetId = UUID.randomUUID();
    }

    private Scan buildScan(String scannerType, String target, String configJson) {
        Scan s = Scan.builder()
                .projectId(projectId)
                .assetId(assetId)
                .scannerType(scannerType)
                .profile("STANDARD")
                .target(target)
                .configJson(configJson)
                .status("RUNNING")
                .scanType("url")
                .build();
        s.setId(scanId);
        return s;
    }

    private Method getPrivateMethod(String name, Class<?>... paramTypes) throws NoSuchMethodException {
        Method m = ScanService.class.getDeclaredMethod(name, paramTypes);
        m.setAccessible(true);
        return m;
    }

    @SuppressWarnings("unchecked")
    private int invokeRunLegacyAnalyzer(Scan scan) throws Exception {
        Method m = getPrivateMethod("runLegacyAnalyzer", Scan.class);
        return (int) m.invoke(scanService, scan);
    }

    @SuppressWarnings("unchecked")
    private int invokeExecutePlugin(String pluginId, Scan scan) throws Exception {
        Method m = getPrivateMethod("executePlugin", String.class, Scan.class);
        return (int) m.invoke(scanService, pluginId, scan);
    }

    @SuppressWarnings("unchecked")
    private String invokeExtractFileContent(Scan scan) throws Exception {
        Method m = getPrivateMethod("extractFileContent", Scan.class);
        return (String) m.invoke(scanService, scan);
    }

    @SuppressWarnings("unchecked")
    private String invokeBuildEvidenceJsonMap(Map<String, Object> f) throws Exception {
        Method m = getPrivateMethod("buildEvidenceJson", Map.class);
        return (String) m.invoke(scanService, f);
    }

    @SuppressWarnings("unchecked")
    private String invokeBuildDastEvidence(Map<String, Object> f, String target) throws Exception {
        Method m = getPrivateMethod("buildDastEvidence", Map.class, String.class);
        return (String) m.invoke(scanService, f, target);
    }

    @SuppressWarnings("unchecked")
    private Finding invokeBuildFindingFromMap(Map<String, Object> f, Scan scan, String type, String source, double defaultCvss) throws Exception {
        Method m = getPrivateMethod("buildFindingFromMap", Map.class, Scan.class, String.class, String.class, double.class);
        return (Finding) m.invoke(scanService, f, scan, type, source, defaultCvss);
    }

    @SuppressWarnings("unchecked")
    private String invokeBuildEvidenceJsonFinding(Finding f) throws Exception {
        Method m = getPrivateMethod("buildEvidenceJson", Finding.class);
        return (String) m.invoke(scanService, f);
    }

    private void injectPluginRegistry(Map<String, SecurityScannerPlugin> registry) throws Exception {
        Field f = ScanService.class.getDeclaredField("pluginRegistry");
        f.setAccessible(true);
        f.set(scanService, registry);
    }

    // =====================================================
    // runLegacyAnalyzer tests
    // =====================================================

    @Test
    void runLegacyAnalyzer_SECRET_type_createsFindings() throws Exception {
        String secretContent = "AKIAIOSFODNN7EXAMPLE";
        String configJson = "{\"fileContent\": \"" + secretContent + "\"}";
        Scan scan = buildScan("SECRET", "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "SECRET analyzer should find the AWS key");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_SAST_type_createsFindings() throws Exception {
        String sastContent = "Statement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = '\" + userId + \"'\");";
        String configJson = "{\"fileContent\": \"" + sastContent.replace("\"", "\\\"") + "\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "SAST analyzer should detect SQL injection");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_DAST_type_noHttpTarget_returnsEmpty() throws Exception {
        Scan scan = buildScan("DAST", "not-a-url", null);

        int count = invokeRunLegacyAnalyzer(scan);

        assertEquals(0, count, "DAST with non-HTTP target should return 0");
    }

    @Test
    void runLegacyAnalyzer_SCA_type_createsFindings() throws Exception {
        String scaContent = "{\"dependencies\": {\"log4j\": \"2.14.1\"}}";
        String configJson = "{\"fileContent\": \"" + scaContent.replace("\"", "\\\"") + "\"}";
        Scan scan = buildScan("SCA", "package.json", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "SCA analyzer should find vulnerable log4j");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_CONTAINER_type_createsFindings() throws Exception {
        String configJson = "{\"dockerfileContent\": \"FROM nginx:1.18\\nRUN apt-get update\"}";
        Scan scan = buildScan("CONTAINER", "nginx:1.18", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "CONTAINER analyzer should find vulnerable base image");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_IAC_type_createsFindings() throws Exception {
        String iacContent = "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}";
        String configJson = "{\"fileContent\": \"" + iacContent.replace("\"", "\\\"") + "\"}";
        Scan scan = buildScan("IAC", "main.tf", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "IAC analyzer should find public S3 bucket");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_API_type_noHttpTarget_skipsApi() throws Exception {
        Scan scan = buildScan("API", "ftp://example.com", null);

        int count = invokeRunLegacyAnalyzer(scan);

        assertEquals(0, count, "API with non-HTTP target should return 0");
    }

    @Test
    void runLegacyAnalyzer_MOBILE_type_createsFindings() throws Exception {
        String configJson = "{\"manifestContent\": \"debuggable=true allowBackup=true\"}";
        Scan scan = buildScan("MOBILE", "app.apk", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "MOBILE analyzer should find debuggable APK issues");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_ALL_type_createsAllFindings() throws Exception {
        String secretContent = "AKIAIOSFODNN7EXAMPLE";
        String configJson = "{\"fileContent\": \"" + secretContent + "\"}";
        Scan scan = buildScan("ALL", "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count > 0, "ALL type should create at least one finding");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void runLegacyAnalyzer_nullType_defaultsToSast() throws Exception {
        String sastContent = "Statement stmt = conn.prepareStatement(\"SELECT * FROM users WHERE id = '\" + userId + \"'\");";
        String configJson = "{\"fileContent\": \"" + sastContent.replace("\"", "\\\"") + "\"}";
        Scan scan = buildScan(null, "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count >= 0, "Null type defaults to SAST without crashing");
    }

    @Test
    void runLegacyAnalyzer_exception_returns0() throws Exception {
        Scan scan = buildScan("SAST", null, null);
        scan.setScannerType("SAST");
        scan.setTarget(null);

        int count = invokeRunLegacyAnalyzer(scan);

        assertEquals(0, count, "Exception in legacy analyzer should return 0");
    }

    // =====================================================
    // executePlugin tests
    // =====================================================

    @Test
    void executePlugin_pluginNotFound_fallsToLegacy() throws Exception {
        String secretContent = "AKIAIOSFODNN7EXAMPLE";
        String configJson = "{\"fileContent\": \"" + secretContent + "\"}";
        Scan scan = buildScan("SECRET", "test.java", configJson);

        int count = invokeExecutePlugin("unknown-plugin", scan);

        assertTrue(count >= 0, "Unknown plugin should fall back to legacy");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void executePlugin_pluginThrows_fallsToLegacy() throws Exception {
        String secretContent = "AKIAIOSFODNN7EXAMPLE";
        String configJson = "{\"fileContent\": \"" + secretContent + "\"}";
        Scan scan = buildScan("SECRET", "test.java", configJson);

        SecurityScannerPlugin failingPlugin = mock(SecurityScannerPlugin.class);
        when(failingPlugin.getId()).thenReturn("failing-plugin");
        when(failingPlugin.plan(anyString(), anyMap())).thenThrow(new RuntimeException("Plugin init failed"));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("failing-plugin", failingPlugin);
        injectPluginRegistry(registry);

        int count = invokeExecutePlugin("failing-plugin", scan);

        assertTrue(count >= 0, "Plugin exception should fall back to legacy");
        verify(findingService, atLeastOnce()).create(any(Finding.class));
    }

    @Test
    void executePlugin_validExecution_createsFindings() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        Finding pluginFinding = Finding.builder()
                .title("Test Finding")
                .description("Test description")
                .type("SAST")
                .severity("HIGH")
                .confidence("HIGH")
                .status("OPEN")
                .source("test-plugin")
                .build();

        SecurityScannerPlugin validPlugin = mock(SecurityScannerPlugin.class);
        when(validPlugin.getId()).thenReturn("valid-plugin");
        when(validPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(validPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(pluginFinding));
        when(validPlugin.normalize(any(), anyMap())).thenReturn(pluginFinding);
        when(validPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("valid-plugin", validPlugin);
        injectPluginRegistry(registry);

        int count = invokeExecutePlugin("valid-plugin", scan);

        assertEquals(1, count, "Valid plugin should create 1 finding");
        verify(findingService).create(any(Finding.class));
    }

    @Test
    void executePlugin_findingValidationFails_skipsFinding() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        Finding pluginFinding = Finding.builder()
                .title("Rejected Finding")
                .description("Should be rejected")
                .type("SAST")
                .severity("HIGH")
                .confidence("HIGH")
                .status("OPEN")
                .source("test-plugin")
                .build();

        SecurityScannerPlugin invalidPlugin = mock(SecurityScannerPlugin.class);
        when(invalidPlugin.getId()).thenReturn("invalid-plugin");
        when(invalidPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(invalidPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(pluginFinding));
        when(invalidPlugin.normalize(any(), anyMap())).thenReturn(pluginFinding);
        when(invalidPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(false, "Missing severity"));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("invalid-plugin", invalidPlugin);
        injectPluginRegistry(registry);

        int count = invokeExecutePlugin("invalid-plugin", scan);

        assertEquals(0, count, "Validation failure should skip finding");
        verify(findingService, never()).create(any(Finding.class));
    }

    @Test
    void executePlugin_validExecution_setsScanFieldsOnFinding() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        Finding pluginFinding = Finding.builder()
                .title("Fields Check")
                .description("Check fields are set")
                .type("SAST")
                .severity("HIGH")
                .confidence("HIGH")
                .status("OPEN")
                .source("test-plugin")
                .build();

        SecurityScannerPlugin fieldPlugin = mock(SecurityScannerPlugin.class);
        when(fieldPlugin.getId()).thenReturn("field-plugin");
        when(fieldPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(fieldPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(pluginFinding));
        when(fieldPlugin.normalize(any(), anyMap())).thenReturn(pluginFinding);
        when(fieldPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("field-plugin", fieldPlugin);
        injectPluginRegistry(registry);

        invokeExecutePlugin("field-plugin", scan);

        verify(findingService).create(argThat(f -> {
            assertEquals(projectId, f.getProjectId());
            assertEquals(assetId, f.getAssetId());
            assertEquals("test.java", f.getAssetName());
            assertEquals(scanId, f.getScanId());
            assertEquals("OPEN", f.getStatus());
            assertNotNull(f.getEvidenceJson());
            return true;
        }));
    }

    @Test
    void executePlugin_withFileContent_setsOptionsCorrectly() throws Exception {
        String configJson = "{\"fileContent\": \"test content\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        Finding pluginFinding = Finding.builder()
                .title("FileContent Test")
                .description("Test")
                .type("SAST")
                .severity("HIGH")
                .confidence("HIGH")
                .build();

        SecurityScannerPlugin fcPlugin = mock(SecurityScannerPlugin.class);
        when(fcPlugin.getId()).thenReturn("fc-plugin");
        when(fcPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(fcPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(pluginFinding));
        when(fcPlugin.normalize(any(), anyMap())).thenReturn(pluginFinding);
        when(fcPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("fc-plugin", fcPlugin);
        injectPluginRegistry(registry);

        invokeExecutePlugin("fc-plugin", scan);

        verify(fcPlugin).plan(eq("test.java"), argThat(opts ->
                opts.containsKey("fileContent") && opts.containsKey("fileName") && opts.containsKey("configJson")));
    }

    @Test
    void executePlugin_evidenceJsonAlreadySet_notOverwritten() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        Finding pluginFinding = Finding.builder()
                .title("Evidence Check")
                .description("Test")
                .type("SAST")
                .severity("HIGH")
                .confidence("HIGH")
                .evidenceJson("{\"custom\": \"evidence\"}")
                .build();

        SecurityScannerPlugin evPlugin = mock(SecurityScannerPlugin.class);
        when(evPlugin.getId()).thenReturn("ev-plugin");
        when(evPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(evPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(pluginFinding));
        when(evPlugin.normalize(any(), anyMap())).thenReturn(pluginFinding);
        when(evPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("ev-plugin", evPlugin);
        injectPluginRegistry(registry);

        invokeExecutePlugin("ev-plugin", scan);

        verify(findingService).create(argThat(f -> {
            assertEquals("{\"custom\": \"evidence\"}", f.getEvidenceJson());
            return true;
        }));
    }

    @Test
    void executePlugin_multipleFindings_createsAll() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            Finding f = Finding.builder()
                    .title("Finding " + i)
                    .description("Desc " + i)
                    .type("SAST")
                    .severity("HIGH")
                    .confidence("HIGH")
                    .build();
            findings.add(f);
        }

        SecurityScannerPlugin multiPlugin = mock(SecurityScannerPlugin.class);
        when(multiPlugin.getId()).thenReturn("multi-plugin");
        when(multiPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(multiPlugin.execute(anyString(), any(), anyMap())).thenReturn(findings);
        when(multiPlugin.normalize(any(), anyMap())).thenReturn(findings.get(0));
        when(multiPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("multi-plugin", multiPlugin);
        injectPluginRegistry(registry);

        int count = invokeExecutePlugin("multi-plugin", scan);

        assertEquals(3, count);
        verify(findingService, times(3)).create(any(Finding.class));
    }

    @Test
    void executePlugin_mixedValidation_createsOnlyValid() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        Finding valid = Finding.builder()
                .title("Valid").description("v").type("SAST").severity("HIGH").confidence("HIGH").build();
        Finding invalid = Finding.builder()
                .title("Invalid").description("i").type("SAST").severity("HIGH").confidence("HIGH").build();
        Finding valid2 = Finding.builder()
                .title("Valid2").description("v2").type("SAST").severity("HIGH").confidence("HIGH").build();

        SecurityScannerPlugin mixedPlugin = mock(SecurityScannerPlugin.class);
        when(mixedPlugin.getId()).thenReturn("mixed-plugin");
        when(mixedPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(mixedPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of(valid, invalid, valid2));
        when(mixedPlugin.normalize(any(), anyMap())).thenAnswer(inv -> inv.getArgument(0));
        when(mixedPlugin.validate(any()))
                .thenAnswer(inv -> {
                    Finding f = inv.getArgument(0);
                    if ("Invalid".equals(f.getTitle())) {
                        return new SecurityScannerPlugin.ValidationResult(false, "bad");
                    }
                    return new SecurityScannerPlugin.ValidationResult(true, null);
                });

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("mixed-plugin", mixedPlugin);
        injectPluginRegistry(registry);

        int count = invokeExecutePlugin("mixed-plugin", scan);

        assertEquals(2, count, "Only valid findings should be created");
        verify(findingService, times(2)).create(any(Finding.class));
    }

    // =====================================================
    // extractFileContent tests
    // =====================================================

    @Test
    void extractFileContent_withFileContent_parses() throws Exception {
        String configJson = "{\"fileContent\": \"SELECT * FROM users\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        String result = invokeExtractFileContent(scan);

        assertNotNull(result);
        assertEquals("SELECT * FROM users", result);
    }

    @Test
    void extractFileContent_withoutFileContent_returnsNull() throws Exception {
        String configJson = "{\"other\": \"value\", \"mode\": \"quick\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        String result = invokeExtractFileContent(scan);

        assertNull(result);
    }

    @Test
    void extractFileContent_nullConfigJson_returnsNull() throws Exception {
        Scan scan = buildScan("SAST", "test.java", null);

        String result = invokeExtractFileContent(scan);

        assertNull(result);
    }

    @Test
    void extractFileContent_malformed_returnsNull() throws Exception {
        String configJson = "not valid json at all";
        Scan scan = buildScan("SAST", "test.java", configJson);

        String result = invokeExtractFileContent(scan);

        assertNull(result);
    }

    @Test
    void extractFileContent_withEscapedNewlines_parsesCorrectly() throws Exception {
        String configJson = "{\"fileContent\": \"line1\\nline2\\nline3\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        String result = invokeExtractFileContent(scan);

        assertNotNull(result);
        assertEquals("line1\nline2\nline3", result);
    }

    @Test
    void extractFileContent_withEscapedQuotes_parsesCorrectly() throws Exception {
        String configJson = "{\"fileContent\": \"say \\\"hello\\\"\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        String result = invokeExtractFileContent(scan);

        assertNotNull(result);
        assertEquals("say \"hello\"", result);
    }

    // =====================================================
    // buildEvidenceJson (Map) tests
    // =====================================================

    @Test
    void buildEvidenceJson_finding_returnsJsonString() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("rule", "SQL Injection");
        f.put("file", "test.java");
        f.put("line", 42);
        f.put("snippet", "SELECT * FROM users");
        f.put("match", "concatenation pattern");
        f.put("cwe", "CWE-89");

        String result = invokeBuildEvidenceJsonMap(f);

        assertNotNull(result);
        assertTrue(result.contains("SQL Injection"));
        assertTrue(result.contains("test.java"));
        assertTrue(result.contains("CWE-89"));
        assertTrue(result.contains("timestamp"));
    }

    @Test
    void buildEvidenceJson_withNullValues_returnsJsonString() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("rule", "Test Rule");
        f.put("file", null);
        f.put("line", null);
        f.put("snippet", null);

        String result = invokeBuildEvidenceJsonMap(f);

        assertNotNull(result);
        assertTrue(result.contains("Test Rule"));
        assertTrue(result.contains("timestamp"));
    }

    // =====================================================
    // buildDastEvidence tests
    // =====================================================

    @Test
    void buildDastEvidence_returnsJsonString() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("rule", "Missing Header");
        f.put("file", "https://example.com");
        f.put("testUrl", "https://example.com/api");
        f.put("statusCode", 200);
        f.put("responseHeaders", "Server: nginx");
        f.put("responseBody", "<html></html>");
        f.put("payload", null);

        String result = invokeBuildDastEvidence(f, "https://example.com");

        assertNotNull(result);
        assertTrue(result.contains("Missing Header"));
        assertTrue(result.contains("https://example.com"));
        assertTrue(result.contains("testUrl"));
    }

    @Test
    void buildDastEvidence_withNullFields_returnsJsonString() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("rule", "Test");
        f.put("testUrl", null);
        f.put("statusCode", null);

        String result = invokeBuildDastEvidence(f, "https://test.com");

        assertNotNull(result);
        assertTrue(result.contains("Test"));
    }

    // =====================================================
    // buildFindingFromMap tests
    // =====================================================

    @Test
    void buildFindingFromMap_returnsCorrectFinding() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("title", "SQL Injection");
        f.put("severity", "CRITICAL");
        f.put("cwe", "CWE-89");
        f.put("file", "test.java");
        f.put("line", 42);
        f.put("snippet", "SELECT * FROM users WHERE id = ?");
        f.put("recommendation", "Use parameterized query");
        f.put("rule", "SQL Injection Rule");
        f.put("match", "concatenation");

        Scan scan = buildScan("SAST", "test.java", null);

        Finding result = invokeBuildFindingFromMap(f, scan, "SAST", "sast-analyzer", 7.0);

        assertNotNull(result);
        assertEquals("SQL Injection", result.getTitle());
        assertEquals("CRITICAL", result.getSeverity());
        assertEquals("CWE-89", result.getCwe());
        assertEquals("SAST", result.getType());
        assertEquals("sast-analyzer", result.getSource());
        assertEquals(scanId, result.getScanId());
        assertEquals(projectId, result.getProjectId());
        assertEquals(assetId, result.getAssetId());
        assertEquals("test.java", result.getAssetName());
        assertEquals("OPEN", result.getStatus());
        assertEquals("HIGH", result.getConfidence());
        assertEquals(7.0, result.getCvss());
        assertEquals("test.java", result.getFilePath());
        assertEquals(42, result.getLineNumber());
        assertEquals("SELECT * FROM users WHERE id = ?", result.getCodeSnippet());
        assertEquals("Use parameterized query", result.getRecommendation());
        assertNotNull(result.getEvidenceJson());
    }

    @Test
    void buildFindingFromMap_withNullSnippet_usesRuleDefault() throws Exception {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("title", "Test Finding");
        f.put("severity", "HIGH");
        f.put("rule", "Test Rule");

        Scan scan = buildScan("SAST", "test.java", null);

        Finding result = invokeBuildFindingFromMap(f, scan, "SAST", "sast-analyzer", 7.0);

        assertNotNull(result);
        assertEquals("Test Rule detected", result.getDescription());
    }

    // =====================================================
    // buildEvidenceJson (Finding) tests
    // =====================================================

    @Test
    void buildEvidenceJson_findingOverload_returnsJsonString() throws Exception {
        Finding finding = Finding.builder()
                .title("Test Finding")
                .type("SAST")
                .filePath("test.java")
                .lineNumber(10)
                .codeSnippet("test code")
                .cwe("CWE-89")
                .build();

        String result = invokeBuildEvidenceJsonFinding(finding);

        assertNotNull(result);
        assertTrue(result.contains("SAST"));
        assertTrue(result.contains("test.java"));
        assertTrue(result.contains("CWE-89"));
    }

    @Test
    void buildEvidenceJson_findingWithNulls_returnsJsonString() throws Exception {
        Finding finding = Finding.builder()
                .title("Minimal Finding")
                .type("SECRET")
                .build();

        String result = invokeBuildEvidenceJsonFinding(finding);

        assertNotNull(result);
        assertTrue(result.contains("SECRET"));
    }

    // =====================================================
    // Edge case tests
    // =====================================================

    @Test
    void runLegacyAnalyzer_emptyContent_returnsZeroOrMore() throws Exception {
        String configJson = "{\"fileContent\": \"\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count >= 0, "Empty content should not crash");
    }

    @Test
    void runLegacyAnalyzer_unknownType_defaultsToSast() throws Exception {
        String configJson = "{\"fileContent\": \"test content\"}";
        Scan scan = buildScan("UNKNOWN_TYPE", "test.java", configJson);

        int count = invokeRunLegacyAnalyzer(scan);

        assertTrue(count >= 0, "Unknown type should default to SAST without crashing");
    }

    @Test
    void executePlugin_withConfigJson_passesToPlugin() throws Exception {
        String configJson = "{\"mode\": \"thorough\"}";
        Scan scan = buildScan("SAST", "test.java", configJson);

        SecurityScannerPlugin cfgPlugin = mock(SecurityScannerPlugin.class);
        when(cfgPlugin.getId()).thenReturn("cfg-plugin");
        when(cfgPlugin.plan(anyString(), anyMap())).thenReturn(
                new SecurityScannerPlugin.ScanPlan(List.of(), Map.of()));
        when(cfgPlugin.execute(anyString(), any(), anyMap())).thenReturn(List.of());
        when(cfgPlugin.validate(any())).thenReturn(
                new SecurityScannerPlugin.ValidationResult(true, null));

        Map<String, SecurityScannerPlugin> registry = new LinkedHashMap<>();
        registry.put("cfg-plugin", cfgPlugin);
        injectPluginRegistry(registry);

        invokeExecutePlugin("cfg-plugin", scan);

        verify(cfgPlugin).plan(eq("test.java"), argThat(opts -> opts.containsKey("configJson")));
    }
}
