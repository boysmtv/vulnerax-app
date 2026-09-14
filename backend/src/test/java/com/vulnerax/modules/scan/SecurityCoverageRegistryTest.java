package com.vulnerax.modules.scan;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SecurityCoverageRegistryTest {

    private SecurityCoverageRegistry registry;

    @BeforeEach
    void setUp() {
        registry = new SecurityCoverageRegistry();
    }

    @Test
    void constructor_registersAllTests() {
        assertFalse(registry.getTestsForTarget("or").isEmpty());
        assertFalse(registry.getTestsForTarget("sqli").isEmpty());
    }

    @Test
    void registerTest_addsNewTest() {
        SecurityCoverageRegistry.TestDefinition test = new SecurityCoverageRegistry.TestDefinition(
                "CUSTOM-01", "Custom Test", "TEST", List.of("custom"), "Test desc", List.of("indicator")
        );
        registry.registerTest(test);
        List<SecurityCoverageRegistry.TestDefinition> tests = registry.getTestsForTarget("custom");
        assertFalse(tests.isEmpty());
        assertEquals("CUSTOM-01", tests.get(0).id());
    }

    @Test
    void registerTargetHint_addsHint() {
        registry.registerTargetHint("custom", "Custom hint");
        Map<String, Object> plan = registry.planCoverage("custom", "https://example.com");
        assertEquals("Custom hint", plan.get("hint"));
    }

    @Test
    void getTestsForTarget_orType_returnsAllOrTests() {
        List<SecurityCoverageRegistry.TestDefinition> tests = registry.getTestsForTarget("or");
        assertTrue(tests.size() > 5);
    }

    @Test
    void getTestsForTarget_sqliType_returnsSqlInjectionTests() {
        List<SecurityCoverageRegistry.TestDefinition> tests = registry.getTestsForTarget("sqli");
        assertFalse(tests.isEmpty());
    }

    @Test
    void getTestsForTarget_unknownType_returnsEmpty() {
        List<SecurityCoverageRegistry.TestDefinition> tests = registry.getTestsForTarget("UNKNOWN_TYPE_XYZ");
        assertTrue(tests.isEmpty());
    }

    @Test
    void planCoverage_orType_returnsAllFields() {
        Map<String, Object> plan = registry.planCoverage("or", "https://example.com");
        assertNotNull(plan.get("target"));
        assertNotNull(plan.get("targetType"));
        assertNotNull(plan.get("totalTests"));
        assertNotNull(plan.get("recommendedTags"));
        assertNotNull(plan.get("hint"));
        assertNotNull(plan.get("tests"));
    }

    @Test
    void planCoverage_unknownType_returnsDefaultHint() {
        Map<String, Object> plan = registry.planCoverage("unknown", "test");
        assertEquals("No specific hints", plan.get("hint"));
    }

    @Test
    void calculateCoverage_withFoundTags_returnsPercentage() {
        double coverage = registry.calculateCoverage(Set.of("or", "xss"));
        assertTrue(coverage > 0);
    }

    @Test
    void calculateCoverage_emptyTags_returnsZero() {
        double coverage = registry.calculateCoverage(Set.of());
        assertEquals(0.0, coverage);
    }

    @Test
    void calculateCoverageWithFinds_matchingTypes_returnsMatches() {
        Map<String, Object> result = registry.calculateCoverageWithFinds(
                Set.of("sqli", "xss"), Set.of("CWE-89")
        );
        assertNotNull(result.get("matched"));
        assertNotNull(result.get("unmatched"));
        assertNotNull(result.get("overallPercentage"));
    }

    @Test
    void calculateCoverageWithFinds_noMatches_allUnmatched() {
        Map<String, Object> result = registry.calculateCoverageWithFinds(
                Set.of("NONEXISTENT"), Set.of("NONEXISTENT")
        );
        assertTrue(((List<?>) result.get("matched")).isEmpty());
        assertFalse(((List<?>) result.get("unmatched")).isEmpty());
    }

    @Test
    void calculateCoverage_projectId_returnsStructure() {
        Map<String, Object> result = registry.calculateCoverage(UUID.randomUUID());
        assertNotNull(result.get("overallPercentage"));
        assertNotNull(result.get("tested"));
        assertNotNull(result.get("untested"));
        assertNotNull(result.get("totalTests"));
        assertNotNull(result.get("testedCount"));
    }

    @Test
    void testDefinition_recordFields() {
        SecurityCoverageRegistry.TestDefinition test = new SecurityCoverageRegistry.TestDefinition(
                "T-01", "Test", "PHASE", List.of("tag"), "desc", List.of("ind")
        );
        assertEquals("T-01", test.id());
        assertEquals("Test", test.name());
        assertEquals("PHASE", test.phase());
        assertEquals(List.of("tag"), test.tags());
        assertEquals("desc", test.description());
        assertEquals(List.of("ind"), test.indicators());
    }

    @Test
    void getTestsForTarget_tlsType_returnsTlsTests() {
        List<SecurityCoverageRegistry.TestDefinition> tests = registry.getTestsForTarget("tls");
        assertFalse(tests.isEmpty());
    }

    @Test
    void planCoverage_multipleTestTypes_returnsAggregated() {
        Map<String, Object> plan = registry.planCoverage("sqli", "https://example.com");
        int totalTests = (int) plan.get("totalTests");
        assertTrue(totalTests > 0);
    }

    @Test
    void calculateCoverageWithFinds_indicatorsMatchCwe() {
        Map<String, Object> result = registry.calculateCoverageWithFinds(
                Set.of("sast"), Set.of("SQL Injection")
        );
        List<Map<String, Object>> matched = (List<Map<String, Object>>) result.get("matched");
        assertNotNull(matched);
    }
}
