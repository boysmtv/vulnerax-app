package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DastAnalyzerTest2 {

    @Test
    void analyze_nullTarget_returnsEmptyList() {
        List<Map<String,Object>> result = DastAnalyzer.analyze(null, "test.java");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void analyze_nonHttpTarget_returnsEmptyList() {
        List<Map<String,Object>> result = DastAnalyzer.analyze("ftp://example.com", "test.java");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void analyze_ipTarget_returnsEmptyList() {
        List<Map<String,Object>> result = DastAnalyzer.analyze("192.168.1.1", "test.java");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void analyze_blankTarget_returnsEmptyList() {
        List<Map<String,Object>> result = DastAnalyzer.analyze("  ", "test.java");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void analyze_httpNonexistentHost_returnsTargetUnreachable() {
        List<Map<String,Object>> result = DastAnalyzer.analyze("http://localhost:19999/unreachable-test", "test.java");
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("Target Unreachable", result.get(0).get("title"));
        assertEquals("CWE-693", result.get(0).get("cwe"));
    }

    @Test
    void analyze_httpsNonexistentHost_returnsTargetUnreachable() {
        List<Map<String,Object>> result = DastAnalyzer.analyze("https://nonexistent.invalid:19999", "test.java");
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("Target Unreachable", result.get(0).get("title"));
    }
}
