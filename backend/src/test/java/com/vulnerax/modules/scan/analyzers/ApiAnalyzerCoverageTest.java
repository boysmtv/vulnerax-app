package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiAnalyzerCoverageTest {

    @Test
    void analyze_nullTarget_returnsEmpty() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze(null);
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_nonHttpTarget_returnsEmpty() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("ftp://example.com");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_unreachableTarget_returnsCompleteMessage() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("https://definitely-not-reachable-12345.invalid");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_urlWithTrailingSlash_handled() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("https://definitely-not-reachable.invalid/");
        assertThat(result).isNotNull();
    }

    @Test
    void mk_returnsCorrectMap() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("https://unreachable-test-xyz.invalid");
        if (!result.isEmpty()) {
            Map<String, Object> finding = result.get(0);
            assertThat(finding).containsKey("title");
            assertThat(finding).containsKey("cwe");
            assertThat(finding).containsKey("severity");
            assertThat(finding).containsKey("file");
            assertThat(finding).containsKey("recommendation");
        }
    }

    @Test
    void analyze_fields_complete() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("https://definitely-not-reachable.invalid");
        assertThat(result).isNotEmpty();
        Map<String, Object> f = result.get(0);
        assertThat(f).containsKey("title");
        assertThat(f).containsKey("cwe");
        assertThat(f).containsKey("severity");
        assertThat(f).containsKey("file");
        assertThat(f).containsKey("recommendation");
    }
}
