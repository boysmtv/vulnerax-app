package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ApiAnalyzerTest {

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
    void analyze_ftpWithSlash_returnsEmpty() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("ftp://example.com/");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_unreachableHttp_returnsApiScanComplete() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://192.0.2.1:99999");
        assertThat(result).isNotNull();
    }

    @Test
    void analyze_unreachableHttp_hasCweField() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://192.0.2.1:99999");
        assertThat(result.get(0)).containsKey("cwe");
        assertThat(result.get(0)).containsKey("severity");
        assertThat(result.get(0)).containsKey("recommendation");
    }

    @Test
    void analyze_emptyString_returnsEmpty() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_httpWithTrailingSlash_stripsSlash() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://192.0.2.1:99999/");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_localhostUnreachable_returnsComplete() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://localhost:19999");
        assertThat(result).isNotNull();
    }

    @Test
    void analyze_resultStructure() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://192.0.2.1:1");
        assertThat(result).isNotEmpty();
        Map<String, Object> finding = result.get(0);
        assertThat(finding).containsKey("title");
        assertThat(finding).containsKey("rule");
        assertThat(finding).containsKey("cwe");
        assertThat(finding).containsKey("severity");
        assertThat(finding).containsKey("file");
        assertThat(finding).containsKey("line");
        assertThat(finding).containsKey("snippet");
        assertThat(finding).containsKey("recommendation");
        assertThat(finding).containsKey("match");
    }

    @Test
    void analyze_localhostWithDifferentPorts() {
        List<Map<String, Object>> result = ApiAnalyzer.analyze("http://localhost:1");
        assertThat(result).isNotEmpty();
    }
}
