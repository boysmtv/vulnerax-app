package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecretAnalyzerCoverageTest {

    @Test
    void analyze_nullContent_returnsEmpty() {
        List<Map<String, Object>> result = SecretAnalyzer.analyze(null, "test.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_emptyContent_returnsEmpty() {
        List<Map<String, Object>> result = SecretAnalyzer.analyze("", "test.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_awsAccessKey_detected() {
        String content = "String key = \"AKIAIOSFODNN7EXAMPLE\";";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "Config.java");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-798");
    }

    @Test
    void analyze_awsSecretKey_detected() {
        String content = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.py");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_privateKey_detected() {
        String content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "server.key");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("severity")).isEqualTo("CRITICAL");
    }

    @Test
    void analyze_genericApiKey_detected() {
        String content = "api_key = \"sk-1234567890abcdef1234567890abcdef\";";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "config.js");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_jwtSecret_detected() {
        String content = "jwt_secret = 'my-super-secret-jwt-key-here'";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "auth.js");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_firebaseKey_detected() {
        String content = "const key = \"AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\";";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "firebase.js");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_noSecret_returnsEmpty() {
        String content = "String name = \"John Doe\";";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "App.java");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_nullFileName_handled() {
        String content = "-----BEGIN RSA PRIVATE KEY-----";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, null);
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("file")).isEqualTo("unknown");
    }

    @Test
    void analyze_multipleSecrets_found() {
        String content = """
                AKIAIOSFODNN7EXAMPLE
                -----BEGIN RSA PRIVATE KEY-----
                api_key = "sk-1234567890abcdef1234567890abcdef"
                """;
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "secrets.txt");
        assertThat(result.size()).isGreaterThanOrEqualTo(3);
    }

    @Test
    void analyze_lineNumber_correct() {
        String content = "line1\nline2\nAKIAIOSFODNN7EXAMPLE\nline4";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "test.txt");
        assertThat(result).isNotEmpty();
        assertThat((Integer) result.get(0).get("line")).isEqualTo(3);
    }

    @Test
    void analyze_maskedMatch() {
        String content = "AKIAIOSFODNN7EXAMPLE";
        List<Map<String, Object>> result = SecretAnalyzer.analyze(content, "test.txt");
        assertThat(result).isNotEmpty();
        String match = (String) result.get(0).get("match");
        assertThat(match).contains("****");
    }

    @Test
    void analyze_maxFindings_limited() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 25; i++) {
            sb.append("AKIAIOSFODNN").append(i).append("EXAMPL\n");
        }
        List<Map<String, Object>> result = SecretAnalyzer.analyze(sb.toString(), "test.txt");
        assertThat(result.size()).isLessThanOrEqualTo(20);
    }
}
