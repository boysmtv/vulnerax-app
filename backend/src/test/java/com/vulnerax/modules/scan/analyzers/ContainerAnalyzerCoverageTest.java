package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ContainerAnalyzerCoverageTest {

    @Test
    void analyze_nullTarget_returnsEmpty() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze(null, null);
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_emptyTarget_returnsEmpty() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("", null);
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_vulnBaseImage_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.18", null);
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("title")).toString().contains("Vulnerable Base Image");
    }

    @Test
    void analyze_alpine314_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("alpine:3.14", null);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_node14_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("node:14", null);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_runningAsRoot_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "user: root");
        assertThat(result).isNotEmpty();
        boolean foundRoot = result.stream().anyMatch(f -> f.get("title").toString().contains("Root"));
        assertThat(foundRoot).isTrue();
    }

    @Test
    void analyze_privileged_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "\"privileged\":true");
        assertThat(result).isNotEmpty();
        boolean foundPriv = result.stream().anyMatch(f -> f.get("title").toString().contains("Privileged"));
        assertThat(foundPriv).isTrue();
    }

    @Test
    void analyze_secretsInConfig_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "MYSQL_ROOT_PASSWORD=secret123");
        assertThat(result).isNotEmpty();
        boolean foundSecret = result.stream().anyMatch(f -> f.get("title").toString().contains("Secret"));
        assertThat(foundSecret).isTrue();
    }

    @Test
    void analyze_hostNetwork_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "network_mode: host");
        assertThat(result).isNotEmpty();
        boolean foundHost = result.stream().anyMatch(f -> f.get("title").toString().contains("Host Network"));
        assertThat(foundHost).isTrue();
    }

    @Test
    void analyze_hostPid_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "pid: host");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dangerousCaps_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "cap_add:\n  - SYS_ADMIN");
        assertThat(result).isNotEmpty();
        boolean foundCap = result.stream().anyMatch(f -> f.get("title").toString().contains("Capabilities"));
        assertThat(foundCap).isTrue();
    }

    @Test
    void analyze_writableRootfs_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", "some config");
        assertThat(result).isNotEmpty();
        boolean foundWritable = result.stream().anyMatch(f -> f.get("title").toString().contains("Writable"));
        assertThat(foundWritable).isTrue();
    }

    @Test
    void analyze_latestTag_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:latest", null);
        assertThat(result).isNotEmpty();
        boolean foundLatest = result.stream().anyMatch(f -> f.get("title").toString().contains("latest"));
        assertThat(foundLatest).isTrue();
    }

    @Test
    void analyze_noTag_detected() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage", null);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfileAptNotCleaned_detected() {
        String config = "FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y curl";
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", config);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfileAddFromUrl_detected() {
        String config = "FROM ubuntu:20.04\nADD http://example.com/file.tar.gz /tmp/";
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", config);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfileSecretInEnv_detected() {
        String config = "FROM ubuntu:20.04\nENV password=secret123";
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("myimage:1.0", config);
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_safeImage_noCritical() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("custom-app:v2.0", "read_only: true");
        assertThat(result).isNotEmpty();
        boolean foundNoIssue = result.stream().anyMatch(f -> f.get("title").toString().contains("No Critical"));
        assertThat(foundNoIssue).isTrue();
    }

    @Test
    void analyze_fields_complete() {
        List<Map<String, Object>> result = ContainerAnalyzer.analyze("nginx:1.18", null);
        assertThat(result).isNotEmpty();
        Map<String, Object> f = result.get(0);
        assertThat(f).containsKey("title");
        assertThat(f).containsKey("cwe");
        assertThat(f).containsKey("severity");
        assertThat(f).containsKey("recommendation");
    }
}
