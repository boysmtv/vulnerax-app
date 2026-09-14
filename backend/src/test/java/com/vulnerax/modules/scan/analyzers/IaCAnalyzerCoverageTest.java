package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class IaCAnalyzerCoverageTest {

    @Test
    void analyze_nullContent_returnsEmpty() {
        List<Map<String, Object>> result = IaCAnalyzer.analyze(null, "main.tf");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_emptyContent_returnsEmpty() {
        List<Map<String, Object>> result = IaCAnalyzer.analyze("", "main.tf");
        assertThat(result).isEmpty();
    }

    @Test
    void analyze_terraform_publicS3_detected() {
        String tf = "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "main.tf");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-538");
    }

    @Test
    void analyze_terraform_unencryptedS3_detected() {
        String tf = "resource \"aws_s3_bucket\" \"data\" {}";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "s3.tf");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_terraform_publicRDS_detected() {
        String tf = "resource \"aws_db_instance\" \"db\" {\n  publicly_accessible = true\n}";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "rds.tf");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_terraform_openSecurityGroup_detected() {
        String tf = "resource \"aws_security_group\" \"sg\" {\n  cidr_blocks = [\"0.0.0.0/0\"]\n}";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "sg.tf");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_terraform_iamWildcard_detected() {
        String tf = "\"Effect\": \"Allow\",\n\"Action\": \"*\"";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "iam.tf");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_kubernetes_privileged_detected() {
        String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - securityContext:\n      privileged: true";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("cwe")).isEqualTo("CWE-250");
    }

    @Test
    void analyze_kubernetes_hostNetwork_detected() {
        String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_kubernetes_hostPID_detected() {
        String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_kubernetes_defaultRoot_detected() {
        String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_kubernetes_noResourceLimits_detected() {
        String k8s = "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(k8s, "pod.yaml");
        boolean foundLimits = result.stream().anyMatch(f -> f.get("title").toString().contains("Resource Limits"));
        assertThat(foundLimits).isTrue();
    }

    @Test
    void analyze_dockerfile_noVersionPin_detected() {
        String df = "FROM ubuntu\nRUN apt-get update";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
        assertThat(result).isNotEmpty();
        boolean foundPin = result.stream().anyMatch(f -> f.get("title").toString().contains("No Version Pin"));
        assertThat(foundPin).isTrue();
    }

    @Test
    void analyze_dockerfile_copyAll_detected() {
        String df = "FROM ubuntu:20.04\nCOPY . /app";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfile_addUrl_detected() {
        String df = "FROM ubuntu:20.04\nADD http://example.com/file.tar.gz /tmp/";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfile_chmod777_detected() {
        String df = "FROM ubuntu:20.04\nRUN chmod 777 /app";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_dockerfile_noUser_detected() {
        String df = "FROM ubuntu:20.04\nRUN echo hello";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(df, "Dockerfile");
        boolean foundNoUser = result.stream().anyMatch(f -> f.get("title").toString().contains("No USER"));
        assertThat(foundNoUser).isTrue();
    }

    @Test
    void analyze_cloudformation_publicResource_detected() {
        String cf = "\"PubliclyAccessible\": true";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(cf, "template.json");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_generic_passwordInConfig_detected() {
        String config = "password=secret123";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(config, "config.yml");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_generic_openNetwork_detected() {
        String config = "0.0.0.0/0 allowed";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(config, "config.yml");
        assertThat(result).isNotEmpty();
    }

    @Test
    void analyze_noIssues_returnsCompleteMessage() {
        String safe = "just a normal config file with no issues";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(safe, "normal.txt");
        assertThat(result).isNotEmpty();
        assertThat(result.get(0).get("title")).toString().contains("Complete");
    }

    @Test
    void analyze_fields_complete() {
        String tf = "resource \"aws_s3_bucket\" \"data\" {\n  acl = \"public-read\"\n}";
        List<Map<String, Object>> result = IaCAnalyzer.analyze(tf, "main.tf");
        assertThat(result).isNotEmpty();
        Map<String, Object> f = result.get(0);
        assertThat(f).containsKey("title");
        assertThat(f).containsKey("cwe");
        assertThat(f).containsKey("severity");
        assertThat(f).containsKey("recommendation");
    }
}
