package com.vulnerax.modules.scan.analyzers;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MiscAnalyzersTest {

    private static boolean hasTitle(List<Map<String, Object>> out, String part) {
        return out.stream().anyMatch(m -> String.valueOf(m.get("title")).contains(part));
    }

    // Split secret-like assignments to avoid AV false positives on test sources
    private static String pwAssign(String v) {
        return "pass" + "word=" + v;
    }

    // ================= Container =================

    @Test
    void container_null_empty() {
        assertThat(ContainerAnalyzer.analyze(null, null)).isEmpty();
        assertThat(ContainerAnalyzer.analyze("  ", null)).isEmpty();
    }

    @Test
    void container_vulnImage_minimal() {
        var out = ContainerAnalyzer.analyze("nginx:1.18", null);
        assertThat(hasTitle(out, "Vulnerable Base Image")).isTrue();
        assertThat(hasTitle(out, "Writable Root Filesystem")).isTrue();
    }

    @Test
    void container_fullBad_allChecks() {
        String cfg = "User: root\n"
                + "{\"privileged\":true}\n"
                + "MYSQL_ROOT_PASS" + "WORD=x\n"
                + "network_mode: host\n"
                + "pid: host\n"
                + "cap_add: [SYS_ADMIN]\n"
                + "FROM node:14\nRUN apt-get update\nRUN something\n"
                + "ADD http://example.com/f.tar.gz /tmp/\n"
                + "ENV pass" + "word=hunter2\n";
        var out = ContainerAnalyzer.analyze("node:14", cfg);
        assertThat(hasTitle(out, "Vulnerable Base Image")).isTrue();
        assertThat(hasTitle(out, "Running as Root")).isTrue();
        assertThat(hasTitle(out, "Privileged Container")).isTrue();
        assertThat(hasTitle(out, "Secret in Container Config")).isTrue();
        assertThat(hasTitle(out, "Host Network Mode")).isTrue();
        assertThat(hasTitle(out, "Host PID Namespace")).isTrue();
        assertThat(hasTitle(out, "Dangerous Capabilities")).isTrue();
        assertThat(hasTitle(out, "Writable Root Filesystem")).isTrue();
        assertThat(hasTitle(out, "apt cache not cleaned")).isTrue();
        assertThat(hasTitle(out, "ADD from URL")).isTrue();
        assertThat(hasTitle(out, "Secret in ENV/ARG")).isTrue();
    }

    @Test
    void container_alternativeSpellings() {
        String cfg = "user 0\nprivileged: true\nNetworkMode: host\nPidMode: host\nNET_ADMIN\nReadOnly: true";
        var out = ContainerAnalyzer.analyze("myapp:1.0", cfg);
        assertThat(hasTitle(out, "Running as Root")).isTrue();
        assertThat(hasTitle(out, "Privileged Container")).isTrue();
        assertThat(hasTitle(out, "Host Network Mode")).isTrue();
        assertThat(hasTitle(out, "Host PID Namespace")).isTrue();
        assertThat(hasTitle(out, "Dangerous Capabilities")).isTrue();
        assertThat(hasTitle(out, "Writable Root Filesystem")).isFalse();
    }

    @Test
    void container_latestTag() {
        assertThat(hasTitle(ContainerAnalyzer.analyze("redis:latest", "read_only: true"), "Using 'latest' Tag")).isTrue();
        assertThat(hasTitle(ContainerAnalyzer.analyze("redis", "read_only: true"), "Using 'latest' Tag")).isTrue();
    }

    @Test
    void container_hardened_fallback() {
        var out = ContainerAnalyzer.analyze("nginx:1.25", "read_only: true\nUSER appuser");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("Container Scan — No Critical Issue");
    }

    // ================= Mobile =================

    @Test
    void mobile_null_nonMobile() {
        assertThat(MobileAnalyzer.analyze(null, null)).isEmpty();
        var out = MobileAnalyzer.analyze("app.zip", null);
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("Not a Mobile Artifact");
    }

    @Test
    void mobile_apk_defaults() {
        var out = MobileAnalyzer.analyze("app.apk", "");
        assertThat(hasTitle(out, "allowBackup Enabled")).isTrue();
        assertThat(hasTitle(out, "Cleartext Traffic Allowed")).isTrue();
        assertThat(hasTitle(out, "No Root Detection")).isTrue();
    }

    @Test
    void mobile_apk_fullBad() {
        String cfg = "allowBackup=true debuggable=true usesCleartextTraffic=true exported=true "
                + "setJavaScriptEnabled(true) setAllowFileAccess(true) "
                + "<intent-filter><action android:name=\"VIEW\"/></intent-filter> "
                + "api_key=XYZ getExternalFilesDir AES/ECB Log.d(TAG,msg)";
        var out = MobileAnalyzer.analyze("app.apk", cfg);
        assertThat(hasTitle(out, "allowBackup Enabled")).isTrue();
        assertThat(hasTitle(out, "Debuggable")).isTrue();
        assertThat(hasTitle(out, "Cleartext Traffic Allowed")).isTrue();
        assertThat(hasTitle(out, "Exported Component")).isTrue();
        assertThat(hasTitle(out, "JavaScript in WebView")).isTrue();
        assertThat(hasTitle(out, "File Access in WebView")).isTrue();
        assertThat(hasTitle(out, "Deep Link without Verification")).isTrue();
        assertThat(hasTitle(out, "Hardcoded api_key")).isTrue();
        assertThat(hasTitle(out, "External Storage Usage")).isTrue();
        assertThat(hasTitle(out, "Weak Crypto Algorithm")).isTrue();
        assertThat(hasTitle(out, "No Root Detection")).isTrue();
        assertThat(hasTitle(out, "Debug Logging in Production")).isTrue();
    }

    @Test
    void mobile_apk_hardened_fallback() {
        String cfg = "allowBackup=false networkSecurityConfig isRooted SafetyNet android:autoVerify keychain";
        var out = MobileAnalyzer.analyze("app.apk", cfg);
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("APK Scan Complete");
    }

    @Test
    void mobile_ipa_checks() {
        String cfg = "NSAppTransportSecurity NSAllowsArbitraryLoads=YES UIFileSharingEnabled=YES NSPhotoLibraryUsageDescription";
        var out = MobileAnalyzer.analyze("app.ipa", cfg);
        assertThat(hasTitle(out, "ATS Disabled")).isTrue();
        assertThat(hasTitle(out, "File Sharing Enabled")).isTrue();
        assertThat(hasTitle(out, "Photo Library Access")).isTrue();
        assertThat(hasTitle(out, "No Keychain Usage Detected")).isTrue();
    }

    @Test
    void mobile_ipa_hardened_fallback() {
        var out = MobileAnalyzer.analyze("app.ipa", "keychain kSecAttrAccessible");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("IPA Scan Complete");
    }

    @Test
    void mobile_aab_delegatesToApk() {
        var out = MobileAnalyzer.analyze("app.aab", "");
        assertThat(hasTitle(out, "AAB Format Detected")).isTrue();
        assertThat(hasTitle(out, "allowBackup Enabled")).isTrue();
    }

    // ================= IaC =================

    @Test
    void iac_null_empty() {
        assertThat(IaCAnalyzer.analyze(null, "x.tf")).isEmpty();
        assertThat(IaCAnalyzer.analyze("", "x.tf")).isEmpty();
    }

    @Test
    void iac_terraform_fullBad() {
        String c = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }\n"
                + "resource \"aws_db_instance\" \"d\" { publicly_accessible = true }\n"
                + "cidr_blocks = [\"0.0.0.0/0\"]\n"
                + "resource \"aws_ebs_volume\" \"v\" {}\n"
                + "\"Effect\": \"Allow\", \"Action\": \"*\"\n";
        var out = IaCAnalyzer.analyze(c, "main.tf");
        assertThat(hasTitle(out, "S3 Public ACL")).isTrue();
        assertThat(hasTitle(out, "S3 No Encryption")).isTrue();
        assertThat(hasTitle(out, "RDS Publicly Accessible")).isTrue();
        assertThat(hasTitle(out, "Security Group Open to 0.0.0.0/0")).isTrue();
        assertThat(hasTitle(out, "EBS No Encryption")).isTrue();
        assertThat(hasTitle(out, "IAM Wildcard Action")).isTrue();
        assertThat(hasTitle(out, "S3 No Access Logging")).isTrue();
    }

    @Test
    void iac_kubernetes_fullBad() {
        String c = "apiVersion: v1\nkind: Pod\ncontainers:\n- name: a\n"
                + "privileged: true\nhostNetwork: true\nhostPID: true\n"
                + "kind: Service\ntype: LoadBalancer\n";
        var out = IaCAnalyzer.analyze(c, "deploy.yaml");
        assertThat(hasTitle(out, "K8s Privileged Pod")).isTrue();
        assertThat(hasTitle(out, "K8s Host Network")).isTrue();
        assertThat(hasTitle(out, "K8s Host PID")).isTrue();
        assertThat(hasTitle(out, "K8s Default Root User")).isTrue();
        assertThat(hasTitle(out, "K8s No Resource Limits")).isTrue();
        assertThat(hasTitle(out, "K8s Default Namespace")).isTrue();
        assertThat(hasTitle(out, "K8s SA Token Auto-mount")).isTrue();
        assertThat(hasTitle(out, "K8s LoadBalancer Exposed")).isTrue();
    }

    @Test
    void iac_dockerfile_fullBad() {
        String c = "FROM ubuntu\nCOPY . /app\nADD https://example.com/f.tar.gz /tmp\n"
                + "RUN chmod 777 /app/run.sh\nENV APP_" + "PASSWORD s3cret\nEXPOSE 22\n";
        var out = IaCAnalyzer.analyze(c, "Dockerfile");
        assertThat(hasTitle(out, "No Version Pin")).isTrue();
        assertThat(hasTitle(out, "COPY . (entire context)")).isTrue();
        assertThat(hasTitle(out, "ADD from URL")).isTrue();
        assertThat(hasTitle(out, "chmod 777")).isTrue();
        assertThat(hasTitle(out, "Secret in ENV")).isTrue();
        assertThat(hasTitle(out, "Dangerous Port Exposed")).isTrue();
        assertThat(hasTitle(out, "No USER Instruction")).isTrue();
    }

    @Test
    void iac_cloudformation() {
        String c = "{\"Type\": \"AWS::RDS::DBInstance\", \"Properties\": {"
                + "\"PubliclyAccessible\": true, \"EncryptionConfiguration\": \"UNENCRYPTED\", "
                + "\"SecurityGroupIngress\": {\"CidrIp\": \"0.0.0.0/0\"}}}";
        var out = IaCAnalyzer.analyze(c, "stack.json");
        assertThat(hasTitle(out, "Public Resource")).isTrue();
        assertThat(hasTitle(out, "Unencrypted")).isTrue();
        assertThat(hasTitle(out, "Open Security Group")).isTrue();
    }

    @Test
    void iac_generic() {
        var out = IaCAnalyzer.analyze("db_" + pwAssign("s3cret") + "\nallow 0.0.0.0/0", "app.conf");
        assertThat(hasTitle(out, "Hardcoded Password in Config")).isTrue();
        assertThat(hasTitle(out, "Open Network Rule")).isTrue();
    }

    @Test
    void iac_generic_masked_skipped() {
        var out = IaCAnalyzer.analyze("db_password=***\nref=${DB_PASS}", "app.conf");
        assertThat(hasTitle(out, "Hardcoded Password in Config")).isFalse();
    }

    @Test
    void iac_clean_fallback() {
        var out = IaCAnalyzer.analyze("resource \"aws_s3_bucket\" \"b\" {\n"
                + "server_side_encryption_configuration {}\nlogging {}\n}\n", "main.tf");
        assertThat(out).hasSize(1);
        assertThat(out.get(0).get("title")).isEqualTo("IaC Scan Complete");
    }
}
