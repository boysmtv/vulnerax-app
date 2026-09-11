package com.vulnerax.modules.scan.analyzers;

import java.util.*;

public class IaCAnalyzer {

    public static List<Map<String,Object>> analyze(String content, String fileName) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (content == null || content.isEmpty()) return out;
        String fn = fileName != null ? fileName.toLowerCase() : "";
        String type = detectType(fn, content);

        switch (type) {
            case "terraform" -> analyzeTerraform(content, out);
            case "kubernetes" -> analyzeKubernetes(content, out);
            case "dockerfile" -> analyzeDockerfile(content, out);
            case "cloudformation" -> analyzeCloudFormation(content, out);
            default -> analyzeGeneric(content, out);
        }

        if (out.isEmpty()) {
            out.add(mk("IaC Scan Complete", "CWE-1104", "INFO",
                "No critical misconfiguration found in " + (fileName != null ? fileName : "config"),
                fileName, 0, "Review full config for compliance"));
        }
        return out;
    }

    private static String detectType(String fn, String content) {
        if (fn.endsWith(".tf") || content.contains("resource \"") || content.contains("provider \"")) return "terraform";
        if (fn.endsWith(".yaml") || fn.endsWith(".yml")) {
            if (content.contains("apiVersion:") && content.contains("kind:")) return "kubernetes";
            if (content.contains("AWSTemplateFormatVersion")) return "cloudformation";
        }
        if (fn.equals("dockerfile") || fn.endsWith("/dockerfile") || content.startsWith("FROM ")) return "dockerfile";
        if (content.contains("\"Type\"") && content.contains("\"Properties\"")) return "cloudformation";
        return "generic";
    }

    private static void analyzeTerraform(String c, List<Map<String,Object>> out) {
        // Public S3
        if (c.contains("acl") && (c.contains("\"public-read\"") || c.contains("\"public-read-write\""))) {
            out.add(mk("S3 Public ACL", "CWE-538", "CRITICAL", "S3 bucket has public-read ACL — data exposure", "terraform", 0, "Use private ACL + bucket policy"));
        }
        // Unencrypted S3
        if (c.contains("aws_s3_bucket") && !c.contains("server_side_encryption_configuration")) {
            out.add(mk("S3 No Encryption", "CWE-311", "HIGH", "S3 bucket without server-side encryption", "terraform", 0, "Add AES-256 or KMS encryption"));
        }
        // Public RDS
        if (c.contains("publicly_accessible") && c.contains("true")) {
            out.add(mk("RDS Publicly Accessible", "CWE-668", "CRITICAL", "RDS instance is publicly accessible", "terraform", 0, "Set publicly_accessible = false"));
        }
        // Open security group
        if (c.contains("cidr_blocks") && c.contains("\"0.0.0.0/0\"")) {
            out.add(mk("Security Group Open to 0.0.0.0/0", "CWE-284", "HIGH", "Security group allows traffic from any IP", "terraform", 0, "Restrict to specific CIDR ranges"));
        }
        // Unencrypted EBS
        if (c.contains("aws_ebs_volume") && !c.contains("encrypted")) {
            out.add(mk("EBS No Encryption", "CWE-311", "MEDIUM", "EBS volume without encryption", "terraform", 0, "Add encrypted = true"));
        }
        // IAM admin
        if (c.contains("\"Effect\"") && c.contains("\"Allow\"") && c.contains("\"Action\"") && c.contains("\"*\"")) {
            out.add(mk("IAM Wildcard Action", "CWE-269", "HIGH", "IAM policy allows all actions (*) — overprivileged", "terraform", 0, "Follow principle of least privilege"));
        }
        // Logging disabled
        if (c.contains("aws_s3_bucket") && !c.contains("logging")) {
            out.add(mk("S3 No Access Logging", "CWE-778", "MEDIUM", "S3 bucket without access logging", "terraform", 0, "Enable S3 access logging"));
        }
    }

    private static void analyzeKubernetes(String c, List<Map<String,Object>> out) {
        // Privileged container
        if (c.contains("privileged: true")) {
            out.add(mk("K8s Privileged Pod", "CWE-250", "CRITICAL", "Pod runs in privileged mode", "kubernetes", 0, "Set privileged: false"));
        }
        // Host network
        if (c.contains("hostNetwork: true")) {
            out.add(mk("K8s Host Network", "CWE-668", "HIGH", "Pod uses host network namespace", "kubernetes", 0, "Remove hostNetwork: true"));
        }
        // Host PID
        if (c.contains("hostPID: true")) {
            out.add(mk("K8s Host PID", "CWE-250", "HIGH", "Pod shares host PID namespace", "kubernetes", 0, "Remove hostPID: true"));
        }
        // Running as root
        if (!c.contains("runAsNonRoot: true") && !c.contains("runAsUser:")) {
            out.add(mk("K8s Default Root User", "CWE-250", "MEDIUM", "Pod doesn't set runAsNonRoot — may run as root", "kubernetes", 0, "Add securityContext.runAsNonRoot: true"));
        }
        // No resource limits
        if (c.contains("containers:") && !c.contains("resources:") && !c.contains("limits:")) {
            out.add(mk("K8s No Resource Limits", "CWE-770", "MEDIUM", "Container without resource limits — DoS risk", "kubernetes", 0, "Add resources.limits.cpu/memory"));
        }
        // Default namespace
        if (c.contains("namespace: default") || (!c.contains("namespace:") && c.contains("kind:"))) {
            out.add(mk("K8s Default Namespace", "CWE-668", "LOW", "Resource deployed to default namespace", "kubernetes", 0, "Use dedicated namespace"));
        }
        // ServiceAccount token automount
        if (!c.contains("automountServiceAccountToken: false")) {
            out.add(mk("K8s SA Token Auto-mount", "CWE-522", "MEDIUM", "ServiceAccount token auto-mounted", "kubernetes", 0, "Set automountServiceAccountToken: false"));
        }
        // No network policy reference
        if (c.contains("kind: Service") && c.contains("type: LoadBalancer")) {
            out.add(mk("K8s LoadBalancer Exposed", "CWE-284", "MEDIUM", "Service exposed via LoadBalancer — check NetworkPolicy", "kubernetes", 0, "Add NetworkPolicy to restrict traffic"));
        }
    }

    private static void analyzeDockerfile(String c, List<Map<String,Object>> out) {
        String[] lines = c.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String l = lines[i].trim();
            if (l.startsWith("FROM ") && (l.contains(":latest") || !l.contains(":"))) {
                out.add(mk("Dockerfile: No Version Pin", "CWE-1104", "HIGH", "FROM without version tag — non-reproducible", "Dockerfile:" + (i+1), 0, "Pin to specific version"));
            }
            if (l.startsWith("COPY ") && l.contains(".")) {
                out.add(mk("Dockerfile: COPY . (entire context)", "CWE-1104", "MEDIUM", "COPY . copies everything including secrets", "Dockerfile:" + (i+1), 0, "Use .dockerignore, copy specific files"));
            }
            if (l.startsWith("ADD ") && (l.contains("http://") || l.contains("https://"))) {
                out.add(mk("Dockerfile: ADD from URL", "CWE-1104", "HIGH", "ADD from remote URL — no checksum", "Dockerfile:" + (i+1), 0, "Use COPY with downloaded file + checksum"));
            }
            if (l.startsWith("RUN ") && l.contains("chmod 777")) {
                out.add(mk("Dockerfile: chmod 777", "CWE-732", "HIGH", "chmod 777 — world-writable files", "Dockerfile:" + (i+1), 0, "Use least-privilege permissions"));
            }
            String[] secrets = {"password", "secret", "token", "key", "credential"};
            for (String s : secrets) {
                if (l.toUpperCase().startsWith("ENV ") && l.toLowerCase().contains(s)) {
                    out.add(mk("Dockerfile: Secret in ENV", "CWE-798", "CRITICAL", "Secret in ENV — visible in image history", "Dockerfile:" + (i+1), 0, "Use build secrets"));
                }
            }
            if (l.startsWith("EXPOSE ") && (l.contains("22") || l.contains("2375") || l.contains("2376"))) {
                out.add(mk("Dockerfile: Dangerous Port Exposed", "CWE-284", "HIGH", "Port " + l.split(" ")[1] + " exposed — potentially dangerous", "Dockerfile:" + (i+1), 0, "Remove if not needed"));
            }
        }
        if (!c.contains("USER ") && !c.contains("user ")) {
            out.add(mk("Dockerfile: No USER Instruction", "CWE-250", "MEDIUM", "No USER — container runs as root by default", "Dockerfile", 0, "Add USER nonroot:nonroot"));
        }
    }

    private static void analyzeCloudFormation(String c, List<Map<String,Object>> out) {
        if (c.contains("\"PubliclyAccessible\": true")) {
            out.add(mk("CloudFormation: Public Resource", "CWE-668", "HIGH", "Resource is publicly accessible", "CloudFormation", 0, "Set PubliclyAccessible to false"));
        }
        if (c.contains("\"EncryptionConfiguration\"") && c.contains("UNENCRYPTED")) {
            out.add(mk("CloudFormation: Unencrypted", "CWE-311", "HIGH", "Resource uses unencrypted storage", "CloudFormation", 0, "Enable encryption"));
        }
        if (c.contains("\"SecurityGroupIngress\"") && c.contains("\"CidrIp\": \"0.0.0.0/0\"")) {
            out.add(mk("CloudFormation: Open Security Group", "CWE-284", "HIGH", "Security group open to 0.0.0.0/0", "CloudFormation", 0, "Restrict CIDR"));
        }
    }

    private static void analyzeGeneric(String c, List<Map<String,Object>> out) {
        if (c.contains("password") && (c.contains("=") || c.contains(":")) && !c.contains("***") && !c.contains("${")) {
            out.add(mk("Hardcoded Password in Config", "CWE-798", "HIGH", "Password found in configuration file", "config", 0, "Use environment variables / secrets"));
        }
        if (c.contains("0.0.0.0/0") || c.contains("::/0")) {
            out.add(mk("Open Network Rule", "CWE-284", "MEDIUM", "Network rule allows all traffic", "config", 0, "Restrict to specific sources"));
        }
    }

    private static Map<String,Object> mk(String title, String cwe, String severity, String desc, String file, int line, String rec) {
        Map<String,Object> m = new HashMap<>();
        m.put("title", title); m.put("rule", title); m.put("cwe", cwe);
        m.put("severity", severity); m.put("file", file); m.put("line", line);
        m.put("snippet", desc); m.put("recommendation", rec); m.put("match", title);
        return m;
    }
}
