package com.vulnerax.modules.scan.analyzers;

import java.util.*;

public class ContainerAnalyzer {

    private static final List<String> VULN_IMAGES = List.of(
        "alpine:3.14", "nginx:1.18", "nginx:1.19", "node:14", "node:16",
        "python:3.8", "openjdk:11", "redis:6", "mysql:5.7", "postgres:13"
    );

    private static final List<String> SECRETS_PATTERNS = List.of(
        "password", "secret", "token", "api_key", "apikey", "AWS_ACCESS_KEY",
        "AWS_SECRET", "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "REDIS_PASSWORD"
    );

    public static List<Map<String,Object>> analyze(String target, String configJson) {
        List<Map<String,Object>> out = new ArrayList<>();
        String image = target != null ? target.trim() : "";
        if (image.isEmpty()) return out;

        // 1. Check known vulnerable base images
        for (String vuln : VULN_IMAGES) {
            if (image.startsWith(vuln)) {
                out.add(mk("Vulnerable Base Image", "CWE-1104", "HIGH",
                    "Image " + image + " uses outdated base " + vuln + " — known CVEs",
                    image, 0, "Update to latest version, use distroless/multi-stage"));
            }
        }

        // 2. Check running as root (if config has User: root or no USER instruction)
        String config = configJson != null ? configJson : "";
        if (config.toLowerCase().contains("user: root") || config.toLowerCase().contains("user 0")) {
            out.add(mk("Running as Root", "CWE-250", "HIGH",
                "Container runs as root — privilege escalation risk",
                image, 0, "Use USER instruction with non-root user"));
        }

        // 3. Check for privileged mode
        if (config.contains("\"privileged\":true") || config.contains("privileged: true")) {
            out.add(mk("Privileged Container", "CWE-250", "CRITICAL",
                "Container runs in privileged mode — full host access",
                image, 0, "Remove --privileged flag, use minimal capabilities"));
        }

        // 4. Check for secrets in environment
        for (String secret : SECRETS_PATTERNS) {
            if (config.toUpperCase().contains(secret.toUpperCase())) {
                out.add(mk("Secret in Container Config: " + secret, "CWE-798", "CRITICAL",
                    "Secret " + secret + " found in container config/environment — image layer leak",
                    image, 0, "Use Docker secrets, Vault, or runtime injection"));
            }
        }

        // 5. Check for host network
        if (config.contains("network_mode: host") || config.contains("NetworkMode: host")) {
            out.add(mk("Host Network Mode", "CWE-668", "HIGH",
                "Container uses host network — no network isolation",
                image, 0, "Use bridge network with explicit port mapping"));
        }

        // 6. Check for host PID
        if (config.contains("pid: host") || config.contains("PidMode: host")) {
            out.add(mk("Host PID Namespace", "CWE-250", "HIGH",
                "Container shares host PID namespace — process injection risk",
                image, 0, "Remove pid: host"));
        }

        // 7. Check for capability additions
        if (config.contains("cap_add") || config.contains("CAP_ADD") || config.contains("SYS_ADMIN") || config.contains("NET_ADMIN")) {
            out.add(mk("Dangerous Capabilities", "CWE-250", "HIGH",
                "Container has elevated capabilities (SYS_ADMIN/NET_ADMIN)",
                image, 0, "Drop all capabilities, add only needed ones"));
        }

        // 8. Check for writable root filesystem
        if (!config.contains("read_only: true") && !config.contains("ReadOnly: true")) {
            out.add(mk("Writable Root Filesystem", "CWE-732", "MEDIUM",
                "Container root filesystem is writable — attacker can modify binaries",
                image, 0, "Set read_only: true, use tmpfs for writable dirs"));
        }

        // 9. Check for latest tag
        if (image.endsWith(":latest") || !image.contains(":")) {
            out.add(mk("Using 'latest' Tag", "CWE-1104", "MEDIUM",
                "Image " + image + " uses 'latest' or no tag — non-reproducible builds",
                image, 0, "Pin to specific version digest"));
        }

        // 10. Dockerfile best practices (if config contains Dockerfile content)
        if (config.contains("FROM ") && config.contains("RUN ")) {
            if (config.contains("RUN apt-get update") && !config.contains("apt-get clean")) {
                out.add(mk("Dockerfile: apt cache not cleaned", "CWE-1104", "LOW",
                    "apt-get update without cleanup — large image layer",
                    image, 0, "Combine RUN: apt-get update && install && clean"));
            }
            if (config.contains("ADD ") && config.contains("http")) {
                out.add(mk("Dockerfile: ADD from URL", "CWE-1104", "MEDIUM",
                    "ADD from remote URL — no integrity check, supply chain risk",
                    image, 0, "Use COPY + multi-stage build"));
            }
            String[] secrets = {"password", "secret", "token", "key", "credential"};
            for (String s : secrets) {
                if (config.toLowerCase().contains("env " + s) || config.toLowerCase().contains("arg " + s)) {
                    out.add(mk("Dockerfile: Secret in ENV/ARG", "CWE-798", "CRITICAL",
                        "Secret " + s + " in ENV/ARG — visible in image history",
                        image, 0, "Use build secrets (DOCKER_BUILDKIT=1 --mount=type=secret)"));
                }
            }
        }

        if (out.isEmpty()) {
            out.add(mk("Container Scan — No Critical Issue", "CWE-1104", "INFO",
                "No obvious container misconfiguration found for " + image,
                image, 0, "Review full Dockerfile + runtime config"));
        }
        return out;
    }

    private static Map<String,Object> mk(String title, String cwe, String severity, String desc, String file, int line, String rec) {
        Map<String,Object> m = new HashMap<>();
        m.put("title", title); m.put("rule", title); m.put("cwe", cwe);
        m.put("severity", severity); m.put("file", file); m.put("line", line);
        m.put("snippet", desc); m.put("recommendation", rec); m.put("match", title);
        return m;
    }
}
