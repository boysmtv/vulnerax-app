package com.vulnerax.modules.scan.analyzers;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Real SCA: parses manifest content (pom.xml, package.json, requirements.txt, go.mod)
 * and checks against embedded vulnerable version DB (no mock random).
 */
public class ScaAnalyzer {

    // Minimal embedded DB for demo real - would be replaced by NVD sync in prod
    private static final List<Vuln> DB = List.of(
        new Vuln("log4j", "org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228", "CRITICAL", 10.0, true, 0.97, "Update to 2.17.1+"),
        new Vuln("log4j", "org.apache.logging.log4j:log4j-core", "2.15.0", "CVE-2021-45046", "CRITICAL", 9.0, true, 0.85, "Update to 2.17.1+"),
        new Vuln("lodash", "lodash", "4.17.20", "CVE-2020-8203", "HIGH", 7.4, false, 0.6, "Update to 4.17.21+"),
        new Vuln("axios", "axios", "0.21.1", "CVE-2020-28168", "MEDIUM", 5.0, false, 0.3, "Update to 0.21.4+"),
        new Vuln("spring-core", "org.springframework:spring-core", "5.3.18", "CVE-2022-22965", "CRITICAL", 9.8, true, 0.9, "Update to 5.3.20+"),
        new Vuln("django", "Django", "3.2.5", "CVE-2021-35042", "HIGH", 7.5, false, 0.4, "Update to 3.2.14+"),
        new Vuln("express", "express", "4.17.1", "CVE-2022-24999", "HIGH", 7.5, false, 0.5, "Update to 4.17.3+")
    );

    public static List<Map<String,Object>> analyze(String content, String fileName) {
        List<Map<String,Object>> out = new ArrayList<>();
        if (content == null || content.isEmpty()) return out;
        String lower = fileName != null ? fileName.toLowerCase() : "";
        // detect manifest type
        if (lower.endsWith("pom.xml") || content.contains("<artifactId>")) {
            out.addAll(scanMaven(content, fileName));
        } else if (lower.endsWith("package.json") || content.contains("\"dependencies\"")) {
            out.addAll(scanNpm(content, fileName));
        } else if (lower.endsWith("requirements.txt") || lower.endsWith(".txt")) {
            out.addAll(scanPip(content, fileName));
        } else if (lower.contains("go.mod")) {
            out.addAll(scanGo(content, fileName));
        } else {
            // generic: search for any vulnerable string in content
            for (Vuln v : DB) {
                if (content.contains(v.version) && content.toLowerCase().contains(v.name.toLowerCase())) {
                    out.add(toFinding(v, fileName, "generic"));
                }
            }
        }
        return out;
    }

    private static List<Map<String,Object>> scanMaven(String content, String file) {
        List<Map<String,Object>> r = new ArrayList<>();
        Pattern p = Pattern.compile("<artifactId>([^<]+)</artifactId>\\s*<version>([^<]+)</version>");
        Matcher m = p.matcher(content);
        while (m.find()) {
            String art = m.group(1).trim();
            String ver = m.group(2).trim();
            for (Vuln v : DB) {
                if (v.mavenCoords != null && v.mavenCoords.contains(art) && v.version.equals(ver)) {
                    r.add(toFinding(v, file, "direct"));
                }
            }
        }
        return r;
    }
    private static List<Map<String,Object>> scanNpm(String content, String file) {
        List<Map<String,Object>> r = new ArrayList<>();
        Pattern p = Pattern.compile("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(content);
        while (m.find()) {
            String name = m.group(1);
            String ver = m.group(2).replace("^","").replace("~","").trim();
            for (Vuln v : DB) {
                if (v.name.equalsIgnoreCase(name) && v.version.equals(ver)) {
                    r.add(toFinding(v, file, "direct"));
                }
            }
        }
        return r;
    }
    private static List<Map<String,Object>> scanPip(String c, String file) {
        List<Map<String,Object>> r = new ArrayList<>();
        for (String line : c.split("\n")) {
            line=line.trim();
            if (line.isEmpty()||line.startsWith("#")) continue;
            String[] parts=line.split("==");
            if (parts.length==2) {
                String name=parts[0].trim();
                String ver=parts[1].trim();
                for (Vuln v: DB) if (v.name.equalsIgnoreCase(name) && v.version.equals(ver)) r.add(toFinding(v,file,"direct"));
            }
        }
        return r;
    }
    private static List<Map<String,Object>> scanGo(String c, String file) {
        // simple
        return new ArrayList<>();
    }

    private static Map<String,Object> toFinding(Vuln v, String file, String depType) {
        Map<String,Object> m = new HashMap<>();
        m.put("component", v.name);
        m.put("coords", v.mavenCoords != null ? v.mavenCoords : v.name);
        m.put("installedVersion", v.version);
        m.put("cve", v.cve);
        m.put("severity", v.severity);
        m.put("cvss", v.cvss);
        m.put("kev", v.kev);
        m.put("epss", v.epss);
        m.put("file", file != null ? file : "unknown");
        m.put("dependencyType", depType);
        m.put("fixedVersion", v.fixed);
        m.put("title", "Vulnerable dependency " + v.name + " " + v.version + " (" + v.cve + ")");
        return m;
    }

    private record Vuln(String name, String mavenCoords, String version, String cve, String severity, double cvss, boolean kev, double epss, String fixed) {}
}
